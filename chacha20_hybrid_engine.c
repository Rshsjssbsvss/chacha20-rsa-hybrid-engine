/*
 * ChaCha20 Hybrid 32-byte Engine v7 (light adaptive update)
 *
 * - ChaCha20-Poly1305 AEAD (256-bit / 32-byte session key)
 * - RSA-4096 + OAEP (SHA-256) key wrap
 * - Master private-key password: Ffff@@@@1234@@Hash00
 * - Adaptive chunks (light modify):
 *     - File size < 1 GiB (MB range)  -> 1 KiB chunks, progress every 10 KiB
 *     - File size >= 1 GiB (GB range) -> 1 MiB chunks, progress every 10 MiB
 * - list/ batch encrypt & multi-threaded decrypt
 * - After encrypt: wipe plaintext, delete shadows, purge Trash
 * - Only .enc + .key remain until decrypt
 * - Strong error handling throughout
 *
 * Build: make  (system libssl-dev; no runtime downloads)
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define MAGIC           "SENG"
#define VERSION         7
#define ALG_CHACHA      1
#define WRAP_RSA        1
#define KEY_LEN         32
#define NONCE_LEN       12
#define TAG_LEN         16
#define ID_LEN          16
#define HDR_LEN         32
#define BUF_SIZE_LARGE  (1u * 1024u * 1024u)          /* 1 MiB  – used for GB-range files */
#define BUF_SIZE_SMALL  (1u * 1024u)                   /* 1 KiB  – used for MB-range files */
#define PROGRESS_LARGE  (10ULL * 1024ULL * 1024ULL)    /* progress every 10 MiB */
#define PROGRESS_SMALL  (10ULL * 1024ULL)              /* progress every 10 KiB */
#define SMALL_FILE_MAX  (1024ULL * 1024ULL * 1024ULL)  /* 1 GiB threshold: <1GiB = MB mode, >=1GiB = GB mode */
#define MAX_FILE        (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define MAX_THREADS     4
#define LIST_DIR        "list"
#define MAX_PATHS       50000
#define PASS_MAX        512
#define WIPE_CHUNK      (1024 * 1024)
#define RSA_BITS        4096
#define FIXED_PRIV_PASS "Ffff@@@@1234@@Hash00"

static void die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void ok(int cond, const char *msg)
{
    if (!cond) die(msg);
}

static int soft_fail(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    return 0;
}

static void secure_zero(void *p, size_t n)
{
    if (p && n) OPENSSL_cleanse(p, n);
}

static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8)  & 0xff;
    p[3] = v & 0xff;
}

static int write_all(FILE *f, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    while (n > 0) {
        size_t w = fwrite(p, 1, n, f);
        if (w == 0) return 0;
        p += w;
        n -= w;
    }
    return 1;
}

static int read_all(FILE *f, void *buf, size_t n)
{
    unsigned char *p = buf;
    while (n > 0) {
        size_t r = fread(p, 1, n, f);
        if (r == 0) return 0;
        p += r;
        n -= r;
    }
    return 1;
}

static void validate_path(const char *path)
{
    if (!path || !*path) die("empty path");
    if (strstr(path, "..")) die("path traversal not allowed");
    if (strlen(path) >= PATH_MAX) die("path too long");
}

static void require_new_path(const char *path)
{
    validate_path(path);
    struct stat st;
    if (stat(path, &st) == 0)
        die("output path already exists (refusing to overwrite)");
}

static void compute_key_id(EVP_PKEY *pkey, unsigned char id[ID_LEN])
{
    unsigned char *der = NULL;
    int len = i2d_PublicKey(pkey, &der);
    ok(len > 0 && der != NULL, "public key DER export failed");
    unsigned char hash[32];
    ok(EVP_Digest(der, (size_t)len, hash, NULL, EVP_sha256(), NULL) == 1, "SHA-256 failed");
    memcpy(id, hash, ID_LEN);
    OPENSSL_free(der);
}

static EVP_PKEY *load_public_key(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { soft_fail("cannot open public/main key file"); return NULL; }
    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) soft_fail("invalid public/main key (RSA PEM expected)");
    return k;
}

static EVP_PKEY *load_private_key(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { soft_fail("cannot open private key file"); return NULL; }
    char pass[PASS_MAX];
    strncpy(pass, FIXED_PRIV_PASS, sizeof pass - 1);
    pass[sizeof pass - 1] = '\0';
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, pass);
    fclose(f);
    secure_zero(pass, sizeof pass);
    if (!k) {
        fprintf(stderr, "WARNING: private key load failed — wrong file or password\n");
        soft_fail("invalid private key or password (expected Ffff@@@@1234@@Hash00)");
        return NULL;
    }
    if (EVP_PKEY_base_id(k) != EVP_PKEY_RSA) {
        EVP_PKEY_free(k);
        soft_fail("key is not RSA");
        return NULL;
    }
    int bits = EVP_PKEY_bits(k);
    if (bits < 4096)
        fprintf(stderr, "WARNING: RSA key is %d-bit (engine expects 4096-bit)\n", bits);
    else
        fprintf(stderr, "OK: RSA-%d private key verified.\n", bits);
    return k;
}

static int write_key_file(const char *path, EVP_PKEY *pub,
                          const unsigned char *key, const unsigned char *id)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return soft_fail("RSA-OAEP wrap init failed");
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, key, KEY_LEN) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return soft_fail("RSA wrap size query failed");
    }
    unsigned char *wrapped = OPENSSL_malloc(outlen);
    if (!wrapped) { EVP_PKEY_CTX_free(ctx); return soft_fail("OOM wrapping key"); }
    if (EVP_PKEY_encrypt(ctx, wrapped, &outlen, key, KEY_LEN) != 1) {
        OPENSSL_free(wrapped);
        EVP_PKEY_CTX_free(ctx);
        return soft_fail("RSA-OAEP encrypt (wrap) failed");
    }
    EVP_PKEY_CTX_free(ctx);

    FILE *f = fopen(path, "wb");
    if (!f) { OPENSSL_free(wrapped); return soft_fail("cannot create session key file"); }
    int okw = write_all(f, id, ID_LEN);
    unsigned char lenbuf[4];
    put32(lenbuf, (uint32_t)outlen);
    okw = okw && write_all(f, lenbuf, 4) && write_all(f, wrapped, outlen);
    if (fclose(f) != 0) okw = 0;
    OPENSSL_free(wrapped);
    if (!okw) { unlink(path); return soft_fail("session key file write failed"); }
    return 1;
}

static int read_key_file(const char *path, EVP_PKEY *priv,
                         const unsigned char *expected_id, unsigned char *key_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return soft_fail("cannot open session key file");
    unsigned char id[ID_LEN];
    if (!read_all(f, id, ID_LEN)) { fclose(f); return soft_fail("key-id read failed"); }
    if (CRYPTO_memcmp(id, expected_id, ID_LEN) != 0) {
        fclose(f);
        fprintf(stderr, "WARNING: key-id mismatch — wrong keypair\n");
        return soft_fail("key-id mismatch");
    }
    unsigned char lenbuf[4];
    if (!read_all(f, lenbuf, 4)) { fclose(f); return soft_fail("wrapped-len read failed"); }
    uint32_t wlen = get32(lenbuf);
    if (wlen == 0 || wlen > 2048) { fclose(f); return soft_fail("invalid wrapped key length"); }
    unsigned char *wrapped = OPENSSL_malloc(wlen);
    if (!wrapped) { fclose(f); return soft_fail("OOM"); }
    if (!read_all(f, wrapped, wlen)) { OPENSSL_free(wrapped); fclose(f); return soft_fail("wrapped-key read failed"); }
    fclose(f);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(wrapped);
        return soft_fail("RSA-OAEP unwrap init failed");
    }
    unsigned char tmp[64];
    size_t tmplen = sizeof tmp;
    int rc = EVP_PKEY_decrypt(ctx, tmp, &tmplen, wrapped, wlen);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(wrapped);
    if (rc != 1 || tmplen != KEY_LEN) {
        secure_zero(tmp, sizeof tmp);
        return soft_fail("RSA unwrap failed (wrong private key?)");
    }
    memcpy(key_out, tmp, KEY_LEN);
    secure_zero(tmp, sizeof tmp);
    return 1;
}

static FILE *open_temp(const char *final_path, char *tmp, size_t tmpsz)
{
    snprintf(tmp, tmpsz, "%s.tmp.%d", final_path, (int)getpid());
    FILE *f = fopen(tmp, "wb");
    ok(f != NULL, "cannot create temporary file");
    return f;
}

static int commit_temp(FILE *f, const char *tmp, const char *final_path)
{
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f); unlink(tmp); return soft_fail("fsync failed");
    }
    if (fclose(f) != 0) { unlink(tmp); return soft_fail("temp close failed"); }
    if (rename(tmp, final_path) != 0) { unlink(tmp); return soft_fail("atomic rename failed"); }
    return 1;
}

static void init_keys(const char *priv_path, const char *pub_path)
{
    require_new_path(priv_path);
    require_new_path(pub_path);
    char pass[PASS_MAX];
    strncpy(pass, FIXED_PRIV_PASS, sizeof pass - 1);
    pass[sizeof pass - 1] = '\0';
    fprintf(stderr, "Generating RSA-%d keypair...\n", RSA_BITS);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    ok(ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1 &&
       EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) == 1, "RSA keygen init failed");
    EVP_PKEY *pkey = NULL;
    ok(EVP_PKEY_keygen(ctx, &pkey) == 1, "RSA-4096 keygen failed");
    EVP_PKEY_CTX_free(ctx);

    FILE *fp = fopen(priv_path, "w");
    ok(fp != NULL, "cannot write private key");
    ok(PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(),
                            (unsigned char *)pass, (int)strlen(pass), NULL, NULL) == 1,
       "private key write failed");
    fclose(fp);
    secure_zero(pass, sizeof pass);

    FILE *fpub = fopen(pub_path, "w");
    ok(fpub != NULL, "cannot write public key");
    ok(PEM_write_PUBKEY(fpub, pkey) == 1, "public key write failed");
    fclose(fpub);
    EVP_PKEY_free(pkey);
    fprintf(stderr, "OK: RSA-%d keypair created.\n", RSA_BITS);
    fprintf(stderr, "  private: %s\n  public:  %s\n", priv_path, pub_path);
}

static int secure_wipe_fd(int fd, off_t size)
{
    if (fd < 0 || size <= 0) return 1;
    unsigned char *buf = OPENSSL_malloc(WIPE_CHUNK);
    if (!buf) return 0;
    memset(buf, 0, WIPE_CHUNK);
    if (lseek(fd, 0, SEEK_SET) != 0) { OPENSSL_free(buf); return 0; }
    off_t left = size;
    while (left > 0) {
        size_t n = left > (off_t)WIPE_CHUNK ? WIPE_CHUNK : (size_t)left;
        if (write(fd, buf, n) != (ssize_t)n) { OPENSSL_free(buf); return 0; }
        left -= (off_t)n;
    }
    fsync(fd);
    if (lseek(fd, 0, SEEK_SET) != 0) { OPENSSL_free(buf); return 0; }
    left = size;
    while (left > 0) {
        size_t n = left > (off_t)WIPE_CHUNK ? WIPE_CHUNK : (size_t)left;
        if (RAND_bytes(buf, (int)n) != 1) break;
        if (write(fd, buf, n) != (ssize_t)n) break;
        left -= (off_t)n;
    }
    fsync(fd);
    memset(buf, 0, WIPE_CHUNK);
    if (lseek(fd, 0, SEEK_SET) == 0) {
        left = size;
        while (left > 0) {
            size_t n = left > (off_t)WIPE_CHUNK ? WIPE_CHUNK : (size_t)left;
            if (write(fd, buf, n) != (ssize_t)n) break;
            left -= (off_t)n;
        }
        fsync(fd);
    }
    OPENSSL_free(buf);
    return 1;
}

static void purge_from_trash(const char *orig_path)
{
    const char *base = strrchr(orig_path, '/');
    base = base ? base + 1 : orig_path;
    if (!base || !*base) return;
    const char *home = getenv("HOME");
    if (!home) return;
    char trash_files[PATH_MAX], trash_info[PATH_MAX];
    if (snprintf(trash_files, sizeof trash_files, "%s/.local/share/Trash/files", home) >= (int)sizeof trash_files) return;
    if (snprintf(trash_info, sizeof trash_info, "%s/.local/share/Trash/info", home) >= (int)sizeof trash_info) return;
    DIR *d = opendir(trash_files);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        size_t bl = strlen(base);
        if (strcmp(ent->d_name, base) == 0 ||
            (strncmp(ent->d_name, base, bl) == 0 && ent->d_name[bl] == '.')) {
            char full[PATH_MAX];
            if (snprintf(full, sizeof full, "%s/%s", trash_files, ent->d_name) < (int)sizeof full) {
                if (unlink(full) == 0) fprintf(stderr, "  TRASH PURGED: %s\n", full);
            }
            char info[PATH_MAX];
            if (snprintf(info, sizeof info, "%s/%s.trashinfo", trash_info, ent->d_name) < (int)sizeof info)
                unlink(info);
        }
    }
    closedir(d);
}

static int wipe_all_plaintext(const char *path)
{
    validate_path(path);
    char void_path[PATH_MAX];
    snprintf(void_path, sizeof void_path, "%s.void", path);
    int fd = open(path, O_RDWR);
    if (fd >= 0) {
        if (flock(fd, LOCK_EX) == 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && st.st_size > 0) secure_wipe_fd(fd, st.st_size);
            flock(fd, LOCK_UN);
        }
        close(fd);
        if (unlink(path) == 0) fprintf(stderr, "  PLAINTEXT DELETED: %s\n", path);
        else fprintf(stderr, "WARN: unlink failed: %s (%s)\n", path, strerror(errno));
    }
    if (unlink(void_path) == 0) fprintf(stderr, "  SHADOW DELETED: %s\n", void_path);
    purge_from_trash(path);
    purge_from_trash(void_path);
    return 1;
}

static int encrypt_one(const char *pub_path, const char *in_path,
                       const char *out_path, const char *key_path)
{
    validate_path(in_path);
    struct stat st;
    if (stat(in_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "SKIP (not a regular file): %s\n", in_path);
        return 0;
    }
    if ((uint64_t)st.st_size > MAX_FILE) {
        fprintf(stderr, "SKIP (too large >64GiB): %s\n", in_path);
        return 0;
    }
    {
        struct stat o;
        if (stat(out_path, &o) == 0) {
            fprintf(stderr, "SKIP (already encrypted): %s\n", out_path);
            return 0;
        }
    }

    EVP_PKEY *pub = load_public_key(pub_path);
    if (!pub) return 0;
    unsigned char id[ID_LEN];
    compute_key_id(pub, id);

    unsigned char key[KEY_LEN], nonce[NONCE_LEN];
    if (RAND_bytes(key, KEY_LEN) != 1 || RAND_bytes(nonce, NONCE_LEN) != 1) {
        EVP_PKEY_free(pub);
        return soft_fail("RNG failed for session key/nonce");
    }
    fprintf(stderr, "  256-bit session key generated + RSA-OAEP wrap for: %s\n", in_path);

    FILE *in = fopen(in_path, "rb");
    if (!in) {
        secure_zero(key, sizeof key);
        EVP_PKEY_free(pub);
        return soft_fail("cannot open input");
    }
    char tmp[PATH_MAX];
    FILE *out = open_temp(out_path, tmp, sizeof tmp);

    unsigned char h[HDR_LEN] = {0};
    memcpy(h, MAGIC, 4);
    h[4] = VERSION; h[5] = ALG_CHACHA; h[6] = WRAP_RSA; h[7] = NONCE_LEN;
    memcpy(h + 16, id, ID_LEN);
    if (!write_all(out, h, HDR_LEN) || !write_all(out, nonce, NONCE_LEN)) {
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return soft_fail("header/nonce write failed");
    }

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, key, nonce) != 1) {
        if (cctx) EVP_CIPHER_CTX_free(cctx);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return soft_fail("ChaCha20-Poly1305 init failed");
    }

    size_t chunk = ((uint64_t)st.st_size < SMALL_FILE_MAX) ? BUF_SIZE_SMALL : BUF_SIZE_LARGE;
    uint64_t prog_every = ((uint64_t)st.st_size < SMALL_FILE_MAX) ? PROGRESS_SMALL : PROGRESS_LARGE;
    unsigned char *ibuf = OPENSSL_malloc(chunk);
    unsigned char *obuf = OPENSSL_malloc(chunk + 32);
    if (!ibuf || !obuf) {
        OPENSSL_free(ibuf); OPENSSL_free(obuf); EVP_CIPHER_CTX_free(cctx);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return soft_fail("OOM buffers");
    }

    int out_len, failed = 0;
    uint64_t total = 0;
    for (;;) {
        size_t n = fread(ibuf, 1, chunk, in);
        if (n == 0) break;
        if (EVP_EncryptUpdate(cctx, obuf, &out_len, ibuf, (int)n) != 1 ||
            !write_all(out, obuf, (size_t)out_len)) { failed = 1; break; }
        total += n;
        if (prog_every && (total % prog_every) < chunk) {
            if (chunk <= BUF_SIZE_SMALL)
                fprintf(stderr, "  ... %llu KB\n", (unsigned long long)(total / 1024));
            else
                fprintf(stderr, "  ... %llu MB\n", (unsigned long long)(total / (1024 * 1024)));
        }
    }
    if (failed || ferror(in) ||
        EVP_EncryptFinal_ex(cctx, obuf, &out_len) != 1 ||
        !write_all(out, obuf, (size_t)out_len)) {
        EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return soft_fail("encrypt stream failed");
    }
    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1 ||
        !write_all(out, tag, TAG_LEN)) {
        EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return soft_fail("tag write failed");
    }
    EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf); fclose(in);

    if (!write_key_file(key_path, pub, key, id)) {
        fclose(out); unlink(tmp);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return 0;
    }
    if (!commit_temp(out, tmp, out_path)) {
        unlink(key_path);
        secure_zero(key, sizeof key); EVP_PKEY_free(pub);
        return 0;
    }
    secure_zero(key, sizeof key);
    EVP_PKEY_free(pub);
    wipe_all_plaintext(in_path);
    fprintf(stderr, "OK encrypt: %s -> %s (+ .key)\n", in_path, out_path);
    return 1;
}

static int decrypt_one(EVP_PKEY *priv, const unsigned char *id,
                       const char *key_path, const char *in_path, const char *out_path)
{
    validate_path(in_path);
    struct stat st;
    if (stat(out_path, &st) == 0) {
        fprintf(stderr, "SKIP (output exists): %s\n", out_path);
        return 0;
    }
    FILE *in = fopen(in_path, "rb");
    if (!in) return soft_fail("cannot open encrypted file");

    unsigned char h[HDR_LEN], nonce[NONCE_LEN];
    if (!read_all(in, h, HDR_LEN) || !read_all(in, nonce, NONCE_LEN)) {
        fclose(in); return soft_fail("truncated encrypted file");
    }
    if (memcmp(h, MAGIC, 4) != 0 || h[4] != VERSION || h[5] != ALG_CHACHA ||
        h[6] != WRAP_RSA || h[7] != NONCE_LEN || CRYPTO_memcmp(h + 16, id, ID_LEN) != 0) {
        fclose(in);
        fprintf(stderr, "WARNING: invalid header or wrong keypair for %s\n", in_path);
        return soft_fail("header/keypair check failed");
    }
    if (fstat(fileno(in), &st) != 0 || st.st_size < (off_t)(HDR_LEN + NONCE_LEN + TAG_LEN)) {
        fclose(in); return soft_fail("invalid encrypted-file size");
    }
    uint64_t left = (uint64_t)st.st_size - HDR_LEN - NONCE_LEN - TAG_LEN;
    if (left > MAX_FILE) { fclose(in); return soft_fail("encrypted payload too large"); }

    unsigned char key[KEY_LEN];
    if (!read_key_file(key_path, priv, id, key)) { fclose(in); return 0; }

    char tmp[PATH_MAX];
    FILE *out = open_temp(out_path, tmp, sizeof tmp);
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(cctx, NULL, NULL, key, nonce) != 1) {
        if (cctx) EVP_CIPHER_CTX_free(cctx);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key);
        return soft_fail("decrypt cipher init failed");
    }

    size_t chunk = (left < SMALL_FILE_MAX) ? BUF_SIZE_SMALL : BUF_SIZE_LARGE;
    uint64_t prog_every = (left < SMALL_FILE_MAX) ? PROGRESS_SMALL : PROGRESS_LARGE;
    unsigned char *ibuf = OPENSSL_malloc(chunk);
    unsigned char *obuf = OPENSSL_malloc(chunk + 32);
    if (!ibuf || !obuf) {
        OPENSSL_free(ibuf); OPENSSL_free(obuf); EVP_CIPHER_CTX_free(cctx);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key);
        return soft_fail("OOM");
    }

    int out_len, failed = 0;
    uint64_t done = 0;
    while (left > 0) {
        size_t n = left > chunk ? chunk : (size_t)left;
        if (!read_all(in, ibuf, n) ||
            EVP_DecryptUpdate(cctx, obuf, &out_len, ibuf, (int)n) != 1 ||
            !write_all(out, obuf, (size_t)out_len)) { failed = 1; break; }
        left -= n; done += n;
        if (prog_every && (done % prog_every) < chunk) {
            if (chunk <= BUF_SIZE_SMALL)
                fprintf(stderr, "  ... %llu KB\n", (unsigned long long)(done / 1024));
            else
                fprintf(stderr, "  ... %llu MB\n", (unsigned long long)(done / (1024 * 1024)));
        }
    }

    unsigned char tag[TAG_LEN];
    if (failed || !read_all(in, tag, TAG_LEN) ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) != 1 ||
        EVP_DecryptFinal_ex(cctx, obuf, &out_len) != 1) {
        EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key);
        fprintf(stderr, "WARNING: authentication failed for %s\n", in_path);
        return soft_fail("decrypt authentication failed");
    }
    if (!write_all(out, obuf, (size_t)out_len)) {
        EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf);
        fclose(in); fclose(out); unlink(tmp);
        secure_zero(key, sizeof key);
        return soft_fail("final plaintext write failed");
    }
    EVP_CIPHER_CTX_free(cctx); OPENSSL_free(ibuf); OPENSSL_free(obuf); fclose(in);
    secure_zero(key, sizeof key);
    if (!commit_temp(out, tmp, out_path)) return 0;
    fprintf(stderr, "OK decrypt: %s -> %s\n", in_path, out_path);
    return 1;
}

static int load_paths_from_list(char ***paths_out, int *count_out)
{
    DIR *d = opendir(LIST_DIR);
    if (!d) {
        fprintf(stderr, "ERROR: cannot open '%s/'\n", LIST_DIR);
        return 0;
    }
    char **paths = calloc(MAX_PATHS, sizeof(char *));
    if (!paths) { closedir(d); return soft_fail("OOM path list"); }
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < MAX_PATHS) {
        if (ent->d_name[0] == '.') continue;
        char fpath[PATH_MAX];
        if (snprintf(fpath, sizeof fpath, "%s/%s", LIST_DIR, ent->d_name) >= (int)sizeof fpath) continue;
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        FILE *f = fopen(fpath, "r");
        if (!f) continue;
        char line[PATH_MAX];
        while (fgets(line, sizeof line, f) && count < MAX_PATHS) {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                               line[len-1] == ' ' || line[len-1] == '\t'))
                line[--len] = '\0';
            if (len == 0 || line[0] == '#') continue;
            paths[count] = strdup(line);
            if (!paths[count]) { fclose(f); closedir(d); return soft_fail("OOM strdup"); }
            count++;
        }
        fclose(f);
    }
    closedir(d);
    *paths_out = paths;
    *count_out = count;
    return 1;
}

static void free_paths(char **paths, int count)
{
    if (!paths) return;
    for (int i = 0; i < count; i++) free(paths[i]);
    free(paths);
}

typedef struct {
    const char *pub_path;
    char **paths;
    int start, end, success, fail;
    pthread_mutex_t *lock;
} job_t;

static void *worker_encrypt(void *arg)
{
    job_t *j = arg;
    for (int i = j->start; i < j->end; i++) {
        const char *in = j->paths[i];
        char out[PATH_MAX], key[PATH_MAX];
        snprintf(out, sizeof out, "%s.enc", in);
        snprintf(key, sizeof key, "%s.key", in);
        int ok_flag = encrypt_one(j->pub_path, in, out, key);
        pthread_mutex_lock(j->lock);
        if (ok_flag) j->success++; else j->fail++;
        pthread_mutex_unlock(j->lock);
    }
    return NULL;
}

static void batch_encrypt(const char *pub_path)
{
    fprintf(stderr, "[1/2] Verifying main/public key: %s\n", pub_path);
    EVP_PKEY *pub = load_public_key(pub_path);
    if (!pub) {
        fprintf(stderr, "WARNING: main key invalid — abort\n");
        return;
    }
    fprintf(stderr, "OK: main key RSA-%d loaded.\n", EVP_PKEY_bits(pub));
    EVP_PKEY_free(pub);

    char **paths = NULL;
    int count = 0;
    if (!load_paths_from_list(&paths, &count)) return;
    if (count == 0) {
        fprintf(stderr, "No paths in list/\n");
        free_paths(paths, count);
        return;
    }
    fprintf(stderr, "[2/2] Encrypting %d path(s), max %d threads...\n", count, MAX_THREADS);

    int nthreads = count < MAX_THREADS ? count : MAX_THREADS;
    if (nthreads < 1) nthreads = 1;
    pthread_t threads[MAX_THREADS];
    job_t jobs[MAX_THREADS];
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    int chunk = (count + nthreads - 1) / nthreads;
    for (int t = 0; t < nthreads; t++) {
        jobs[t].pub_path = pub_path;
        jobs[t].paths = paths;
        jobs[t].start = t * chunk;
        jobs[t].end = (t + 1) * chunk < count ? (t + 1) * chunk : count;
        jobs[t].success = jobs[t].fail = 0;
        jobs[t].lock = &lock;
        ok(pthread_create(&threads[t], NULL, worker_encrypt, &jobs[t]) == 0, "thread create failed");
    }
    int total_ok = 0, total_fail = 0;
    for (int t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        total_ok += jobs[t].success;
        total_fail += jobs[t].fail;
    }
    pthread_mutex_destroy(&lock);
    free_paths(paths, count);
    fprintf(stderr, "\nBatch encrypt done. Success: %d  Failed/Skipped: %d\n", total_ok, total_fail);
}

typedef struct {
    EVP_PKEY *priv;
    unsigned char id[ID_LEN];
    char **paths;
    int start, end, success, fail;
    pthread_mutex_t *lock;
} djob_t;

static void *worker_decrypt(void *arg)
{
    djob_t *j = arg;
    for (int i = j->start; i < j->end; i++) {
        const char *enc = j->paths[i];
        char base[PATH_MAX];
        strncpy(base, enc, sizeof base - 1);
        base[sizeof base - 1] = '\0';
        size_t len = strlen(base);
        if (len > 4 && strcmp(base + len - 4, ".enc") == 0) base[len - 4] = '\0';
        char key[PATH_MAX], out[PATH_MAX];
        snprintf(key, sizeof key, "%s.key", base);
        snprintf(out, sizeof out, "%s.restored", base);
        int ok_flag = decrypt_one(j->priv, j->id, key, enc, out);
        pthread_mutex_lock(j->lock);
        if (ok_flag) j->success++; else j->fail++;
        pthread_mutex_unlock(j->lock);
    }
    return NULL;
}

static void batch_decrypt(const char *priv_path)
{
    fprintf(stderr, "[1/3] Loading RSA private key: %s\n", priv_path);
    EVP_PKEY *priv = load_private_key(priv_path);
    if (!priv) {
        fprintf(stderr, "WARNING: RSA key verification failed — decrypt aborted\n");
        return;
    }
    fprintf(stderr, "[2/3] Master password applied — private key unlocked\n");
    unsigned char id[ID_LEN];
    compute_key_id(priv, id);

    char **paths = NULL;
    int count = 0;
    if (!load_paths_from_list(&paths, &count)) { EVP_PKEY_free(priv); return; }
    if (count == 0) {
        fprintf(stderr, "No paths in list/\n");
        free_paths(paths, count);
        EVP_PKEY_free(priv);
        return;
    }
    fprintf(stderr, "[3/3] Decrypting %d file(s), max %d threads...\n", count, MAX_THREADS);

    int nthreads = count < MAX_THREADS ? count : MAX_THREADS;
    if (nthreads < 1) nthreads = 1;
    pthread_t threads[MAX_THREADS];
    djob_t jobs[MAX_THREADS];
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    int chunk = (count + nthreads - 1) / nthreads;
    for (int t = 0; t < nthreads; t++) {
        jobs[t].priv = priv;
        memcpy(jobs[t].id, id, ID_LEN);
        jobs[t].paths = paths;
        jobs[t].start = t * chunk;
        jobs[t].end = (t + 1) * chunk < count ? (t + 1) * chunk : count;
        jobs[t].success = jobs[t].fail = 0;
        jobs[t].lock = &lock;
        ok(pthread_create(&threads[t], NULL, worker_decrypt, &jobs[t]) == 0, "decrypt thread create failed");
    }
    int total_ok = 0, total_fail = 0;
    for (int t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        total_ok += jobs[t].success;
        total_fail += jobs[t].fail;
    }
    pthread_mutex_destroy(&lock);
    free_paths(paths, count);
    EVP_PKEY_free(priv);
    fprintf(stderr, "\nBatch decrypt done. Success: %d  Failed/Skipped: %d\n", total_ok, total_fail);
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "init") == 0) {
        init_keys(argv[2], argv[3]);
        return EXIT_SUCCESS;
    }
    if (argc == 3 && strcmp(argv[1], "encrypt-list") == 0) {
        batch_encrypt(argv[2]);
        return EXIT_SUCCESS;
    }
    if (argc == 3 && strcmp(argv[1], "decrypt-list") == 0) {
        batch_decrypt(argv[2]);
        return EXIT_SUCCESS;
    }
    if (argc == 6 && strcmp(argv[1], "encrypt") == 0) {
        return encrypt_one(argv[2], argv[3], argv[4], argv[5]) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc == 6 && strcmp(argv[1], "decrypt") == 0) {
        fprintf(stderr, "Verifying RSA private key...\n");
        EVP_PKEY *priv = load_private_key(argv[2]);
        if (!priv) return EXIT_FAILURE;
        unsigned char id[ID_LEN];
        compute_key_id(priv, id);
        int rc = decrypt_one(priv, id, argv[3], argv[4], argv[5]);
        EVP_PKEY_free(priv);
        return rc ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    fprintf(stderr,
        "ChaCha20 Hybrid 32-byte Engine v7\n"
        "  RSA-4096 + OAEP | ChaCha20-Poly1305 | master password locked\n\n"
        "Usage:\n"
        "  %s init <private.pem> <public.pem>\n"
        "  %s encrypt <public.pem> <input> <output.enc> <output.key>\n"
        "  %s decrypt <private.pem> <input.key> <input.enc> <restored>\n"
        "  %s encrypt-list <public.pem>\n"
        "  %s decrypt-list <private.pem>\n\n"
        "Master password: Ffff@@@@1234@@Hash00\n"
        "After encrypt: only .enc + .key remain.\n",
        argv[0], argv[0], argv[0], argv[0], argv[0]);
    return EXIT_FAILURE;
}
