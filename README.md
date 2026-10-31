# / Ransumwar / ChaCha20 Hybrid 32-byte Engine v7

Adaptive hybrid encryption engine:

- **ChaCha20-Poly1305** AEAD (256-bit / 32-byte session key)
- **RSA-4096 + OAEP (SHA-256)** key wrap
- Master private-key password: `Ffff@@@@1234@@Hash00`

## Adaptive Chunks (light update)

| File size          | Chunk size | Progress interval |
|--------------------|------------|-------------------|
| < 1 GiB (MB range) | 1 KiB      | every 10 KiB      |
| ≥ 1 GiB (GB range) | 1 MiB      | every 10 MiB      |

## Build

```bash
# Install dependency (Debian/Ubuntu)
sudo apt install libssl-dev

# Compile
make
```

## Usage

```bash
./chacha20_hybrid init private.pem public.pem
./chacha20_hybrid encrypt public.pem inputfile output.enc output.key
./chacha20_hybrid decrypt private.pem input.key input.enc restored
./chacha20_hybrid encrypt-list public.pem
./chacha20_hybrid decrypt-list private.pem
```

After encryption only `.enc` + `.key` remain (plaintext is securely wiped).
=======
# chacha20-rsa-hybrid-engine
Hybrid cryptography engine using ChaCha20 and RSA
>>>>>>> a1fcd339408bb3801399b96638d2dafb7d725454
