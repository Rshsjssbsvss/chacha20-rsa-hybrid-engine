# ChaCha20 Hybrid 32-byte Engine v7
# Requires: libssl-dev (OpenSSL) and pthread

CC       = gcc
CFLAGS   = -O2 -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
LDFLAGS  = -lssl -lcrypto -lpthread
TARGET   = chacha20_hybrid
SRC      = chacha20_hybrid_engine.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Quick test help
help:
	@echo "Usage after build:"
	@echo "  ./$(TARGET) init <private.pem> <public.pem>"
	@echo "  ./$(TARGET) encrypt <public.pem> <input> <output.enc> <output.key>"
	@echo "  ./$(TARGET) decrypt <private.pem> <input.key> <input.enc> <restored>"
	@echo "  ./$(TARGET) encrypt-list <public.pem>"
	@echo "  ./$(TARGET) decrypt-list <private.pem>"
	@echo ""
	@echo "Master password: Ffff@@@@1234@@Hash00"
