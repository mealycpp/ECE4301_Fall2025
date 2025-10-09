CC=gcc
CFLAGS_EVP=-O3 -march=armv8-a+crypto -mtune=cortex-a76 -Wall
CFLAGS_PURE=-O3 -march=armv8-a -mtune=cortex-a76 -fno-builtin -Wall
LIBS=-lssl -lcrypto

all: aes_evp aes_afalg aes_pure

aes_evp: aes_evp.c
	$(CC) $(CFLAGS_EVP) $< -o $@ $(LIBS)

aes_afalg: aes_afalg.c
	$(CC) $(CFLAGS_EVP) $< -o $@

aes_pure: aes_pure.c
	$(CC) $(CFLAGS_PURE) $< -o $@
