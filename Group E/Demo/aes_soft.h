#ifndef TINY_AES_H
#define TINY_AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCKLEN 16 // 128-bit blocks
#define AES_KEYLEN   16 // 128-bit key
#define AES_keyExpSize 176

typedef struct {
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv);

void AES_ECB_encrypt(const AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const AES_ctx* ctx, uint8_t* buf);

void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);

#endif
