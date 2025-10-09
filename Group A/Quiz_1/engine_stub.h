#pragma once
#include <stddef.h>
#include <stdint.h>
int engine_aes128_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16]);
