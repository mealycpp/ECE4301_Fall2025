#include "engine_stub.h"
#include <openssl/evp.h>

int engine_aes128_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t key[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return -1;

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    if(!ok){ EVP_CIPHER_CTX_free(ctx); return -1; }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen=0, tot=0;
    if(!EVP_EncryptUpdate(ctx, out, &outlen, in, (int)len)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    tot += outlen;
    if(!EVP_EncryptFinal_ex(ctx, out+tot, &outlen)){
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
