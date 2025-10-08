#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static double now_sec(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec/1e9; }

int main(int argc, char **argv) {
    size_t total = (argc > 1) ? strtoull(argv[1], NULL, 10) : (size_t)32*1024*1024; // 32 MiB default
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = {0};
    unsigned char iv[16]  = {0};

    unsigned char *in  = malloc(total);
    unsigned char *out = malloc(total + EVP_CIPHER_block_size(cipher));
    if(!in || !out){ fprintf(stderr,"alloc failed\n"); return 1; }
    memset(in, 0xA5, total);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tmplen = 0;

    double t0 = now_sec();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // make timing cleaner; total should be multiple of 16 for CBC
    size_t done = 0;
    while (done < total) {
        size_t chunk = (total - done > 1<<20) ? (1<<20) : (total - done); // 1 MiB chunks
        int outc = 0;
        if(!EVP_EncryptUpdate(ctx, out + outl, &outc, in + done, (int)chunk)){ fprintf(stderr,"EVP_EncryptUpdate failed\n"); return 1; }
        outl += outc;
        done += chunk;
    }
    if(!EVP_EncryptFinal_ex(ctx, out + outl, &tmplen)){ fprintf(stderr,"EVP_EncryptFinal_ex failed\n"); return 1; }
    outl += tmplen;
    double t1 = now_sec();

    double secs = t1 - t0;
    double mib  = (double)total / (1024.0*1024.0);
    printf("EVP AES-256-CBC: %.2f MiB in %.4f s  =>  %.2f MiB/s\n", mib, secs, mib/secs);

    EVP_CIPHER_CTX_free(ctx);
    free(in); free(out);
    return 0;
}
