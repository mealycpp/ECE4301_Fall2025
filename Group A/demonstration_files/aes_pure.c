// aes_pure.c
// Pure C AES-256-CBC (no OpenSSL, no ARMv8 CE). For benchmarking only.
// Usage: ./aes_pure [TOTAL_BYTES]  (must be multiple of 16)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static double now_sec(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec/1e9; }

static void* xaligned_alloc(size_t align, size_t size){
#if defined(_ISOC11_SOURCE)
    return aligned_alloc(align, size);
#else
    void *p=NULL; if (posix_memalign(&p, align, size)!=0) return NULL; return p;
#endif
}

/* --- AES tables --- */
static const uint8_t sbox[256] = {
  // 256-byte AES S-box
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t Rcon[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D};

static uint8_t xtime(uint8_t x){ return (uint8_t)((x<<1) ^ ((x & 0x80)?0x1B:0x00)); }
static uint8_t mul(uint8_t x, uint8_t y){ // GF(2^8) multiply
    uint8_t r=0; while(y){ if(y&1) r^=x; x=xtime(x); y>>=1; } return r;
}

/* --- AES-256 key schedule --- */
static void key_expansion_256(const uint8_t *key, uint8_t *w/*240 bytes*/){
    memcpy(w, key, 32);
    uint8_t temp[4];
    int i = 32, rcon_idx = 1;
    while (i < 240){
        memcpy(temp, &w[i-4], 4);
        if (i % 32 == 0){
            // RotWord
            uint8_t t = temp[0]; temp[0]=temp[1]; temp[1]=temp[2]; temp[2]=temp[3]; temp[3]=t;
            // SubWord
            temp[0]=sbox[temp[0]]; temp[1]=sbox[temp[1]]; temp[2]=sbox[temp[2]]; temp[3]=sbox[temp[3]];
            temp[0] ^= Rcon[rcon_idx++];
        } else if (i % 32 == 16){
            // SubWord
            temp[0]=sbox[temp[0]]; temp[1]=sbox[temp[1]]; temp[2]=sbox[temp[2]]; temp[3]=sbox[temp[3]];
        }
        for (int j=0;j<4;j++) { w[i] = w[i-32] ^ temp[j]; i++; }
    }
}

/* --- AES round helpers --- */
static void sub_bytes(uint8_t s[16]){ for(int i=0;i<16;i++) s[i]=sbox[s[i]]; }
static void shift_rows(uint8_t s[16]){
    uint8_t t[16];
    t[ 0]=s[ 0]; t[ 4]=s[ 4]; t[ 8]=s[ 8]; t[12]=s[12];
    t[ 1]=s[ 5]; t[ 5]=s[ 9]; t[ 9]=s[13]; t[13]=s[ 1];
    t[ 2]=s[10]; t[ 6]=s[14]; t[10]=s[ 2]; t[14]=s[ 6];
    t[ 3]=s[15]; t[ 7]=s[ 3]; t[11]=s[ 7]; t[15]=s[11];
    memcpy(s,t,16);
}
static void mix_columns(uint8_t s[16]){
    for(int c=0;c<4;c++){
        uint8_t *p=&s[c*4];
        uint8_t a0=p[0], a1=p[1], a2=p[2], a3=p[3];
        p[0]= (uint8_t)(mul(0x02,a0)^mul(0x03,a1)^a2^a3);
        p[1]= (uint8_t)(a0^mul(0x02,a1)^mul(0x03,a2)^a3);
        p[2]= (uint8_t)(a0^a1^mul(0x02,a2)^mul(0x03,a3));
        p[3]= (uint8_t)(mul(0x03,a0)^a1^a2^mul(0x02,a3));
    }
}
static void add_round_key(uint8_t s[16], const uint8_t *rk){ for(int i=0;i<16;i++) s[i]^=rk[i]; }

/* --- Encrypt one 16-byte block with AES-256 --- */
static void aes256_encrypt_block(const uint8_t rk[240], const uint8_t in[16], uint8_t out[16]){
    uint8_t s[16]; memcpy(s,in,16);
    add_round_key(s, rk);
    for(int r=1;r<=13;r++){
        sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, rk + 16*r);
    }
    sub_bytes(s); shift_rows(s); add_round_key(s, rk + 16*14);
    memcpy(out,s,16);
}

/* --- CBC encrypt (no padding), IV must be 16 bytes --- */
static void aes256_cbc_encrypt(const uint8_t *key, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len){
    uint8_t rk[240]; key_expansion_256(key, rk);
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (size_t off=0; off<len; off+=16){
        uint8_t blk[16];
        for(int i=0;i<16;i++) blk[i] = in[off+i] ^ prev[i];
        aes256_encrypt_block(rk, blk, &out[off]);
        memcpy(prev, &out[off], 16);
    }
}

int main(int argc, char **argv){
    size_t total = (argc>1) ? strtoull(argv[1], NULL, 10) : (size_t)268435456; // 256 MiB default
    if (total==0 || (total % 16)!=0){ fprintf(stderr,"TOTAL_BYTES must be >0 and multiple of 16\n"); return 1; }

    uint8_t *in  = (uint8_t*)xaligned_alloc(64, total);
    uint8_t *out = (uint8_t*)xaligned_alloc(64, total);
    if(!in || !out){ fprintf(stderr,"alloc failed\n"); return 1; }
    memset(in, 0xA5, total);

    uint8_t key[32] = {0}; // 256-bit zero key (benchmarking only)
    uint8_t iv [16] = {0}; // zero IV (benchmarking only)

    double t0 = now_sec();
    // process in 1 MiB chunks to keep caches friendly
    size_t chunk = 1u<<20;
    for (size_t off=0; off<total; ){
        size_t n = total-off; if (n>chunk) n=chunk; n -= (n%16);
        aes256_cbc_encrypt(key, iv, in+off, out+off, n);
        // CBC with fixed IV per chunk is OK for benchmarking throughput; not secure for real data.
        off += n;
    }
    double t1 = now_sec();

    double secs = t1 - t0;
    double mib  = (double)total / (1024.0*1024.0);
    printf("PURE AES-256-CBC: %.2f MiB in %.4f s  =>  %.2f MiB/s\n", mib, secs, mib/secs);

    free(in); free(out);
    return 0;
}
