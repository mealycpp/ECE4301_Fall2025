#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>

#include "aes_soft.h"

int afalg_aes_cbc_crypt(int op, const uint8_t* key, size_t keylen,
                        const uint8_t* iv, size_t ivlen,
                        uint8_t* buf, size_t len);

static inline double now_sec() {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void fill_random(uint8_t* p, size_t n) {
  FILE* f = fopen("/dev/urandom", "rb");
  if (!f) { perror("urandom"); exit(1); }
  fread(p, 1, n, f);
  fclose(f);
}

typedef enum { IMPL_SOFT=0, IMPL_AFALG=1 } impl_t;
typedef enum { OP_ENC=0, OP_DEC=1 } op_t;

/* ------------ software (pure C) paths ------------ */
static double bench_soft_enc(size_t total_bytes, size_t chunk) {
  uint8_t key[16], iv[16]; fill_random(key, 16); fill_random(iv, 16);
  AES_ctx ctx; AES_init_ctx_iv(&ctx, key, iv);

  uint8_t* buf = (uint8_t*)aligned_alloc(64, chunk);
  if (!buf) { perror("alloc"); exit(1); }
  fill_random(buf, chunk);

  size_t done = 0; double t0 = now_sec();
  while (done < total_bytes) {
    AES_ctx_set_iv(&ctx, iv);
    AES_CBC_encrypt_buffer(&ctx, buf, chunk);
    done += chunk;
  }
  double t1 = now_sec(); free(buf); return (t1 - t0);
}

static double bench_soft_dec(size_t total_bytes, size_t chunk) {
  uint8_t key[16], iv[16]; fill_random(key, 16); fill_random(iv, 16);
  AES_ctx ctx; AES_init_ctx_iv(&ctx, key, iv);

  uint8_t* plain = (uint8_t*)aligned_alloc(64, chunk);
  uint8_t* ct    = (uint8_t*)aligned_alloc(64, chunk);
  if (!plain || !ct) { perror("alloc"); exit(1); }
  fill_random(plain, chunk);

  // Pre-encrypt one chunk to obtain ciphertext we can repeatedly decrypt
  AES_ctx_set_iv(&ctx, iv);
  memcpy(ct, plain, chunk);
  AES_CBC_encrypt_buffer(&ctx, ct, chunk);

  size_t done = 0; double t0 = now_sec();
  while (done < total_bytes) {
    AES_ctx_set_iv(&ctx, iv);
    memcpy(plain, ct, chunk);            // reuse same ciphertext / IV pair
    AES_CBC_decrypt_buffer(&ctx, plain, chunk);
    done += chunk;
  }
  double t1 = now_sec();
  free(plain); free(ct);
  return (t1 - t0);
}

/* ------------ AF_ALG paths ------------ */
static double bench_afalg(size_t total_bytes, size_t chunk, op_t op) {
  uint8_t key[16], iv[16]; fill_random(key, 16); fill_random(iv, 16);

  uint8_t* buf = (uint8_t*)aligned_alloc(64, chunk);
  uint8_t* ct  = (uint8_t*)aligned_alloc(64, chunk);
  if (!buf || !ct) { perror("alloc"); exit(1); }

  fill_random(buf, chunk);

  // Precompute ciphertext for decrypt path
  if (op == OP_DEC) {
    memcpy(ct, buf, chunk);
    if (afalg_aes_cbc_crypt(0, key, sizeof key, iv, sizeof iv, ct, chunk) != 0) {
      fprintf(stderr,"AF_ALG pre-encrypt failed\n"); exit(2);
    }
  }

  size_t done = 0; double t0 = now_sec();
  while (done < total_bytes) {
    if (op == OP_ENC) {
      memcpy(ct, buf, chunk);
      if (afalg_aes_cbc_crypt(0, key, sizeof key, iv, sizeof iv, ct, chunk) != 0) {
        fprintf(stderr,"AF_ALG enc fail\n"); exit(2);
      }
    } else {
      memcpy(buf, ct, chunk);
      if (afalg_aes_cbc_crypt(1, key, sizeof key, iv, sizeof iv, buf, chunk) != 0) {
        fprintf(stderr,"AF_ALG dec fail\n"); exit(2);
      }
    }
    done += chunk;
  }
  double t1 = now_sec();
  free(buf); free(ct);
  return (t1 - t0);
}

/* ------------ CLI + CSV ------------ */
static void usage(const char* a0){
  fprintf(stderr, "Usage: %s --impl soft|afalg --op enc|dec --total-mb N --chunk KB --csv results.csv\n", a0);
}

int main(int argc, char** argv){
  impl_t impl = IMPL_SOFT;
  op_t op = OP_ENC;
  size_t total_mb = 256, chunk_kb = 64;
  const char* csv = NULL;

  for (int i=1;i<argc;i++){
    if (!strcmp(argv[i],"--impl") && i+1<argc){
      if (!strcmp(argv[i+1],"soft")) impl = IMPL_SOFT;
      else if (!strcmp(argv[i+1],"afalg")) impl = IMPL_AFALG;
      else { usage(argv[0]); return 1; }
      i++;
    } else if (!strcmp(argv[i],"--op") && i+1<argc){
      if (!strcmp(argv[i+1],"enc")) op = OP_ENC;
      else if (!strcmp(argv[i+1],"dec")) op = OP_DEC;
      else { usage(argv[0]); return 1; }
      i++;
    } else if (!strcmp(argv[i],"--total-mb") && i+1<argc){
      total_mb = (size_t)atoi(argv[i+1]); i++;
    } else if (!strcmp(argv[i],"--chunk") && i+1<argc){
      chunk_kb = (size_t)atoi(argv[i+1]); i++;
    } else if (!strcmp(argv[i],"--csv") && i+1<argc){
      csv = argv[i+1]; i++;
    } else { usage(argv[0]); return 1; }
  }

  size_t total_bytes = total_mb * 1024ULL * 1024ULL;
  size_t chunk = (chunk_kb * 1024ULL);
  chunk = (chunk/16)*16;
  if (chunk==0) { fprintf(stderr,"chunk too small\n"); return 1; }

  struct rusage ru0, ru1; getrusage(RUSAGE_SELF,&ru0);
  double elapsed=-1.0;
  if (impl==IMPL_SOFT){
    elapsed = (op==OP_ENC) ? bench_soft_enc(total_bytes, chunk)
                           : bench_soft_dec(total_bytes, chunk);
  } else {
    elapsed = bench_afalg(total_bytes, chunk, op);
  }
  getrusage(RUSAGE_SELF,&ru1);

  if (elapsed<0) return 2;

  double throughput_mb_s = (double)total_mb / elapsed;
  long utime_us = (ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec)*1000000L +
                  (ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec);
  long stime_us = (ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec)*1000000L +
                  (ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec);

  if (csv){
    FILE* f = fopen(csv, "a+");
    if (!f) { perror("csv"); return 1; }
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    if (end == 0) {
      fprintf(f, "impl,op,total_mb,chunk_kb,elapsed_s,throughput_MBps,utime_us,stime_us\n");
    }
    fprintf(f, "%s,%s,%zu,%zu,%.6f,%.3f,%ld,%ld\n",
      (impl==IMPL_SOFT?"soft":"afalg"), (op==OP_ENC?"enc":"dec"),
      total_mb, chunk/1024, elapsed, throughput_mb_s, utime_us, stime_us);
    fclose(f);
  } else {
    printf("Impl=%s Op=%s total=%zuMB chunk=%zuKB elapsed=%.6fs throughput=%.2f MB/s user=%ldus sys=%ldus\n",
      (impl==IMPL_SOFT?"soft":"afalg"), (op==OP_ENC?"enc":"dec"),
      total_mb, chunk/1024, elapsed, throughput_mb_s, utime_us, stime_us);
  }
  return 0;
}
