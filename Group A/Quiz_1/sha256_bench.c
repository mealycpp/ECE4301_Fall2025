#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/evp.h>

#if defined(__aarch64__)
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 3) // fallback: typical value on aarch64
#endif
#endif

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}

typedef struct { size_t sz; int iters; int thread_id; } job_t;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void *run_sha256(void *arg) {
    job_t *j = (job_t*)arg;

    uint8_t *in  = aligned_alloc(64, j->sz);
    if (!in) die("aligned_alloc in");
    uint8_t *digest = aligned_alloc(64, 32); // SHA-256 = 32 bytes
    if (!digest) die("aligned_alloc digest");

    memset(in, 0xA5, j->sz);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("EVP_MD_CTX_new");

    // Warm-up to avoid one-time overheads
    unsigned int dlen = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) die("EVP_DigestInit_ex");
    if (EVP_DigestUpdate(ctx, in, j->sz) != 1) die("EVP_DigestUpdate");
    if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) die("EVP_DigestFinal_ex");

    uint64_t t0 = ns_now();
    for (int i = 0; i < j->iters; i++) {
        // fresh hash each iteration (comparable to your AES loop)
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) die("EVP_DigestInit_ex");
        if (EVP_DigestUpdate(ctx, in, j->sz) != 1) die("EVP_DigestUpdate");
        if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) die("EVP_DigestFinal_ex");
    }
    uint64_t t1 = ns_now();

    double sec = (t1 - t0) / 1e9;
    double bytes = (double)j->sz * j->iters;
    double thr_mib_s = (bytes / 1048576.0) / sec;
    double lat_us = (sec * 1e6) / j->iters;

    printf("thread=%d,size=%zu,iter=%d,time_s=%.6f,throughput_MiB_s=%.2f,latency_us=%.2f\n",
           j->thread_id, j->sz, j->iters, sec, thr_mib_s, lat_us);

    EVP_MD_CTX_free(ctx);
    free(in);
    free(digest);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <size_bytes> <iters> <threads>\n", argv[0]);
        return 1;
    }
    size_t sz = strtoull(argv[1], NULL, 10);
    int iters = atoi(argv[2]);
    int threads = atoi(argv[3]);

#if defined(__aarch64__)
    unsigned long hw = getauxval(AT_HWCAP);
    int has_sha2 = (hw & HWCAP_SHA2) ? 1 : 0;
    fprintf(stderr, "CPU feature check: SHA2=%s (HWCAP=0x%lx)\n",
            has_sha2 ? "yes" : "no", hw);
#else
    fprintf(stderr, "CPU feature check: non-AArch64 build; skipping HWCAP SHA2 test.\n");
#endif

    // OpenSSL one-time initialization (no-op in modern versions, kept for clarity)
    OPENSSL_init_crypto(0, NULL);

    pthread_t *ts = (pthread_t*)malloc(sizeof(pthread_t)*threads);
    job_t *jobs = (job_t*)malloc(sizeof(job_t)*threads);
    if (!ts || !jobs) die("malloc");

    for (int t = 0; t < threads; t++) {
        jobs[t] = (job_t){ .sz = sz, .iters = iters, .thread_id = t };
        int rc = pthread_create(&ts[t], NULL, run_sha256, &jobs[t]);
        if (rc != 0) { errno = rc; die("pthread_create"); }
    }
    for (int t = 0; t < threads; t++) {
        pthread_join(ts[t], NULL);
    }

    free(ts);
    free(jobs);
    return 0;
}
