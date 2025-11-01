// bench.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static inline uint64_t ns_now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}

extern int engine_aes128_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                                     const uint8_t key[16]); 

typedef struct { size_t sz; int iters; int thread_id; } job_t;

void *run_aes(void *arg){
    job_t *j = (job_t*)arg;
    uint8_t *in  = aligned_alloc(64, j->sz);
    uint8_t *out = aligned_alloc(64, j->sz);
    uint8_t key[16] = {0};
    memset(in, 0xA5, j->sz);

    engine_aes128_ecb_encrypt(in, out, j->sz, key);

    uint64_t t0 = ns_now();
    for(int i=0;i<j->iters;i++)
        engine_aes128_ecb_encrypt(in, out, j->sz, key);
    uint64_t t1 = ns_now();

    double sec = (t1 - t0)/1e9;
    double bytes = (double)j->sz * j->iters;
    printf("thread=%d,size=%zu,iter=%d,time_s=%.6f,throughput_MiB_s=%.2f,latency_us=%.2f\n",
           j->thread_id, j->sz, j->iters, sec, (bytes/1048576.0)/sec,
           (sec*1e6)/j->iters);

    free(in); free(out);
    return NULL;
}

int main(int argc, char **argv){
    if(argc < 4){ fprintf(stderr,"usage: %s <size_bytes> <iters> <threads>\n", argv[0]); return 1; }
    size_t sz = strtoull(argv[1],0,10);
    int iters = atoi(argv[2]);
    int threads = atoi(argv[3]);

    pthread_t *ts = malloc(sizeof(pthread_t)*threads);
    job_t *jobs = malloc(sizeof(job_t)*threads);

    for(int t=0;t<threads;t++){
        jobs[t]=(job_t){.sz=sz,.iters=iters,.thread_id=t};
        pthread_create(&ts[t], NULL, run_aes, &jobs[t]);
    }
    for(int t=0;t<threads;t++) pthread_join(ts[t], NULL);

    free(ts); free(jobs);
    return 0;
}
