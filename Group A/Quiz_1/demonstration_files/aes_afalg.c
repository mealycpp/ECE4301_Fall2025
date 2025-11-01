// aes_afalg.c (robust)
// Benchmark AES-256-CBC via Linux AF_ALG (kernel crypto API) with safe I/O.
// Usage: ./aes_afalg [TOTAL_BYTES]   (default 268435456 = 256 MiB; must be multiple of 16)

#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <fcntl.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif
#ifndef ALG_SET_IV
#define ALG_SET_IV 2
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

static double now_sec(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec/1e9; }

static void* xaligned_alloc(size_t align, size_t size){
#if defined(_ISOC11_SOURCE)
    return aligned_alloc(align, size);
#else
    void *p = NULL;
    if (posix_memalign(&p, align, size) != 0) return NULL;
    return p;
#endif
}

static void die(const char* msg){ perror(msg); exit(1); }

static int set_timeout(int fd, int sec){
    struct timeval tv = { .tv_sec = sec, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) return -1;
    return 0;
}

int main(int argc, char **argv){
    // ---------- params ----------
    size_t total = (argc > 1) ? strtoull(argv[1], NULL, 10) : (size_t)268435456; // 256 MiB
    const size_t block    = 16;           // AES block size for CBC
    const size_t chunk_sz = 64u * 1024u;  // 64 KiB per request (safer for AF_ALG)
    if (total == 0 || (total % block) != 0){
        fprintf(stderr, "ERROR: TOTAL_BYTES must be >0 and a multiple of 16 for CBC.\n");
        return 1;
    }

    // ---------- AF_ALG setup ----------
    int tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfmfd == -1) die("socket(AF_ALG)");

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char*)sa.salg_type, "skcipher");
    // Try CBC first; if issues, you can test ECB by changing to "ecb(aes)"
    strcpy((char*)sa.salg_name, "cbc(aes)");

    if (bind(tfmfd, (struct sockaddr*)&sa, sizeof(sa)) == -1) die("bind(AF_ALG, cbc(aes))");

    unsigned char key[32] = {0}; // AES-256 test key
    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) die("ALG_SET_KEY");

    int opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1) die("accept(opfd)");

    // Add timeouts so we never block indefinitely
    if (set_timeout(opfd, 5) == -1) die("setsockopt(SO_*TIMEO)");

    // ---------- buffers ----------
    unsigned char *in  = (unsigned char*)xaligned_alloc(64, total);
    unsigned char *out = (unsigned char*)xaligned_alloc(64, total);
    if (!in || !out){ fprintf(stderr, "alloc failed\n"); return 1; }
    memset(in, 0xA5, total);

    unsigned char iv[16] = {0}; // fixed IV for timing comparability

    // ---------- benchmark ----------
    size_t off = 0;
    double t0 = now_sec();

    while (off < total){
        size_t this_chunk = total - off;
        if (this_chunk > chunk_sz) this_chunk = chunk_sz;
        // ensure chunk is block aligned
        this_chunk -= (this_chunk % block);

        // Build control messages: IV first, then OP
        char cbuf[CMSG_SPACE(sizeof(struct af_alg_iv) + sizeof(iv)) +
                  CMSG_SPACE(sizeof(int))];
        memset(cbuf, 0, sizeof(cbuf));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        // CMSG #1: IV
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type  = ALG_SET_IV;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + sizeof(iv));
        struct af_alg_iv *aiv = (struct af_alg_iv*)CMSG_DATA(cmsg);
        aiv->ivlen = sizeof(iv);
        memcpy(aiv->iv, iv, sizeof(iv));

        // CMSG #2: operation = encrypt
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type  = ALG_SET_OP;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
        *(int*)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

        // Payload for this write
        struct iovec iov;
        iov.iov_base = in + off;
        iov.iov_len  = this_chunk;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Robust send loop (handles short send, EAGAIN)
        size_t sent_total = 0;
        while (sent_total < this_chunk){
            // For the first send, include control headers; afterwards, send remaining without control
            ssize_t s;
            if (sent_total == 0){
                s = sendmsg(opfd, &msg, 0);
            } else {
                // subsequent sends (should be rare) — raw write of the rest
                s = send(opfd, (const char*)in + off + sent_total, this_chunk - sent_total, 0);
            }
            if (s == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                die("send/sendmsg");
            }
            sent_total += (size_t)s;
        }

        // Robust read loop (handles partial reads)
        size_t got_total = 0;
        while (got_total < this_chunk){
            ssize_t r = recv(opfd, out + off + got_total, this_chunk - got_total, 0);
            if (r == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                die("recv");
            }
            if (r == 0){
                fprintf(stderr, "recv returned 0 (unexpected EOF)\n");
                return 1;
            }
            got_total += (size_t)r;
        }

        off += this_chunk;
    }

    double t1 = now_sec();
    double secs = t1 - t0;
    double mib  = (double)total / (1024.0*1024.0);
    printf("AF_ALG AES-256-CBC: %.2f MiB in %.4f s  =>  %.2f MiB/s\n", mib, secs, mib/secs);

    // ---------- cleanup ----------
    free(in); free(out);
    close(opfd); close(tfmfd);
    return 0;
}
