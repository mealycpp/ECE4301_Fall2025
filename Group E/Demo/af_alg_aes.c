#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

// op: 0 = encrypt, 1 = decrypt
int afalg_aes_cbc_crypt(int op, const uint8_t* key, size_t keylen,
                        const uint8_t* iv, size_t ivlen,
                        uint8_t* buf, size_t len) {
  if (len % 16 != 0) { fprintf(stderr, "Length must be multiple of 16\n"); return -1; }
  if (ivlen != 16 || keylen != 16) { fprintf(stderr, "Expect 16-byte key/iv\n"); return -1; }

  int tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (tfmfd < 0) { perror("socket(AF_ALG)"); return -1; }

  struct sockaddr_alg sa = {
    .salg_family = AF_ALG,
    .salg_type   = "skcipher",
    .salg_name   = "cbc(aes)"
  };
  if (bind(tfmfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); close(tfmfd); return -1; }
  if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) < 0) { perror("ALG_SET_KEY"); close(tfmfd); return -1; }

  const size_t SLICE = 64*1024;
  uint8_t current_iv[16]; memcpy(current_iv, iv, 16);

  size_t off=0;
  while(off < len){
    size_t want = len - off;
    if (want > SLICE) want = SLICE;
    want = (want/16)*16;

    int opfd = accept(tfmfd, NULL, 0);
    if (opfd < 0) { perror("accept"); close(tfmfd); return -1; }

    // Save last input ciphertext block for decrypt path (before we overwrite buf)
    uint8_t last_ct[16];
    if (op == 1) memcpy(last_ct, (buf + off) + want - 16, 16);

    // control buffer for IV and operation
    size_t ivmsg_len = sizeof(struct af_alg_iv) + 16;
    char cbuf[CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));

    struct iovec iov = { .iov_base = buf + off, .iov_len = want };
    struct msghdr msg; memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_IV;
    cmsg->cmsg_len   = CMSG_LEN(ivmsg_len);
    struct af_alg_iv* ivmsg = (struct af_alg_iv*)CMSG_DATA(cmsg);
    ivmsg->ivlen = 16; memcpy(ivmsg->iv, current_iv, 16);

    struct cmsghdr* cmsg2 = (struct cmsghdr*)((char*)cmsg + CMSG_SPACE(ivmsg_len));
    cmsg2->cmsg_level = SOL_ALG;
    cmsg2->cmsg_type  = ALG_SET_OP;
    cmsg2->cmsg_len   = CMSG_LEN(sizeof(int));
    int* opval = (int*)CMSG_DATA(cmsg2);
    *opval = (op==0) ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    if (sendmsg(opfd, &msg, 0) < 0) { perror("sendmsg"); close(opfd); close(tfmfd); return -1; }
    ssize_t r = read(opfd, buf + off, want);
    if (r < 0) { perror("read"); close(opfd); close(tfmfd); return -1; }
    if ((size_t)r != want) { fprintf(stderr,"short read\n"); close(opfd); close(tfmfd); return -1; }

    if (op == 0) {
      // encrypt: next IV = last ciphertext from output
      memcpy(current_iv, buf + off + want - 16, 16);
    } else {
      // decrypt: next IV = last input ciphertext block (saved)
      memcpy(current_iv, last_ct, 16);
    }
    close(opfd);
    off += want;
  }
  close(tfmfd);
  return 0;
}
