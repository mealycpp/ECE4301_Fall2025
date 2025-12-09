#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>

int crypto_sign_detached(
    uint8_t *sig,
    unsigned long long *siglen,
    const uint8_t *m,
    unsigned long long mlen,
    const uint8_t *sk
);

#endif
