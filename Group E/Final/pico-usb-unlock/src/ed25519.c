#include <stdint.h>
#include <stddef.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "ed25519.h"

// sk layout:
//   sk[0..31]  = secret seed
//   sk[32..63] = public key

int crypto_sign_detached(
    uint8_t *sig,
    unsigned long long *siglen,
    const uint8_t *m,
    unsigned long long mlen,
    const uint8_t *sk)
{
    // Use Monocypher’s high-level Ed25519 API
    crypto_ed25519_sign(sig, sk, m, (size_t)mlen);

    if (siglen) {
        *siglen = 64;
    }
    return 0;
}
