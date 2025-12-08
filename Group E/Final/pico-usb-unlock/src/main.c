#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "pico/stdlib.h"
#include "ed25519.h"


static const unsigned char ed25519_sk[64] = {
    0x54,
    0x9c,
    0xf2,
    0x91,
    0x52,
    0x43,
    0xa6,
    0x93,
    0x71,
    0x64,
    0x15,
    0xea,
    0x6e,
    0xae,
    0xf1,
    0x72,
    0x00,
    0x4e,
    0x9f,
    0x62,
    0x21,
    0x35,
    0x06,
    0xb0,
    0x75,
    0x99,
    0xb5,
    0x8d,
    0x84,
    0xd2,
    0xe6,
    0x72,
    0x7f,
    0x86,
    0x5c,
    0x99,
    0x46,
    0xbd,
    0x34,
    0x7a,
    0x56,
    0x4a,
    0xc0,
    0x0d,
    0xdf,
    0xdd,
    0xad,
    0x9b,
    0x30,
    0xf1,
    0x36,
    0xb3,
    0xa2,
    0xd6,
    0xcb,
    0xee,
    0x98,
    0x19,
    0xc2,
    0x72,
    0x30,
    0x28,
    0xd6,
    0xfe
};

static void bytes_to_hex(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

int main() {
    stdio_init_all();
    sleep_ms(2000);  // Wait for USB enumeration

    char line[256];

    while (true) {

        // Read one line from USB
        if (!fgets(line, sizeof(line), stdin)) {
            sleep_ms(10);
            continue;
        }

        // Strip newline
        size_t msg_len = strlen(line);
        if (msg_len > 0 && (line[msg_len - 1] == '\n' || line[msg_len - 1] == '\r')) {
            line[--msg_len] = '\0';
        }

        unsigned char sig[64];
        unsigned long long siglen = 0;

        // Sign the message
        if (crypto_sign_detached(sig, &siglen,
            (const unsigned char *)line,
            (unsigned long long)msg_len,
            ed25519_sk) != 0)
        {
            printf("ERR\n");
            fflush(stdout);
            continue;
        }

        // Convert signature to hex and send it back
        char sig_hex[129];
        bytes_to_hex(sig, siglen, sig_hex);
        printf("%s\n", sig_hex);
        fflush(stdout);
    }
}
