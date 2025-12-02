#include <stdio.h>
#include <stdint.h>

int main() {
    FILE *f = fopen("/dev/hwrng", "rb");
    uint32_t x;

    while (1) {
        fread(&x, 1, 4, f);
        printf("%08x\n", x);
    }
}
