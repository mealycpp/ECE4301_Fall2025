// build: gcc -O2 -Wall -maes -msse2 aesenc_while.c -o aesenc_while
#include <stdlib.h>

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

int main(int argc, char** argv) {
	__asm__ volatile(
		".rept " STRINGIFY(REPT_COUNT) " / " STRINGIFY(ASM_UNDER_TEST_REPT_COUNT) "\n\t"
		ASM_UNDER_TEST
		".endr"
		:
		:
		: ASM_UNDER_TEST_CLOBBERS);
	return 0;
}

