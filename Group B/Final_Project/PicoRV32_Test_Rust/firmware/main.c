#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "sparkle.h"

// ---------------------------------------------------------------------------
// Memory-mapped IO addresses (match top.v)
// ---------------------------------------------------------------------------
#define UART_TX       (*(volatile uint32_t*)0x10000000)
#define CONTINUE_BTN  (*(volatile uint32_t*) 0x10000004)
#define SKIP_BTN      (*(volatile uint32_t*) 0x10000008)

// ---------------------------------------------------------------------------
// UART helpers (write-only TX; simple pacing)
// ---------------------------------------------------------------------------
static inline void putch(char c) {
    while (UART_TX & 1u) {}     // bit0==1 => busy; wait
    UART_TX = (uint8_t)c;        // only low byte is used by RTL
}

static void uart_puts(const char* s) {
    while (*s) putch(*s++);
}

// ---------------------------------------------------------------------------
// Decimal print with NO division (p10[] aligned)
// ---------------------------------------------------------------------------
void puthex32(uint32_t h) {
    int cur_digit;
    // Iterate through h taking top 4 bits each time and outputting ASCII of hex
    // digit for those 4 bits
    for (int i = 0; i < 8; i++) {
        cur_digit = h >> 28;

        if (cur_digit < 10)
            putch('0' + cur_digit);
        else
            putch('A' - 10 + cur_digit);

        h <<= 4;
    }
}

static void puthex64(uint64_t x) {
    uint32_t low = (uint32_t)(x & 0xFFFFFFFF);
    uint32_t high = (uint32_t)(x >> 32);

    puthex32(high);
    puthex32(low);
}

void put_u64(uint64_t x) {
    char buf[20];       // max decimal digits for uint64_t is 20
    int i = 0;

    // Special case: 0
    if (x == 0) {
        putch('0');
        return;
    }

    // Convert digits into buffer (reverse order)
    while (x > 0) {
        buf[i++] = '0' + (x % 10);
        x /= 10;
    }

    // Output in correct order
    while (i--) {
        putch(buf[i]);
    }
}

// ---------------------------------------------------------------------------
// Decimal print (NO division, NO modulo)
// Uses repeated subtraction against powers of 10
// ---------------------------------------------------------------------------
static const uint64_t p10_64[20] = {
    10000000000000000000ull, // 10^19
    1000000000000000000ull,  // 10^18
    100000000000000000ull,   // 10^17
    10000000000000000ull,    // 10^16
    1000000000000000ull,     // 10^15
    100000000000000ull,      // 10^14
    10000000000000ull,       // 10^13
    1000000000000ull,        // 10^12
    100000000000ull,         // 10^11
    10000000000ull,          // 10^10
    1000000000ull,           // 10^9
    100000000ull,            // 10^8
    10000000ull,             // 10^7
    1000000ull,              // 10^6
    100000ull,               // 10^5
    10000ull,                // 10^4
    1000ull,                 // 10^3
    100ull,                  // 10^2
    10ull,                   // 10^1
    1ull                     // 10^0
};

static void putdec64(uint64_t x) {
    int started = 0;
    for (int i = 0; i < 20; i++) {
        uint64_t p = p10_64[i];
        int digit = 0;
        while (x >= p) {
            x -= p;
            digit++;
        }
        if (digit || started || i == 19) {
            putch('0' + digit);
            started = 1;
        }
    }
}

// ---------------------------------------------------------------------------
// 64-bit counters (mcycle/minstret)
// ---------------------------------------------------------------------------
static inline uint64_t rdcycle64(void) {
    uint32_t hi, lo, hi2;
    __asm__ volatile ("rdcycleh %0" : "=r"(hi));
    __asm__ volatile ("rdcycle  %0" : "=r"(lo));
    __asm__ volatile ("rdcycleh %0" : "=r"(hi2));
    if (hi != hi2) { __asm__ volatile ("rdcycle %0" : "=r"(lo)); hi = hi2; }
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdinstret64(void) {
    uint32_t hi, lo, hi2;
    __asm__ volatile ("rdinstreth %0" : "=r"(hi));
    __asm__ volatile ("rdinstret  %0" : "=r"(lo));
    __asm__ volatile ("rdinstreth %0" : "=r"(hi2));
    if (hi != hi2) { __asm__ volatile ("rdinstret %0" : "=r"(lo)); hi = hi2; }
    return ((uint64_t)hi << 32) | lo;
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------
static int wait_for_press_release(volatile uint32_t* btn_reg) {
    while ((*btn_reg & 1) == 0);
    for (int stable = 0; stable < 10000; stable++) {
        if ((*btn_reg & 1)) stable = 0;
    }
    return 1;
}

bool compare(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(void) {
    uart_puts("Booting...\r\n");
    uart_puts("Sparkle implementation\r\n");

    uint8_t K[16]  = {0};
    uint8_t N[16]  = {0};
    uint8_t T[16];
    uint8_t PT[64] = {0};
    uint8_t CT[64] = {0};
    uint8_t DEC[64]= {0};

    size_t alen = 0;
    size_t mlen = 32;

    // Simple known plaintext pattern
    for (size_t i = 0; i < mlen; i++) {
        PT[i] = (uint8_t)i;
    }

    uart_puts("Message length (bytes): ");
    putdec64(mlen);
    uart_puts("\r\n");

    uart_puts("Encrypting + decrypting sample data...\r\n");

    // ------------------ MEASURE ENCRYPTION ------------------
    uint64_t c_enc_start = rdcycle64();
    uint64_t i_enc_start = rdinstret64();

    schwaemm128_128_encrypt(K, N, NULL, alen, PT, mlen, CT, T);

    uint64_t c_enc_end   = rdcycle64();
    uint64_t i_enc_end   = rdinstret64();

    // ------------------ MEASURE DECRYPTION ------------------
    uint64_t c_dec_start = rdcycle64();
    uint64_t i_dec_start = rdinstret64();

    int ok = schwaemm128_128_decrypt(K, N, NULL, alen, CT, mlen, DEC, T);

    uint64_t c_dec_end   = rdcycle64();
    uint64_t i_dec_end   = rdinstret64();

    // ------------------ CORRECTNESS CHECK -------------------
    if (ok == 0)
        uart_puts("Decryption tag: OK\r\n");
    else
        uart_puts("Decryption tag: FAIL\r\n");

    uart_puts("Plaintext match: ");
    if (compare(PT, DEC, mlen))
        uart_puts("YES\r\n");
    else
        uart_puts("NO\r\n");

    // ------------------ PRINT RAW COUNTERS ------------------
    uart_puts("\r\n=== ENC COUNTERS ===\r\n");
    uart_puts("ENC_CYCLE_START=");
    putdec64(c_enc_start);
    uart_puts("\r\nENC_CYCLE_END=");
    putdec64(c_enc_end);
    uart_puts("\r\nENC_CYCLES=");
    putdec64(c_enc_end - c_enc_start);
    uart_puts("\r\n");

    uart_puts("ENC_INST_START=");
    putdec64(i_enc_start);
    uart_puts("\r\nENC_INST_END=");
    putdec64(i_enc_end);
    uart_puts("\r\nENC_INSTRS=");
    putdec64(i_enc_end - i_enc_start);
    uart_puts("\r\n");

    uart_puts("\r\n=== DEC COUNTERS ===\r\n");
    uart_puts("DEC_CYCLE_START=");
    putdec64(c_dec_start);
    uart_puts("\r\nDEC_CYCLE_END=");
    putdec64(c_dec_end);
    uart_puts("\r\nDEC_CYCLES=");
    putdec64(c_dec_end - c_dec_start);
    uart_puts("\r\n");

    uart_puts("DEC_INST_START=");
    putdec64(i_dec_start);
    uart_puts("\r\nDEC_INST_END=");
    putdec64(i_dec_end);
    uart_puts("\r\nDEC_INSTRS=");
    putdec64(i_dec_end - i_dec_start);
    uart_puts("\r\n");

    uart_puts("\r\nProgram done. Press reset to rerun.\r\n");

    while (1) {
        __asm__ volatile("nop");
    }
}

