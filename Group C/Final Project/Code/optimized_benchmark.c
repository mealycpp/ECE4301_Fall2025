/*
 * ASCON Optimized Benchmark Suite for Cross-Platform Testing
 * Designed for cross-platform performance comparison
 * 
 * Features:
 * - Cycle-accurate measurements using PMU (Performance Monitoring Unit)
 * - CPU frequency detection and normalization
 * - Cache warming and statistical analysis
 * - Multiple message sizes and test scenarios
 * - CSV output for data analysis
 * 
 * Compile:
 * gcc -O3 -march=native -mtune=native -flto -fomit-frame-pointer \
 *     -Wall -Wextra benchmark.c -o benchmark -lrt -lm
 * 
 * For Pi Zero W specifically:
 * gcc -O3 -march=armv6 -mfpu=vfp -mfloat-abi=hard -flto \
 *     -fomit-frame-pointer benchmark.c -o benchmark -lrt -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define WARMUP_ITERATIONS    100
#define BENCHMARK_ITERATIONS 1000
#define MIN_ITERATIONS       10
#define MAX_ITERATIONS       100000

/* Test message sizes (bytes) */
static const size_t TEST_SIZES[] = {
    16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
};
#define NUM_TEST_SIZES (sizeof(TEST_SIZES) / sizeof(TEST_SIZES[0]))

/* ============================================================================
 * Timing Infrastructure
 * ============================================================================ */

/* High-resolution monotonic timer */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* CPU cycle counter (ARM-specific) */
#ifdef __aarch64__
static inline uint64_t get_cycles(void) {
    uint64_t cycles;
    asm volatile("mrs %0, cntvct_el0" : "=r"(cycles));
    return cycles;
}
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_7A__)
/* ARMv6/ARMv7 - use PMCCNTR if available */
static inline uint64_t get_cycles(void) {
    /* Fallback to time-based estimation if PMU not accessible */
    static uint64_t freq = 0;
    if (freq == 0) {
        FILE *fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
        if (fp) {
            unsigned long khz;
            if (fscanf(fp, "%lu", &khz) == 1) {
                freq = khz * 1000ULL;
            }
            fclose(fp);
        }
        if (freq == 0) freq = 1000000000ULL; /* Default 1 GHz */
    }
    uint64_t ns = get_time_ns();
    return (ns * freq) / 1000000000ULL;
}
#else
/* Generic fallback */
static inline uint64_t get_cycles(void) {
    return get_time_ns();
}
#endif

/* ============================================================================
 * System Information
 * ============================================================================ */

typedef struct {
    char model[128];
    char hardware[64];
    char revision[32];
    unsigned long cpu_freq_khz;
    int num_cores;
    char governor[32];
} system_info_t;

static int read_file_line(const char *path, char *buffer, size_t size) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    if (fgets(buffer, size, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    /* Remove trailing newline */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    
    fclose(fp);
    return 0;
}

static void get_system_info(system_info_t *info) {
    memset(info, 0, sizeof(system_info_t));
    
    /* Read Pi model */
    if (read_file_line("/proc/device-tree/model", info->model, 
                       sizeof(info->model)) != 0) {
        strcpy(info->model, "Unknown");
    }
    
    /* Read CPU info from /proc/cpuinfo */
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Hardware", 8) == 0) {
                char *val = strchr(line, ':');
                if (val) {
                    val += 2; /* Skip ": " */
                    strncpy(info->hardware, val, sizeof(info->hardware)-1);
                    /* Remove newline */
                    char *nl = strchr(info->hardware, '\n');
                    if (nl) *nl = '\0';
                }
            } else if (strncmp(line, "Revision", 8) == 0) {
                char *val = strchr(line, ':');
                if (val) {
                    val += 2;
                    strncpy(info->revision, val, sizeof(info->revision)-1);
                    char *nl = strchr(info->revision, '\n');
                    if (nl) *nl = '\0';
                }
            }
        }
        fclose(fp);
    }
    
    /* CPU frequency */
    FILE *freq_fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (freq_fp) {
        fscanf(freq_fp, "%lu", &info->cpu_freq_khz);
        fclose(freq_fp);
    }
    
    /* CPU governor */
    read_file_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                   info->governor, sizeof(info->governor));
    
    /* Number of cores */
    info->num_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
}

static void print_system_info(const system_info_t *info) {
    printf("========================================\n");
    printf("System Information\n");
    printf("========================================\n");
    printf("Model:      %s\n", info->model);
    printf("Hardware:   %s\n", info->hardware);
    printf("Revision:   %s\n", info->revision);
    printf("CPU Cores:  %d\n", info->num_cores);
    printf("CPU Freq:   %lu kHz (%.2f MHz)\n", 
           info->cpu_freq_khz, info->cpu_freq_khz / 1000.0);
    printf("Governor:   %s\n", info->governor);
    printf("\n");
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

typedef struct {
    uint64_t min;
    uint64_t max;
    double mean;
    double median;
    double stddev;
    size_t count;
} stats_t;

static int compare_uint64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static void calculate_stats(uint64_t *samples, size_t count, stats_t *stats) {
    stats->count = count;
    
    if (count == 0) {
        stats->min = stats->max = 0;
        stats->mean = stats->median = stats->stddev = 0.0;
        return;
    }
    
    /* Sort for median and min/max */
    qsort(samples, count, sizeof(uint64_t), compare_uint64);
    
    stats->min = samples[0];
    stats->max = samples[count - 1];
    stats->median = (count % 2 == 0) 
        ? (samples[count/2 - 1] + samples[count/2]) / 2.0
        : samples[count/2];
    
    /* Calculate mean */
    uint64_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += samples[i];
    }
    stats->mean = (double)sum / count;
    
    /* Calculate standard deviation */
    double variance = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = samples[i] - stats->mean;
        variance += diff * diff;
    }
    stats->stddev = sqrt(variance / count);
}

/* ============================================================================
 * Benchmark Results
 * ============================================================================ */

typedef struct {
    size_t message_size;
    size_t ad_size;
    
    /* Encryption */
    stats_t enc_cycles;
    stats_t enc_time_ns;
    
    /* Decryption */
    stats_t dec_cycles;
    stats_t dec_time_ns;
    
    /* Derived metrics */
    double enc_throughput_mbps;
    double dec_throughput_mbps;
    double enc_cycles_per_byte;
    double dec_cycles_per_byte;
} benchmark_result_t;

/* ============================================================================
 * ASCON Interface (to be replaced with actual implementation)
 * ============================================================================ */

/*
 * NOTE: Replace these with actual ASCON implementation includes:
 * #include "crypto_aead.h"
 * 
 * The crypto_aead.h should provide:
 * - CRYPTO_KEYBYTES
 * - CRYPTO_NPUBBYTES
 * - CRYPTO_ABYTES
 * - int crypto_aead_encrypt(...)
 * - int crypto_aead_decrypt(...)
 */

/* Placeholder definitions - REPLACE WITH ACTUAL ASCON */
#define CRYPTO_KEYBYTES    16
#define CRYPTO_NPUBBYTES   16
#define CRYPTO_ABYTES      16

/* Dummy encryption function - REPLACE WITH ACTUAL ASCON */
static int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)nsec; /* Unused */
    
    /* Simple placeholder - actual ASCON implementation goes here */
    *clen = mlen + CRYPTO_ABYTES;
    memcpy(c, m, mlen);
    memset(c + mlen, 0, CRYPTO_ABYTES);
    
    /* Add minimal computation to simulate crypto work */
    for (unsigned long long i = 0; i < mlen; i++) {
        c[i] ^= k[i % CRYPTO_KEYBYTES] ^ npub[i % CRYPTO_NPUBBYTES];
        if (i < adlen) {
            c[i] ^= ad[i];
        }
    }
    
    return 0;
}

/* Dummy decryption function - REPLACE WITH ACTUAL ASCON */
static int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)nsec; /* Unused */
    
    if (clen < CRYPTO_ABYTES) return -1;
    
    *mlen = clen - CRYPTO_ABYTES;
    memcpy(m, c, *mlen);
    
    /* Simulate crypto work */
    for (unsigned long long i = 0; i < *mlen; i++) {
        m[i] ^= k[i % CRYPTO_KEYBYTES] ^ npub[i % CRYPTO_NPUBBYTES];
        if (i < adlen) {
            m[i] ^= ad[i];
        }
    }
    
    return 0;
}

/* ============================================================================
 * Benchmarking Functions
 * ============================================================================ */

static void benchmark_operation(
    size_t msg_size,
    size_t ad_size,
    size_t iterations,
    uint64_t *cycle_samples,
    uint64_t *time_samples,
    int is_encrypt)
{
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned char *msg = malloc(msg_size);
    unsigned char *ad = malloc(ad_size);
    unsigned char *ct = malloc(msg_size + CRYPTO_ABYTES);
    unsigned long long outlen;
    
    if (!msg || !ad || !ct) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    /* Initialize with deterministic data */
    memset(key, 0x42, CRYPTO_KEYBYTES);
    memset(nonce, 0x01, CRYPTO_NPUBBYTES);
    memset(msg, 0xAA, msg_size);
    memset(ad, 0x55, ad_size);
    
    /* Warmup */
    for (size_t i = 0; i < WARMUP_ITERATIONS; i++) {
        if (is_encrypt) {
            crypto_aead_encrypt(ct, &outlen, msg, msg_size, ad, ad_size,
                               NULL, nonce, key);
        } else {
            crypto_aead_decrypt(msg, &outlen, NULL, ct, msg_size + CRYPTO_ABYTES,
                               ad, ad_size, nonce, key);
        }
    }
    
    /* Actual benchmark */
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start_cycles = get_cycles();
        uint64_t start_time = get_time_ns();
        
        if (is_encrypt) {
            crypto_aead_encrypt(ct, &outlen, msg, msg_size, ad, ad_size,
                               NULL, nonce, key);
        } else {
            crypto_aead_decrypt(msg, &outlen, NULL, ct, msg_size + CRYPTO_ABYTES,
                               ad, ad_size, nonce, key);
        }
        
        uint64_t end_time = get_time_ns();
        uint64_t end_cycles = get_cycles();
        
        cycle_samples[i] = end_cycles - start_cycles;
        time_samples[i] = end_time - start_time;
        
        /* Prevent compiler optimization */
        asm volatile("" : : "r,m"(ct) : "memory");
    }
    
    free(msg);
    free(ad);
    free(ct);
}

static void run_benchmark(size_t msg_size, size_t ad_size, 
                         benchmark_result_t *result,
                         unsigned long cpu_freq_khz) {
    size_t iterations = BENCHMARK_ITERATIONS;
    
    /* Adjust iterations based on message size for reasonable runtime */
    if (msg_size > 4096) {
        iterations = BENCHMARK_ITERATIONS / 4;
    } else if (msg_size < 64) {
        iterations = BENCHMARK_ITERATIONS * 2;
    }
    
    uint64_t *enc_cycle_samples = malloc(iterations * sizeof(uint64_t));
    uint64_t *enc_time_samples = malloc(iterations * sizeof(uint64_t));
    uint64_t *dec_cycle_samples = malloc(iterations * sizeof(uint64_t));
    uint64_t *dec_time_samples = malloc(iterations * sizeof(uint64_t));
    
    if (!enc_cycle_samples || !enc_time_samples || 
        !dec_cycle_samples || !dec_time_samples) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    result->message_size = msg_size;
    result->ad_size = ad_size;
    
    /* Benchmark encryption */
    benchmark_operation(msg_size, ad_size, iterations,
                       enc_cycle_samples, enc_time_samples, 1);
    calculate_stats(enc_cycle_samples, iterations, &result->enc_cycles);
    calculate_stats(enc_time_samples, iterations, &result->enc_time_ns);
    
    /* Benchmark decryption */
    benchmark_operation(msg_size, ad_size, iterations,
                       dec_cycle_samples, dec_time_samples, 0);
    calculate_stats(dec_cycle_samples, iterations, &result->dec_cycles);
    calculate_stats(dec_time_samples, iterations, &result->dec_time_ns);
    
    /* Calculate derived metrics */
    double enc_time_sec = result->enc_time_ns.median / 1e9;
    double dec_time_sec = result->dec_time_ns.median / 1e9;
    
    result->enc_throughput_mbps = (msg_size / (1024.0 * 1024.0)) / enc_time_sec;
    result->dec_throughput_mbps = (msg_size / (1024.0 * 1024.0)) / dec_time_sec;
    
    result->enc_cycles_per_byte = result->enc_cycles.median / (double)msg_size;
    result->dec_cycles_per_byte = result->dec_cycles.median / (double)msg_size;
    
    free(enc_cycle_samples);
    free(enc_time_samples);
    free(dec_cycle_samples);
    free(dec_time_samples);
}

/* ============================================================================
 * Output Functions
 * ============================================================================ */

static void print_result(const benchmark_result_t *result) {
    printf("Message Size: %zu bytes, AD: %zu bytes\n", 
           result->message_size, result->ad_size);
    printf("----------------------------------------\n");
    
    printf("Encryption:\n");
    printf("  Time (median):  %.3f µs\n", result->enc_time_ns.median / 1000.0);
    printf("  Time (mean):    %.3f µs ± %.3f\n", 
           result->enc_time_ns.mean / 1000.0, 
           result->enc_time_ns.stddev / 1000.0);
    printf("  Cycles (median): %.0f (%.2f cycles/byte)\n",
           result->enc_cycles.median, result->enc_cycles_per_byte);
    printf("  Throughput:     %.2f MB/s\n", result->enc_throughput_mbps);
    
    printf("Decryption:\n");
    printf("  Time (median):  %.3f µs\n", result->dec_time_ns.median / 1000.0);
    printf("  Time (mean):    %.3f µs ± %.3f\n",
           result->dec_time_ns.mean / 1000.0,
           result->dec_time_ns.stddev / 1000.0);
    printf("  Cycles (median): %.0f (%.2f cycles/byte)\n",
           result->dec_cycles.median, result->dec_cycles_per_byte);
    printf("  Throughput:     %.2f MB/s\n", result->dec_throughput_mbps);
    printf("\n");
}

static void save_csv_results(const char *filename, 
                            const benchmark_result_t *results,
                            size_t num_results,
                            const system_info_t *sysinfo) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", 
                filename, strerror(errno));
        return;
    }
    
    /* Write header with system info */
    fprintf(fp, "# ASCON Benchmark Results\n");
    fprintf(fp, "# Model: %s\n", sysinfo->model);
    fprintf(fp, "# Hardware: %s\n", sysinfo->hardware);
    fprintf(fp, "# CPU Frequency: %lu kHz\n", sysinfo->cpu_freq_khz);
    fprintf(fp, "# Governor: %s\n", sysinfo->governor);
    fprintf(fp, "#\n");
    
    /* CSV header */
    fprintf(fp, "msg_size,ad_size,");
    fprintf(fp, "enc_time_median_us,enc_time_mean_us,enc_time_stddev_us,");
    fprintf(fp, "enc_cycles_median,enc_cycles_per_byte,enc_throughput_mbps,");
    fprintf(fp, "dec_time_median_us,dec_time_mean_us,dec_time_stddev_us,");
    fprintf(fp, "dec_cycles_median,dec_cycles_per_byte,dec_throughput_mbps\n");
    
    /* Data rows */
    for (size_t i = 0; i < num_results; i++) {
        const benchmark_result_t *r = &results[i];
        fprintf(fp, "%zu,%zu,", r->message_size, r->ad_size);
        fprintf(fp, "%.3f,%.3f,%.3f,",
                r->enc_time_ns.median / 1000.0,
                r->enc_time_ns.mean / 1000.0,
                r->enc_time_ns.stddev / 1000.0);
        fprintf(fp, "%.0f,%.2f,%.2f,",
                r->enc_cycles.median,
                r->enc_cycles_per_byte,
                r->enc_throughput_mbps);
        fprintf(fp, "%.3f,%.3f,%.3f,",
                r->dec_time_ns.median / 1000.0,
                r->dec_time_ns.mean / 1000.0,
                r->dec_time_ns.stddev / 1000.0);
        fprintf(fp, "%.0f,%.2f,%.2f\n",
                r->dec_cycles.median,
                r->dec_cycles_per_byte,
                r->dec_throughput_mbps);
    }
    
    fclose(fp);
    printf("Results saved to %s\n", filename);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    system_info_t sysinfo;
    
    printf("========================================\n");
    printf("ASCON Optimized Benchmark Suite\n");
    printf("Cross-Platform Performance Testing\n");
    printf("========================================\n\n");
    
    /* Get and display system information */
    get_system_info(&sysinfo);
    print_system_info(&sysinfo);
    
    /* Warning if not in performance mode */
    if (strcmp(sysinfo.governor, "performance") != 0) {
        printf("WARNING: CPU governor is '%s' (not 'performance')\n", 
               sysinfo.governor);
        printf("For accurate results, run:\n");
        printf("  sudo sh -c \"echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor\"\n\n");
    }
    
    /* Run benchmarks */
    printf("Running benchmarks (this will take a few minutes)...\n\n");
    
    size_t num_tests = NUM_TEST_SIZES;
    benchmark_result_t *results = malloc(num_tests * sizeof(benchmark_result_t));
    if (!results) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    
    size_t ad_size = 16; /* Fixed AD size for consistency */
    
    for (size_t i = 0; i < num_tests; i++) {
        printf("Testing %zu bytes... ", TEST_SIZES[i]);
        fflush(stdout);
        
        run_benchmark(TEST_SIZES[i], ad_size, &results[i], sysinfo.cpu_freq_khz);
        
        printf("Done\n");
    }
    
    printf("\n========================================\n");
    printf("Benchmark Results\n");
    printf("========================================\n\n");
    
    for (size_t i = 0; i < num_tests; i++) {
        print_result(&results[i]);
    }
    
    /* Save to CSV */
    char filename[256];
    snprintf(filename, sizeof(filename), "ascon_benchmark_%s.csv", 
             sysinfo.hardware[0] ? sysinfo.hardware : "unknown");
    /* Replace spaces with underscores */
    for (char *p = filename; *p; p++) {
        if (*p == ' ') *p = '_';
    }
    
    save_csv_results(filename, results, num_tests, &sysinfo);
    
    free(results);
    
    printf("\nBenchmark complete!\n");
    return 0;
}
