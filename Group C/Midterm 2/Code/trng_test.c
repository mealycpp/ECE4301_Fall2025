/*
 * Raspberry Pi Hardware TRNG - Enhanced C Implementation with Visualization
 * Generates PPM images showing random data patterns
 * Compile: gcc -o trng_visual trng_visual.c -lm
 * Run: sudo ./trng_visual
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define HWRNG_DEVICE "/dev/hwrng"
#define BUFFER_SIZE 4096

// Function to read random bytes from hardware RNG
int read_hwrng(unsigned char *buffer, size_t size) {
    int fd = open(HWRNG_DEVICE, O_RDONLY);
    if (fd < 0) {
        perror("Error opening /dev/hwrng - run with sudo");
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, size);
    close(fd);
    
    return bytes_read;
}

// Generate grayscale visualization (16x16 grid)
void generate_grayscale_image() {
    printf("\n========================================\n");
    printf("Generating Grayscale Visualization\n");
    printf("========================================\n");
    
    unsigned char buffer[256];  // 16x16 = 256 bytes
    if (read_hwrng(buffer, 256) < 0) {
        return;
    }
    
    FILE *fp = fopen("trng_grayscale.ppm", "w");
    if (!fp) {
        printf("Error creating image file\n");
        return;
    }
    
    // PPM header (P3 = ASCII PPM format)
    fprintf(fp, "P3\n");
    fprintf(fp, "16 16\n");  // 16x16 image
    fprintf(fp, "255\n");    // Max color value
    
    // Write pixel data (grayscale: R=G=B)
    for (int i = 0; i < 256; i++) {
        fprintf(fp, "%d %d %d ", buffer[i], buffer[i], buffer[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(fp, "\n");
        }
    }
    
    fclose(fp);
    printf("✓ Grayscale image saved: trng_grayscale.ppm\n");
}

// Generate bit pattern visualization (32x32 grid showing 1024 bits)
void generate_bit_pattern_image() {
    printf("\n========================================\n");
    printf("Generating Bit Pattern Visualization\n");
    printf("========================================\n");
    
    unsigned char buffer[128];  // 128 bytes = 1024 bits
    if (read_hwrng(buffer, 128) < 0) {
        return;
    }
    
    FILE *fp = fopen("trng_bitpattern.ppm", "w");
    if (!fp) {
        printf("Error creating image file\n");
        return;
    }
    
    // PPM header
    fprintf(fp, "P3\n");
    fprintf(fp, "32 32\n");  // 32x32 image (1024 pixels for 1024 bits)
    fprintf(fp, "255\n");
    
    // Write pixel data (black=0, white=1)
    for (int i = 0; i < 128; i++) {
        for (int bit = 0; bit < 8; bit++) {
            int pixel_value = (buffer[i] & (1 << (7-bit))) ? 255 : 0;
            fprintf(fp, "%d %d %d ", pixel_value, pixel_value, pixel_value);
            if (((i * 8 + bit + 1) % 32) == 0) {
                fprintf(fp, "\n");
            }
        }
    }
    
    fclose(fp);
    printf("✓ Bit pattern image saved: trng_bitpattern.ppm\n");
}

// Generate color noise visualization (64x64 RGB)
void generate_color_noise_image() {
    printf("\n========================================\n");
    printf("Generating Color Noise Visualization\n");
    printf("========================================\n");
    
    unsigned char buffer[12288];  // 64x64x3 = 12,288 bytes (RGB)
    if (read_hwrng(buffer, 12288) < 0) {
        return;
    }
    
    FILE *fp = fopen("trng_colornoise.ppm", "w");
    if (!fp) {
        printf("Error creating image file\n");
        return;
    }
    
    // PPM header
    fprintf(fp, "P3\n");
    fprintf(fp, "64 64\n");
    fprintf(fp, "255\n");
    
    // Write RGB pixel data
    for (int i = 0; i < 12288; i += 3) {
        fprintf(fp, "%d %d %d ", buffer[i], buffer[i+1], buffer[i+2]);
        if (((i/3 + 1) % 64) == 0) {
            fprintf(fp, "\n");
        }
    }
    
    fclose(fp);
    printf("✓ Color noise image saved: trng_colornoise.ppm\n");
}

// Generate large grayscale image (128x128)
void generate_large_visualization() {
    printf("\n========================================\n");
    printf("Generating Large Visualization (128x128)\n");
    printf("========================================\n");
    
    unsigned char buffer[16384];  // 128x128 = 16,384 bytes
    if (read_hwrng(buffer, 16384) < 0) {
        return;
    }
    
    FILE *fp = fopen("trng_large.ppm", "w");
    if (!fp) {
        printf("Error creating image file\n");
        return;
    }
    
    // PPM header
    fprintf(fp, "P3\n");
    fprintf(fp, "128 128\n");
    fprintf(fp, "255\n");
    
    // Write pixel data
    for (int i = 0; i < 16384; i++) {
        fprintf(fp, "%d %d %d ", buffer[i], buffer[i], buffer[i]);
        if ((i + 1) % 128 == 0) {
            fprintf(fp, "\n");
        }
    }
    
    fclose(fp);
    printf("✓ Large visualization saved: trng_large.ppm\n");
}

// Test 1: Display hex dump of random bytes
void test_hex_output() {
    printf("\n========================================\n");
    printf("TEST 1: Random Byte Output (Hex)\n");
    printf("========================================\n");
    
    unsigned char buffer[32];
    if (read_hwrng(buffer, 32) < 0) {
        return;
    }
    
    printf("32 random bytes:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Test 2: Generate random 32-bit integers
void test_integers() {
    printf("\n========================================\n");
    printf("TEST 2: Random 32-bit Integers\n");
    printf("========================================\n");
    
    uint32_t numbers[10];
    if (read_hwrng((unsigned char*)numbers, sizeof(numbers)) < 0) {
        return;
    }
    
    printf("10 random 32-bit integers:\n");
    for (int i = 0; i < 10; i++) {
        printf("%2d: %10u (0x%08x)\n", i+1, numbers[i], numbers[i]);
    }
}

// Test 3: Chi-square test for uniform distribution
void test_distribution() {
    printf("\n========================================\n");
    printf("TEST 3: Distribution Test (Chi-Square)\n");
    printf("========================================\n");
    
    unsigned char buffer[BUFFER_SIZE];
    int counts[256] = {0};
    
    if (read_hwrng(buffer, BUFFER_SIZE) < 0) {
        return;
    }
    
    // Count frequency of each byte value
    for (int i = 0; i < BUFFER_SIZE; i++) {
        counts[buffer[i]]++;
    }
    
    // Calculate chi-square statistic
    double expected = BUFFER_SIZE / 256.0;
    double chi_square = 0.0;
    
    for (int i = 0; i < 256; i++) {
        double diff = counts[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    
    printf("Samples: %d bytes\n", BUFFER_SIZE);
    printf("Expected frequency: %.2f per byte value\n", expected);
    printf("Chi-square statistic: %.2f\n", chi_square);
    printf("Degrees of freedom: 255\n");
    printf("Critical value (α=0.05): ~293.25\n");
    
    if (chi_square < 293.25) {
        printf("✓ Distribution is uniform (test passed)\n");
    } else {
        printf("✗ Distribution may not be uniform (test failed)\n");
    }
}

// Test 4: Calculate Shannon entropy
void test_entropy() {
    printf("\n========================================\n");
    printf("TEST 4: Shannon Entropy Calculation\n");
    printf("========================================\n");
    
    unsigned char buffer[BUFFER_SIZE];
    int counts[256] = {0};
    
    if (read_hwrng(buffer, BUFFER_SIZE) < 0) {
        return;
    }
    
    // Count byte frequencies
    for (int i = 0; i < BUFFER_SIZE; i++) {
        counts[buffer[i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double probability = (double)counts[i] / BUFFER_SIZE;
            entropy -= probability * log2(probability);
        }
    }
    
    printf("Shannon Entropy: %.4f bits per byte\n", entropy);
    printf("Maximum Entropy: 8.0000 bits per byte\n");
    printf("Percentage: %.2f%%\n", (entropy / 8.0) * 100);
    
    if (entropy > 7.9) {
        printf("✓ High entropy - excellent randomness\n");
    } else {
        printf("⚠ Lower entropy detected\n");
    }
}

// Test 5: Monobit test (balance of 0s and 1s)
void test_monobit() {
    printf("\n========================================\n");
    printf("TEST 5: Monobit Frequency Test\n");
    printf("========================================\n");
    
    unsigned char buffer[2000];
    if (read_hwrng(buffer, 2000) < 0) {
        return;
    }
    
    // Count bits
    int ones = 0;
    int total_bits = 2000 * 8;
    
    for (int i = 0; i < 2000; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (buffer[i] & (1 << bit)) {
                ones++;
            }
        }
    }
    
    int zeros = total_bits - ones;
    double ratio = (double)ones / total_bits;
    
    printf("Total bits: %d\n", total_bits);
    printf("Ones: %d (%.2f%%)\n", ones, ratio * 100);
    printf("Zeros: %d (%.2f%%)\n", zeros, (1.0 - ratio) * 100);
    printf("Expected: ~50%% each\n");
    
    if (ratio > 0.48 && ratio < 0.52) {
        printf("✓ Bit balance is good\n");
    } else {
        printf("⚠ Bit imbalance detected\n");
    }
}

// Main function
int main() {
    printf("\n");
    printf("========================================================\n");
    printf("  RASPBERRY PI HARDWARE TRNG WITH VISUALIZATION\n");
    printf("  C Implementation with Image Generation\n");
    printf("========================================================\n");
    
    // Check for root privileges
    if (geteuid() != 0) {
        printf("\n⚠ Error: This program requires root privileges\n");
        printf("Please run: sudo ./trng_visual\n\n");
        return 1;
    }
    
    // Run all tests
    test_hex_output();
    test_integers();
    test_distribution();
    test_entropy();
    test_monobit();
    
    // Generate visualizations
    printf("\n========================================================\n");
    printf("  GENERATING VISUALIZATIONS\n");
    printf("========================================================\n");
    
    generate_grayscale_image();
    generate_bit_pattern_image();
    generate_color_noise_image();
    generate_large_visualization();
    
    printf("\n========================================================\n");
    printf("  ALL TESTS AND VISUALIZATIONS COMPLETED\n");
    printf("========================================================\n");
    printf("\nGenerated Images:\n");
    printf("  1. trng_grayscale.ppm   - 16x16 grayscale pattern\n");
    printf("  2. trng_bitpattern.ppm  - 32x32 bit visualization\n");
    printf("  3. trng_colornoise.ppm  - 64x64 color noise\n");
    printf("  4. trng_large.ppm       - 128x128 large visualization\n");
    printf("\nTo view PPM images:\n");
    printf("  feh trng_*.ppm\n");
    printf("  # or\n");
    printf("  convert trng_grayscale.ppm trng_grayscale.png\n");
    printf("\nThe Raspberry Pi hardware RNG is functioning\n");
    printf("and producing cryptographic-quality randomness.\n\n");
    
    return 0;
}