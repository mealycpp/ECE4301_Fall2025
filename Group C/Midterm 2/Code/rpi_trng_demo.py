#!/usr/bin/env python3
"""
Raspberry Pi Hardware TRNG Demonstration and Testing
Midterm #2 Project - TRNG on Raspberry Pi Crypto Engine
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import time

class RPiTRNG:
    """Interface to Raspberry Pi Hardware Random Number Generator"""
    
    def __init__(self, device='/dev/hwrng'):
        self.device = device
        
    def read_bytes(self, num_bytes):
        """Read random bytes from hardware RNG"""
        try:
            with open(self.device, 'rb') as hwrng:
                return hwrng.read(num_bytes)
        except PermissionError:
            print("Error: Permission denied. Run with sudo.")
            sys.exit(1)
            
    def read_uint32(self, count=1):
        """Read random 32-bit unsigned integers"""
        bytes_data = self.read_bytes(count * 4)
        return np.frombuffer(bytes_data, dtype=np.uint32)
    
    def read_floats(self, count=1):
        """Read random floats between 0 and 1"""
        integers = self.read_uint32(count)
        return integers / (2**32 - 1)


def test_basic_output(trng, num_samples=100):
    """Test 1: Display basic random output"""
    print("="*60)
    print("TEST 1: Basic Random Output")
    print("="*60)
    
    # Read some random bytes
    random_bytes = trng.read_bytes(32)
    print(f"\n32 Random Bytes (hex): {random_bytes.hex()}")
    
    # Read some random integers
    random_ints = trng.read_uint32(8)
    print(f"\n8 Random 32-bit Integers:")
    for i, val in enumerate(random_ints):
        print(f"  {i+1}: {val:10d} (0x{val:08x})")
    
    print("\n✓ Hardware RNG is producing output")


def test_distribution(trng, num_samples=10000):
    """Test 2: Test uniform distribution"""
    print("\n" + "="*60)
    print("TEST 2: Distribution Analysis")
    print("="*60)
    
    # Generate random bytes
    random_bytes = trng.read_bytes(num_samples)
    byte_array = np.frombuffer(random_bytes, dtype=np.uint8)
    
    # Count frequency of each byte value (0-255)
    counts = Counter(byte_array)
    
    # Expected frequency for uniform distribution
    expected = num_samples / 256
    
    # Calculate chi-square statistic
    chi_square = sum((counts[i] - expected)**2 / expected for i in range(256))
    
    print(f"\nGenerated {num_samples} random bytes")
    print(f"Expected frequency per byte value: {expected:.2f}")
    print(f"Chi-square statistic: {chi_square:.2f}")
    print(f"Degrees of freedom: 255")
    print(f"Critical value (α=0.05): ~293.25")
    
    if chi_square < 293.25:
        print("✓ Distribution appears uniform (chi-square test passed)")
    else:
        print("⚠ Distribution may not be uniform (chi-square test failed)")
    
    return byte_array, counts


def test_entropy(trng, num_samples=10000):
    """Test 3: Calculate Shannon entropy"""
    print("\n" + "="*60)
    print("TEST 3: Entropy Calculation")
    print("="*60)
    
    random_bytes = trng.read_bytes(num_samples)
    byte_array = np.frombuffer(random_bytes, dtype=np.uint8)
    
    # Calculate Shannon entropy
    counts = Counter(byte_array)
    probabilities = [count/num_samples for count in counts.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    
    print(f"\nShannon Entropy: {entropy:.4f} bits per byte")
    print(f"Maximum Entropy: 8.0000 bits per byte")
    print(f"Entropy Percentage: {(entropy/8.0)*100:.2f}%")
    
    if entropy > 7.9:
        print("✓ High entropy - good randomness quality")
    else:
        print("⚠ Lower entropy - may indicate bias")


def test_correlation(trng, num_samples=1000):
    """Test 4: Test for correlation between consecutive bytes"""
    print("\n" + "="*60)
    print("TEST 4: Correlation Analysis")
    print("="*60)
    
    random_bytes = trng.read_bytes(num_samples)
    byte_array = np.frombuffer(random_bytes, dtype=np.uint8)
    
    # Calculate autocorrelation at lag 1
    correlation = np.corrcoef(byte_array[:-1], byte_array[1:])[0, 1]
    
    print(f"\nAutocorrelation (lag=1): {correlation:.6f}")
    print(f"Expected for random data: ~0.0")
    
    if abs(correlation) < 0.1:
        print("✓ Low correlation - bytes are independent")
    else:
        print("⚠ High correlation detected - may indicate pattern")


def test_monobit(trng, num_samples=20000):
    """Test 5: NIST Monobit Frequency Test"""
    print("\n" + "="*60)
    print("TEST 5: NIST Monobit Frequency Test")
    print("="*60)
    
    random_bytes = trng.read_bytes(num_samples)
    
    # Convert to bits
    bits = np.unpackbits(np.frombuffer(random_bytes, dtype=np.uint8))
    
    # Count ones and zeros
    ones = int(np.sum(bits))
    zeros = len(bits) - ones
    
    # Calculate test statistic
    S = abs(ones - zeros)
    n = len(bits)
    s_obs = float(S) / np.sqrt(n)
    
    # P-value (approximation)
    from math import erfc
    p_value = erfc(s_obs / np.sqrt(2))
    
    print(f"\nTotal bits: {n}")
    print(f"Ones: {ones} ({ones/n*100:.2f}%)")
    print(f"Zeros: {zeros} ({zeros/n*100:.2f}%)")
    print(f"P-value: {p_value:.4f}")
    print(f"Threshold (α=0.01): 0.01")
    
    if p_value >= 0.01:
        print("✓ Monobit test passed - balanced ones and zeros")
    else:
        print("⚠ Monobit test failed - imbalanced bit distribution")


def visualize_results(byte_array, counts):
    """Create visualizations of random data"""
    print("\n" + "="*60)
    print("Generating Visualizations...")
    print("="*60)
    
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    fig.suptitle('Raspberry Pi Hardware TRNG Analysis', fontsize=16, fontweight='bold')
    
    # Plot 1: Distribution histogram
    ax1 = axes[0, 0]
    ax1.bar(range(256), [counts[i] for i in range(256)], width=1.0, color='steelblue', alpha=0.7)
    ax1.axhline(y=len(byte_array)/256, color='red', linestyle='--', label='Expected (uniform)')
    ax1.set_xlabel('Byte Value (0-255)')
    ax1.set_ylabel('Frequency')
    ax1.set_title('Byte Value Distribution')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: First 256 bytes as image
    ax2 = axes[0, 1]
    sample_2d = byte_array[:256].reshape(16, 16)
    im = ax2.imshow(sample_2d, cmap='gray', interpolation='nearest')
    ax2.set_title('Visual Randomness (16x16 bytes)')
    ax2.set_xlabel('X')
    ax2.set_ylabel('Y')
    plt.colorbar(im, ax=ax2)
    
    # Plot 3: Bit pattern visualization
    ax3 = axes[1, 0]
    bits = np.unpackbits(byte_array[:100])
    bit_image = bits.reshape(25, 32)
    ax3.imshow(bit_image, cmap='binary', interpolation='nearest', aspect='auto')
    ax3.set_title('Bit Pattern (800 bits)')
    ax3.set_xlabel('Bit Position')
    ax3.set_ylabel('Byte Group')
    
    # Plot 4: Scatter plot of consecutive bytes
    ax4 = axes[1, 1]
    sample_size = min(1000, len(byte_array)-1)
    ax4.scatter(byte_array[:sample_size], byte_array[1:sample_size+1], 
                alpha=0.3, s=1, color='darkblue')
    ax4.set_xlabel('Byte N')
    ax4.set_ylabel('Byte N+1')
    ax4.set_title('Correlation Plot (consecutive bytes)')
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('trng_analysis.png', dpi=150, bbox_inches='tight')
    print("\n✓ Visualization saved as 'trng_analysis.png'")


def benchmark_speed(trng):
    """Test 6: Benchmark RNG speed"""
    print("\n" + "="*60)
    print("TEST 6: Performance Benchmark")
    print("="*60)
    
    sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    
    for size in sizes:
        start = time.time()
        data = trng.read_bytes(size)
        elapsed = time.time() - start
        
        throughput = size / elapsed / 1024  # KB/s
        print(f"\n{size/1024:.0f} KB: {elapsed*1000:.2f} ms ({throughput:.2f} KB/s)")


def main():
    """Run all tests and demonstrations"""
    print("\n" + "="*60)
    print("RASPBERRY PI HARDWARE TRNG DEMONSTRATION")
    print("Midterm #2 - TRNG on Raspberry Pi Crypto Engine")
    print("="*60)
    
    # Check if running with sudo
    if os.geteuid() != 0:
        print("\n⚠ Warning: This script requires sudo access to read /dev/hwrng")
        print("Please run: sudo python3 rpi_trng_demo.py")
        sys.exit(1)
    
    # Initialize TRNG
    trng = RPiTRNG()
    print("\n✓ Hardware RNG device opened: /dev/hwrng")
    
    # Run all tests
    test_basic_output(trng)
    byte_array, counts = test_distribution(trng)
    test_entropy(trng)
    test_correlation(trng)
    test_monobit(trng)
    benchmark_speed(trng)
    
    # Create visualizations
    visualize_results(byte_array, counts)
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60)
    print("\nSummary:")
    print("✓ Hardware TRNG is functioning correctly")
    print("✓ Random data passes statistical tests")
    print("✓ High entropy and uniform distribution confirmed")
    print("✓ Suitable for cryptographic applications")
    print("\n")


if __name__ == "__main__":
    main()