# Raspberry Pi TRNG Demo (Rust)

This project implements and demonstrates a **True Random Number Generator (TRNG)** using the Raspberry Pi 5 hardware crypto engine. The SoC exposes a hardware entropy source through Linux at:

```
/dev/hwrng
```

The provided Rust program reads raw hardware-generated random bytes, performs basic statistical tests, generates a byte-frequency histogram, and optionally produces plots for visualization.

---

## Features

- Read true random bytes from Raspberry Pi hardware TRNG 
- Hex dump preview of sampled random data 
- Bit-frequency test (checks 0/1 balance) 
- Runs test (detects streaks of identical bits) 
- Byte histogram (0 - 255 distribution) 
- CSV export (`histogram.csv`) 
- Optional plotting with Python/Matplotlib 

---

## Hardware & Software Requirements

### Hardware
- Raspberry Pi 5
### Software
- Install Rust and Python support packages:
```bash
sudo apt update
sudo apt install rustc cargo
sudo apt install python3-matplotlib python3-pandas
```

### Build the Package
- Build the pi-trng-test package
```bash
cd pi-trng-test
cargo build --release
```

### Running the TRNG Reader
- The hardware TRNG requires root access:
```bash
sudo ./target/release/pi_trng_test
```
When running, the program will:
1. Read **100,000 bytes** from `/dev/hwrng`
2. Display a hex dump preview
3. Run statistical tests:
    - Bit frequency (0 vs. 1)
    - Runs test
4. Generate a byte histogram
5. Write `histogram.csv`

### Plotting the histogram
- Use the included Python script:
```bash
python3 plot_hist.py
```

This generates a bar plot showing the relative frequency of each byte in the TRNG output.
A properly functioning TRNG should produce:
- Uniform distribution across 0 - 255
- Natural fluctuations around the ideal count
	$≈100000256≈390\approx \frac{100000}{256} \approx 390≈256100000​≈390$
- No missing byte values
- No obvious clustering or bias

## Interpreting Results
A healthy TRNG output should show:
### Bit Frequency
Approximately equal numbers of zeros and ones.
### Runs Test
No extremely long runs and a large number of alternating bit runs.
