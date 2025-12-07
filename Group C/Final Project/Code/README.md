# ASCON Cross-Platform Benchmark Suite

**Universal setup with automatic platform detection**

---

## Quick Start

```bash
# Download and run universal setup
bash setup_universal.sh
```

The script will:
- Detect your platform automatically
- Install dependencies
- Clone ASCON repository (if not present)
- Create platform-specific configuration
- Set up build scripts
- Organize everything cleanly

---

## Directory Structure

```
~/4301-workspace/final/
├── Code/
│   ├── Common/                      # Shared across all platforms
│   │   ├── optimized_benchmark.c    # Universal benchmark code
│   │   ├── analyze_results.py       # Analysis tool
│   │   └── README.md
│   │
│   ├── RP-Zero-W/                   # Raspberry Pi Zero W specific
│   │   ├── config.sh                # Platform configuration
│   │   ├── build.sh                 # Build script
│   │   ├── optimized_benchmark.c    # Symlink to Common/
│   │   ├── analyze_results.py       # Symlink to Common/
│   │   ├── benchmark_bi32_armv6     # Built executable
│   │   └── results/                 # Results directory
│   │
│   ├── VisionFive-2/                # VisionFive 2 specific
│   │   ├── config.sh
│   │   ├── build.sh
│   │   ├── benchmark_opt64
│   │   └── results/
│   │
│   ├── Pi-5/                        # Raspberry Pi 5 specific
│   │   ├── config.sh
│   │   ├── build.sh
│   │   ├── benchmark_opt64
│   │   └── results/
│   │
│   └── Scripts/                     # Universal utilities
│       └── compare_all.py           # Cross-platform comparison
│
├── ascon-c/                         # Shared ASCON repository
│   └── crypto_aead/...              # (Clone this separately or setup does it)
│
└── Documentation/
    └── README.md
```

---

## Supported Platforms

Automatic detection for:

| Platform | Directory | Best Implementation |
|----------|-----------|---------------------|
| Raspberry Pi Zero W | RP-Zero-W/ | bi32_armv6 |
| Raspberry Pi 5 | Pi-5/ | opt64 |
| Raspberry Pi 4 | Pi-4/ | opt64 |
| Raspberry Pi 3 | Pi-3/ | opt32 / neon |
| VisionFive 2 | VisionFive-2/ | opt64 |
| Generic ARM64 | ARM64-Generic/ | opt64 |
| Generic RISC-V | RISC-V-Generic/ | opt64 |

---

## Usage on Each Device

```bash
# 1. Run universal setup (first time only)
cd ~/4301-workspace/final
bash setup_universal.sh

# 2. Navigate to your platform directory
cd Code/[Your-Platform]/

# 3. Build
./build.sh

# 4. Run
./benchmark_[best-impl]

# 5. Results saved to results/
```

---

## Example Workflows

### Single Platform Testing

```bash
# On Raspberry Pi Zero W
cd ~/4301-workspace/final/Code/RP-Zero-W/
./build.sh
./benchmark_bi32_armv6

# Results: results/ascon_benchmark_*.csv
```

### Multi-Platform Comparison

```bash
# On Pi Zero W
cd ~/4301-workspace/final/Code/RP-Zero-W/
./build.sh && ./benchmark_bi32_armv6
cp results/*.csv ~/pi_zero_results.csv

# On VisionFive 2
cd ~/4301-workspace/final/Code/VisionFive-2/
./build.sh && ./benchmark_opt64
cp results/*.csv ~/vf2_results.csv

# On Pi 5
cd ~/4301-workspace/final/Code/Pi-5/
./build.sh && ./benchmark_opt64
cp results/*.csv ~/pi5_results.csv

# Compare (on any device with Python)
cd ~/4301-workspace/final/Code/Common/
python3 analyze_results.py ~/pi_zero_results.csv ~/vf2_results.csv ~/pi5_results.csv
```

### Test All Implementations on One Platform

```bash
cd ~/4301-workspace/final/Code/RP-Zero-W/
./build.sh  # Builds all available implementations

# Run each one
./benchmark_bi32_armv6
mv results/*.csv results/results_bi32_armv6.csv

./benchmark_ref
mv results/*.csv results/results_ref.csv

./benchmark_opt32
mv results/*.csv results/results_opt32.csv

# Compare
python3 analyze_results.py results/*.csv
```

---

## Platform Configuration

Each platform has a `config.sh` file:

```bash
# Platform identification
PLATFORM_NAME="rp-zero-w"
ARCHITECTURE="armv6l"

# ASCON repository path
ASCON_BASE="/home/user/4301-workspace/final/ascon-c/crypto_aead/asconaead128"

# Compiler flags (platform-optimized)
CFLAGS="-O3 -march=armv6 -mfpu=vfp -mfloat-abi=hard -flto"

# Best implementation
BEST_IMPL="bi32_armv6"

# All implementations to build
IMPLEMENTATIONS=("bi32_armv6" "ref" "opt32" "armv6")
```

To customize:
```bash
cd ~/4301-workspace/final/Code/[Your-Platform]/
nano config.sh
./build.sh  # Rebuild with new settings
```

---

## Cross-Platform Analysis

### Collect Results from All Platforms

```bash
# On your main computer or any device

# From Pi Zero W
scp pi-zero-w:~/4301-workspace/final/Code/RP-Zero-W/results/*.csv ./pi_zero.csv

# From VisionFive 2
scp visionfive2:~/4301-workspace/final/Code/VisionFive-2/results/*.csv ./vf2.csv

# From Pi 5
scp pi5:~/4301-workspace/final/Code/Pi-5/results/*.csv ./pi5.csv

# Analyze together
python3 analyze_results.py pi_zero.csv vf2.csv pi5.csv
```

---

## Key Features

### Automatic Platform Detection
- Detects Raspberry Pi models
- Detects RISC-V boards (VisionFive 2)
- Falls back to architecture-based detection
- Manual override available

### Platform-Specific Optimizations
- ARMv6 flags for Pi Zero W
- ARMv8.2 flags for Pi 5
- RISC-V flags for VisionFive 2
- Correct implementations selected automatically

### Clean Organization
- Code and Scripts under Code/
- No file duplication (symlinks)
- Platform directories are independent
- ASCON repository separate (public repo)

### Universal Tools
- Same analyze_results.py works everywhere
- Same benchmark code across platforms
- Consistent CSV output format

---

## Adding a New Platform

```bash
# Run setup on new device
bash setup_universal_v2.sh

# If not detected automatically, choose from menu
# Then customize if needed:
cd ~/4301-workspace/final/Code/[New-Platform]/
nano config.sh  # Edit CFLAGS, BEST_IMPL, IMPLEMENTATIONS

# Build and test
./build.sh
./benchmark_[best-impl]
```

---

## Files Explained

### setup_universal.sh
- Detects platform automatically
- Creates directory structure (Code/Common, Code/Scripts, Code/[Platform])
- Generates platform-specific config.sh and build.sh
- Clones ASCON to base directory
- Installs dependencies

### Code/Common/
- optimized_benchmark.c - Universal benchmark (same on all platforms)
- analyze_results.py - Universal analysis tool

### Code/Scripts/
- Universal utilities
- Cross-platform comparison tools
- Helper scripts

### Code/[Platform]/
- config.sh - Platform-specific settings
- build.sh - Build script (loads config.sh)
- results/ - Where benchmark results are saved
- Symlinks to Common/ files

### ascon-c/
- Public ASCON repository
- Cloned to base directory
- Shared by all platforms

---

## Migration from Old Structure

If you have existing files:

```bash
# Old structure
~/ascon-workspace/optimized-benchmarks/

# Run new setup
cd ~/4301-workspace/final
bash setup_universal_v2.sh

# It will organize files into new structure automatically
```

---

## Research Benefits

This structure is ideal for academic work:

1. **Clear separation** - Code/Common vs Code/[Platform]
2. **Reproducible** - Same code, different optimizations
3. **Organized results** - Each platform's data separate
4. **Professional** - Publication-ready organization
5. **Portable** - Easy to share (just Code/ and Documentation/)

---

## Best Practices

### Performance
1. Set CPU to performance mode (setup prompts for this)
2. Run multiple times for consistency
3. Check temperature during runs
4. Minimize system load

### Organization
1. Use setup_universal_v2.sh on each device
2. Keep Code/Common/ synchronized
3. Name results descriptively
4. Document test conditions

### Results Naming
```bash
# Descriptive names help later
mv results/ascon_benchmark_*.csv \
   results/pi_zero_w_bi32_armv6_$(date +%Y%m%d).csv
```

---

## Troubleshooting

### "Platform not detected"
Run setup and choose manually from the menu.

### "Build fails"
Check that config.sh has correct paths and flags.

### "Can't find ASCON"
Ensure ascon-c is in: ~/4301-workspace/final/ascon-c

### "Results in wrong directory"
Results always save to [Platform-Dir]/results/

---

## Quick Reference

```bash
# Setup (first time, each device)
bash setup_universal_v2.sh

# Build (in platform directory)
./build.sh

# Run (in platform directory)
./benchmark_[best-impl]

# Analyze
python3 analyze_results.py results/*.csv

# View config
cat config.sh

# List executables
ls -lh benchmark_*
```

---

## Complete Example Session

```bash
# On Pi Zero W
cd ~/4301-workspace/final
bash setup_universal_v2.sh
cd Code/RP-Zero-W
./build.sh
./benchmark_bi32_armv6

# On VisionFive 2
cd ~/4301-workspace/final
bash setup_universal_v2.sh
cd Code/VisionFive-2
./build.sh
./benchmark_opt64

# On Pi 5
cd ~/4301-workspace/final
bash setup_universal_v2.sh
cd Code/Pi-5
./build.sh
./benchmark_opt64

# Compare all (on any device)
python3 analyze_results.py \
    pi_zero_results.csv \
    vf2_results.csv \
    pi5_results.csv
```

---

## Summary

**One script. Clean structure. All platforms.**

- Code and scripts organized under Code/
- ASCON repository separate (public)
- Platform-specific directories auto-generated
- Universal tools in Common/
- Cross-platform comparison ready

Ready to start? Run:
```bash
bash setup_universal_v2.sh
```
