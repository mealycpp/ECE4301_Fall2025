#!/bin/bash
################################################################################
# ASCON Universal Setup Script
# Automatically detects platform and sets up appropriate configuration
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() { echo -e "\n${BLUE}========================================${NC}\n${BLUE}$1${NC}\n${BLUE}========================================${NC}\n"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${CYAN}ℹ${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }

print_header "ASCON Benchmark Universal Setup"

################################################################################
# Platform Detection
################################################################################

detect_platform() {
    local arch=$(uname -m)
    local model=""
    
    # Try to get device model
    if [ -f /proc/device-tree/model ]; then
        model=$(cat /proc/device-tree/model 2>/dev/null)
    fi
    
    # Determine platform
    if [[ "$model" == *"Raspberry Pi Zero W"* ]]; then
        echo "rp-zero-w"
    elif [[ "$model" == *"Raspberry Pi 5"* ]]; then
        echo "pi-5"
    elif [[ "$model" == *"Raspberry Pi 4"* ]]; then
        echo "pi-4"
    elif [[ "$model" == *"Raspberry Pi 3"* ]]; then
        echo "pi-3"
    elif [[ "$arch" == "riscv64" ]]; then
        if [[ "$model" == *"StarFive"* ]] || [[ "$model" == *"VisionFive"* ]]; then
            echo "visionfive-2"
        else
            echo "riscv-generic"
        fi
    elif [[ "$arch" == "x86_64" ]]; then
        echo "x86-64"
    elif [[ "$arch" == "i686" ]] || [[ "$arch" == "i386" ]]; then
        echo "x86-32"
    elif [[ "$arch" == "aarch64" ]]; then
        echo "arm64-generic"
    elif [[ "$arch" == "armv7l" ]]; then
        echo "armv7-generic"
    elif [[ "$arch" == "armv6l" ]]; then
        echo "armv6-generic"
    else
        echo "unknown"
    fi
}

PLATFORM=$(detect_platform)

print_info "Detected platform: $PLATFORM"
print_info "Architecture: $(uname -m)"

if [ -f /proc/device-tree/model ]; then
    print_info "Model: $(cat /proc/device-tree/model)"
fi

if [ "$PLATFORM" == "unknown" ]; then
    print_error "Could not detect platform automatically"
    echo ""
    echo "Please choose your platform:"
    echo "  1) Raspberry Pi Zero W"
    echo "  2) Raspberry Pi 5"
    echo "  3) VisionFive 2"
    echo "  4) Other ARM64"
    echo "  5) Other RISC-V"
    read -p "Enter choice (1-5): " choice
    
    case $choice in
        1) PLATFORM="rp-zero-w" ;;
        2) PLATFORM="pi-5" ;;
        3) PLATFORM="visionfive-2" ;;
        4) PLATFORM="arm64-generic" ;;
        5) PLATFORM="riscv-generic" ;;
        *) print_error "Invalid choice"; exit 1 ;;
    esac
fi

echo ""
print_success "Platform set to: $PLATFORM"

################################################################################
# Directory Setup
################################################################################

print_header "Setting Up Directory Structure"

BASE_DIR="${HOME}/4301-workspace/final"
CODE_DIR="${BASE_DIR}/Code"
COMMON_DIR="${CODE_DIR}/Common"
SCRIPTS_DIR="${CODE_DIR}/Scripts"
DOCS_DIR="${BASE_DIR}/Documentation"

# Platform-specific directory name mapping
case $PLATFORM in
    rp-zero-w)      PLATFORM_DIR="${CODE_DIR}/RP-Zero-W" ;;
    pi-5)           PLATFORM_DIR="${CODE_DIR}/Pi-5" ;;
    pi-4)           PLATFORM_DIR="${CODE_DIR}/Pi-4" ;;
    pi-3)           PLATFORM_DIR="${CODE_DIR}/Pi-3" ;;
    visionfive-2)   PLATFORM_DIR="${CODE_DIR}/VisionFive-2" ;;
    x86-64)         PLATFORM_DIR="${CODE_DIR}/x86-64" ;;
    x86-32)         PLATFORM_DIR="${CODE_DIR}/x86-32" ;;
    riscv-generic)  PLATFORM_DIR="${CODE_DIR}/RISC-V-Generic" ;;
    arm64-generic)  PLATFORM_DIR="${CODE_DIR}/ARM64-Generic" ;;
    armv7-generic)  PLATFORM_DIR="${CODE_DIR}/ARMv7-Generic" ;;
    armv6-generic)  PLATFORM_DIR="${CODE_DIR}/ARMv6-Generic" ;;
    *)              PLATFORM_DIR="${CODE_DIR}/Unknown" ;;
esac

# Create directories
mkdir -p "$COMMON_DIR"
mkdir -p "$PLATFORM_DIR/results"
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$DOCS_DIR"

print_success "Created directory structure"
echo "  Common: $COMMON_DIR"
echo "  Scripts: $SCRIPTS_DIR"
echo "  Platform: $PLATFORM_DIR"
echo "  Documentation: $DOCS_DIR"

################################################################################
# Install Dependencies
################################################################################

print_header "Installing Dependencies"

if command -v apt-get &> /dev/null; then
    print_info "Detected Debian/Ubuntu-based system"
    sudo apt-get update
    sudo apt-get install -y build-essential git python3 python3-pip
elif command -v dnf &> /dev/null; then
    print_info "Detected Fedora/Red Hat-based system"
    sudo dnf install -y gcc make git python3 python3-pip
elif command -v pacman &> /dev/null; then
    print_info "Detected Arch-based system"
    sudo pacman -S --noconfirm base-devel git python python-pip
else
    print_warning "Unknown package manager - please install manually:"
    echo "  - gcc, make, git"
    echo "  - python3, python3-pip"
fi

print_success "Dependencies installed"

################################################################################
# Clone ASCON Repository
################################################################################

print_header "Cloning ASCON Repository"

cd "$BASE_DIR"

if [ ! -d "ascon-c" ]; then
    print_info "Cloning ASCON repository..."
    git clone https://github.com/ascon/ascon-c.git
    print_success "ASCON cloned"
else
    print_info "ASCON repository already exists"
    cd ascon-c
    git pull 2>/dev/null || print_warning "Could not update ASCON"
    cd ..
fi

ASCON_PATH="${BASE_DIR}/ascon-c"

################################################################################
# Create Platform Configuration
################################################################################

print_header "Creating Platform Configuration"

cat > "${PLATFORM_DIR}/config.sh" << EOF
#!/bin/bash
# Platform configuration for: $PLATFORM
# Auto-generated by setup_universal.sh

# Platform identification
PLATFORM_NAME="$PLATFORM"
ARCHITECTURE="$(uname -m)"

# ASCON repository path
ASCON_BASE="${ASCON_PATH}/crypto_aead/asconaead128"

# Platform-specific compiler flags
EOF

# Add platform-specific settings
case $PLATFORM in
    rp-zero-w|armv6-generic)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=armv6 -mfpu=vfp -mfloat-abi=hard -flto -fomit-frame-pointer"
BEST_IMPL="bi32_armv6"
IMPLEMENTATIONS=("bi32_armv6" "ref" "opt32" "armv6" "armv6_lowsize")
EOF
        ;;
        
    pi-5|arm64-generic)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=armv8.2-a+fp16+rcpc+dotprod+crypto -mtune=cortex-a76 -flto -fomit-frame-pointer"
BEST_IMPL="opt64"
IMPLEMENTATIONS=("opt64" "neon" "opt32" "ref")
EOF
        ;;
        
    pi-4)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=armv8-a+crc -mtune=cortex-a72 -flto -fomit-frame-pointer"
BEST_IMPL="opt64"
IMPLEMENTATIONS=("opt64" "neon" "opt32" "ref")
EOF
        ;;
        
    visionfive-2|riscv-generic)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=rv64gc -mtune=sifive-7-series -flto -fomit-frame-pointer"
BEST_IMPL="opt64"
IMPLEMENTATIONS=("opt64" "asm_rv32b" "asm_bi32_rv32b" "asm_rv32i" "ref")
EOF
        ;;
        
    x86-64)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=native -mtune=native -flto -fomit-frame-pointer"
BEST_IMPL="opt64"
IMPLEMENTATIONS=("opt64" "bi32" "opt32" "ref")
EOF
        ;;
        
    x86-32)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -march=native -mtune=native -flto -fomit-frame-pointer"
BEST_IMPL="opt32"
IMPLEMENTATIONS=("opt32" "bi32" "bi32_lowsize" "ref")
EOF
        ;;
        
    *)
        cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'
CFLAGS="-O3 -flto -fomit-frame-pointer"
BEST_IMPL="ref"
IMPLEMENTATIONS=("ref" "opt32" "opt64")
EOF
        ;;
esac

cat >> "${PLATFORM_DIR}/config.sh" << 'EOF'

# Common settings
LDFLAGS="-lrt -lm"
WARNINGS="-w"
INCLUDES="-I."

# Output
echo "Configuration loaded for: $PLATFORM_NAME"
echo "  Architecture: $ARCHITECTURE"
echo "  Best implementation: $BEST_IMPL"
echo "  Compiler flags: $CFLAGS"
EOF

chmod +x "${PLATFORM_DIR}/config.sh"
print_success "Created platform configuration"

################################################################################
# Move/Link Common Files
################################################################################

print_header "Setting Up Common Files"

# If optimized_benchmark.c exists in current directory, move it to Common
if [ -f "optimized_benchmark.c" ]; then
    cp optimized_benchmark.c "$COMMON_DIR/"
    print_success "Copied optimized_benchmark.c to Common/"
fi

if [ -f "analyze_results.py" ]; then
    cp analyze_results.py "$COMMON_DIR/"
    print_success "Copied analyze_results.py to Common/"
fi

# Create symlinks in platform directory
cd "$PLATFORM_DIR"
if [ -f "$COMMON_DIR/optimized_benchmark.c" ]; then
    ln -sf "$COMMON_DIR/optimized_benchmark.c" optimized_benchmark.c 2>/dev/null || \
        cp "$COMMON_DIR/optimized_benchmark.c" optimized_benchmark.c
    print_success "Linked optimized_benchmark.c"
fi

if [ -f "$COMMON_DIR/analyze_results.py" ]; then
    ln -sf "$COMMON_DIR/analyze_results.py" analyze_results.py 2>/dev/null || \
        cp "$COMMON_DIR/analyze_results.py" analyze_results.py
    print_success "Linked analyze_results.py"
fi

################################################################################
# Create Platform Build Script
################################################################################

print_header "Creating Build Script"

cat > "${PLATFORM_DIR}/build.sh" << 'BUILD_EOF'
#!/bin/bash
################################################################################
# Platform-Specific Build Script
# Auto-generated - customized for detected platform
################################################################################

set -e

# Load platform configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

echo "========================================"
echo "Building ASCON for $PLATFORM_NAME"
echo "========================================"
echo ""

# Check ASCON repository
if [ ! -d "$ASCON_BASE" ]; then
    echo "ERROR: ASCON not found at $ASCON_BASE"
    exit 1
fi

# Build each implementation
BUILT=0
FAILED=0

for IMPL in "${IMPLEMENTATIONS[@]}"; do
    IMPL_DIR="$ASCON_BASE/$IMPL"
    
    if [ ! -d "$IMPL_DIR" ]; then
        echo "Warning: Skipping $IMPL (not available)"
        continue
    fi
    
    echo "Building: $IMPL..."
    
    # Create temp directory
    BUILD_DIR="build_temp_$IMPL"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Copy files
    cp "$IMPL_DIR"/*.c "$BUILD_DIR/" 2>/dev/null || true
    cp "$IMPL_DIR"/*.h "$BUILD_DIR/" 2>/dev/null || true
    cp optimized_benchmark.c "$BUILD_DIR/"
    
    cd "$BUILD_DIR"
    
    # Create crypto_aead.h wrapper
    cat > crypto_aead.h << 'HEADER_EOF'
#ifndef CRYPTO_AEAD_H
#define CRYPTO_AEAD_H
#include "api.h"
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k);
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec,
                        const unsigned char* c, unsigned long long clen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* npub, const unsigned char* k);
#endif
HEADER_EOF
    
    # Find ASCON files
    ASCON_FILES=$(ls *.c 2>/dev/null | grep -v "optimized_benchmark" | tr '\n' ' ')
    
    if [ -z "$ASCON_FILES" ]; then
        echo "Error: No source files"
        cd ..
        rm -rf "$BUILD_DIR"
        FAILED=$((FAILED + 1))
        continue
    fi
    
    # Compile
    gcc $CFLAGS $WARNINGS $INCLUDES \
        optimized_benchmark.c $ASCON_FILES \
        -o "../benchmark_${IMPL}" $LDFLAGS 2>&1 | grep -i "error" || true
    
    cd ..
    rm -rf "$BUILD_DIR"
    
    if [ -f "benchmark_${IMPL}" ]; then
        SIZE=$(ls -lh "benchmark_${IMPL}" | awk '{print $5}')
        echo "Success: Built benchmark_${IMPL} ($SIZE)"
        BUILT=$((BUILT + 1))
    else
        echo "Error: Failed to build $IMPL"
        FAILED=$((FAILED + 1))
    fi
    echo ""
done

echo "========================================"
echo "Build Summary"
echo "========================================"
echo "Built: $BUILT"
echo "Failed: $FAILED"
echo ""

if [ $BUILT -gt 0 ]; then
    echo "Available benchmarks:"
    ls -lh benchmark_* 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
    echo ""
    echo "Run with: ./benchmark_${BEST_IMPL}"
else
    echo "ERROR: No benchmarks built successfully"
    exit 1
fi
BUILD_EOF

chmod +x "${PLATFORM_DIR}/build.sh"
print_success "Created build.sh"

################################################################################
# CPU Performance Tuning
################################################################################

print_header "CPU Performance Setup"

GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
print_info "Current CPU governor: $GOVERNOR"

if [ "$GOVERNOR" != "performance" ]; then
    print_warning "CPU is not in performance mode"
    echo ""
    read -p "Set CPU to performance mode? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo sh -c 'for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $cpu 2>/dev/null; done'
        print_success "CPU set to performance mode"
    fi
fi

################################################################################
# Summary
################################################################################

print_header "Setup Complete!"

cat << EOF
Installation Summary:
--------------------------------------------

Platform:     $PLATFORM
Base Dir:     $BASE_DIR
Code Dir:     $CODE_DIR
Platform Dir: $PLATFORM_DIR
ASCON Path:   $ASCON_PATH

Directory Structure:
--------------------------------------------

~/4301-workspace/final/
├── Code/
│   ├── Common/          # Shared files
│   ├── $(basename $PLATFORM_DIR)/          # Your platform
│   └── Scripts/         # Utilities
├── ascon-c/             # ASCON repository
└── Documentation/       # Docs

Next Steps:
--------------------------------------------

1. Navigate to platform directory:
   ${CYAN}cd $PLATFORM_DIR${NC}

2. Build benchmarks:
   ${CYAN}./build.sh${NC}

3. Run best implementation:
   ${CYAN}./benchmark_${BEST_IMPL}${NC}

4. Results will be in:
   ${CYAN}$PLATFORM_DIR/results/${NC}

5. Analyze results:
   ${CYAN}python3 analyze_results.py results/*.csv${NC}

Configuration:
--------------------------------------------

View platform config:
  ${CYAN}cat config.sh${NC}

Edit if needed:
  ${CYAN}nano config.sh${NC}

EOF

print_success "Ready to benchmark!"
