#!/usr/bin/env bash
set -euo pipefail

# ---- Tunables --------------------------------------------------------------
MIB=${MIB:-256}          # MiB per iteration
ITERS=${ITERS:-20}       # iterations
REPEATS=${REPEATS:-5}    # perf -r <repeats>
OUT=target/release
# ---------------------------------------------------------------------------

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found"; exit 1; }; }
need cargo
need time

# Detect whether perf is available *and* permitted by kernel policy.
PERF_OK=0
if command -v perf >/dev/null 2>&1; then
  if perf stat -e cycles -- echo >/dev/null 2>&1; then
    PERF_OK=1
  fi
fi

echo "Building HW-accelerated (default runtime-detect) ..."
RUSTFLAGS="--cfg aes_armv8" cargo build --release > /dev/null
cp "$OUT/aes-demo" "$OUT/aes_demo_hw"

echo "Building SOFTWARE-only (force portable backend) ..."
RUSTFLAGS="--cfg aes_force_soft" cargo build --release > /dev/null
cp "$OUT/aes-demo" "$OUT/aes_demo_soft"

echo
echo "=== Build info ==="
"$OUT/aes_demo_hw"   --print-info || true
"$OUT/aes_demo_soft" --print-info || true

run_case () {
  local name="$1"
  local bin="$2"

  echo
  echo "================= $name ================="
  if [ "$PERF_OK" -eq 1 ]; then
    /usr/bin/time -v sh -c \
      "perf stat -d -r $REPEATS \"$bin\" --mib $MIB --iterations $ITERS --quiet || true" \
      2>&1 | tee "$OUT/${name}_perf.txt"
  else
    echo "(perf unavailable or not permitted; running without perf)"
    /usr/bin/time -v "$bin" --mib "$MIB" --iterations "$ITERS" --quiet \
      2>&1 | tee "$OUT/${name}_perf.txt"
  fi
}

run_case "HW"   "$OUT/aes_demo_hw"
run_case "SOFT" "$OUT/aes_demo_soft"

echo
echo "Done. Raw outputs saved to:"
echo "  $OUT/HW_perf.txt"
echo "  $OUT/SOFT_perf.txt"

echo
echo "Tip: To FORCE HW on x86_64 regardless of runtime detection, rebuild with:"
echo "  RUSTFLAGS='-C target-cpu=native -C target-feature=+aes,+ssse3' cargo build --release"
echo "CAUTION: Such binaries will SIGILL on CPUs without AES-NI."

if [[ $(uname -m) == "aarch64" ]]; then
  echo
  echo "ARM64 tip: enable ARMv8 AES intrinsics with:"
  echo "  RUSTFLAGS='--cfg aes_armv8' cargo build --release"
fi

