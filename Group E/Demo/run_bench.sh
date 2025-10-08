#!/usr/bin/env bash
set -euo pipefail

OUTCSV="results.csv"
: > "$OUTCSV"

TOTAL_MB_LIST=(64 128 256)
CHUNK_KB_LIST=(4 16 64 256 1024)
IMPLS=(soft afalg)
OPS=(enc dec)

echo "Building..."
make -j"$(nproc)"

i=0
total_runs=$(( ${#TOTAL_MB_LIST[@]} * ${#CHUNK_KB_LIST[@]} * ${#IMPLS[@]} * ${#OPS[@]} ))
for total in "${TOTAL_MB_LIST[@]}"; do
  for chunk in "${CHUNK_KB_LIST[@]}"; do
    for impl in "${IMPLS[@]}"; do
      for op in "${OPS[@]}"; do
        i=$((i+1))
        echo "[$i/$total_runs] $impl $op total=${total}MB chunk=${chunk}KB"
        ./bench --impl "$impl" --op "$op" --total-mb "$total" --chunk "$chunk" --csv "$OUTCSV"
      done
    done
  done
done

echo "Done. Results in $OUTCSV"
