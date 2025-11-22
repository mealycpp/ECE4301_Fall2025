#!/usr/bin/env bash
set -euo pipefail
echo "algo,size_bytes,mib_per_s" > engine.csv
for ALG in sha1 sha256; do
  for B in 1024 8192 65536 1048576; do
    OUT="$(taskset -c 3 openssl speed -elapsed -evp "$ALG" -bytes "$B" 2>&1 || true)"

    # Try to grab the last token ending in 'k' on a line mentioning 'evp'
    K=$(printf "%s\n" "$OUT" | awk 'tolower($0) ~ /evp/ {for(i=1;i<=NF;i++) if($i ~ /k$/) last=$i} END{print last}')
    # Fallback: grab the last 'k' token anywhere (handles odd output)
    if [ -z "${K:-}" ]; then
      K=$(printf "%s\n" "$OUT" | awk '{for(i=1;i<=NF;i++) if($i ~ /k$/) last=$i} END{print last}')
    fi
    if [ -z "${K:-}" ]; then
      echo "WARN: could not parse OpenSSL output for $ALG $B; skipping" >&2
      continue
    fi

    VAL="${K%k}"  # strip trailing 'k' (OpenSSL uses decimal *1000* bytes/sec)
    MIB=$(python3 - <<PY
v = float("$VAL")*1000.0/(1024.0*1024.0)
print(f"{v:.6f}")
PY
)
    printf "%s,%d,%s\n" "$ALG" "$B" "$MIB" >> engine.csv
  done
done
