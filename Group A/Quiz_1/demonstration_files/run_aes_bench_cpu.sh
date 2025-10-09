#!/bin/bash
# Benchmark AES-256-CBC using EVP (OpenSSL), AF_ALG, and PURE-C,
# logging throughput and CPU% per run. Prefers /usr/bin/time -v.

set -u

SIZES=(16777216 33554432 67108864 134217728 268435456)  # 16, 32, 64, 128, 256 MiB
RESULTS="aes_results.csv"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { log "Missing binary: $1"; exit 1; }; }

# Binaries to benchmark
need ./aes_evp
need ./aes_afalg
need ./aes_pure

# Try to load AF_ALG helpers (ignore errors if already loaded / not needed)
sudo modprobe algif_skcipher 2>/dev/null || true
sudo modprobe cbc            2>/dev/null || true
sudo modprobe algif_hash     2>/dev/null || true

echo "Mode,Bytes,MiB,Time(s),CPU(%),Throughput(MiB/s)" > "$RESULTS"
log "Writing results to $RESULTS"

have_gtime=false
if command -v /usr/bin/time >/dev/null 2>&1; then
  have_gtime=true
fi

run_one() {
  local mode="$1" bin="$2" size="$3"
  local tag="${mode}_${size}"
  local out="/tmp/${tag}.out"
  local tfile="/tmp/${tag}.time"

  log "Running $mode size=$((size/1024/1024)) MiB ..."

  local secs="" cpu="" tput=""

  if $have_gtime; then
    # Use GNU time verbose output
    /usr/bin/time -v "$bin" "$size" >"$out" 2>"$tfile"
    # Parse elapsed/user/sys (GNU time -v is stable)
    local elapsed user sys
    elapsed=$(awk -F': ' '/Elapsed \(wall clock\) time/ {print $2}' "$tfile")
    user=$(awk -F': ' '/User time \(seconds\)/         {print $2}' "$tfile")
    sys=$(awk  -F': ' '/System time \(seconds\)/       {print $2}' "$tfile")

    # Normalize elapsed to seconds (handles mm:ss.xx or h:mm:ss)
    # Convert H:M:S.sss to seconds
    to_secs() {
      awk -v t="$1" '
        function parse(s,   n,i,sum,part) {
          n=split(s,a,":"); sum=0
          for(i=1;i<=n;i++){ part=a[i]+0; sum=sum*60+part }
          return sum
        }
        BEGIN{ print parse(t) }
      '
    }
    secs=$(to_secs "$elapsed")
    # CPU% = (user + sys) / secs * 100
    if [[ -n "$secs" && "$secs" != "0" ]]; then
      cpu=$(awk -v u="$user" -v s="$sys" -v r="$secs" 'BEGIN{printf("%.0f", 100*(u+s)/r)}')
    else
      cpu=""
    fi
  else
    # Fallback to shell built-in `time` (format varies by shell)
    { time "$bin" "$size" >"$out"; } 2>"$tfile"
    # Try to find first numeric field on the line as elapsed seconds
    secs=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+$/){print $i; exit}}' "$tfile")
    # Try to derive CPU% from "Xuser Ysystem" if present
    local usr sys
    usr=$(grep -o '[0-9.]\+user' "$tfile"   | sed 's/user//') || true
    sys=$(grep -o '[0-9.]\+system' "$tfile" | sed 's/system//') || true
    if [[ -n "${usr:-}" && -n "${sys:-}" && -n "${secs:-}" && "$secs" != "0" ]]; then
      cpu=$(awk -v u="$usr" -v s="$sys" -v r="$secs" 'BEGIN{printf("%.0f", 100*(u+s)/r)}')
    else
      cpu=""
    fi
  fi

  # Parse throughput from program output; else compute MiB/s
  tput=$(grep -Eo '[0-9]+\.[0-9]+\s+MiB/s' "$out" | tail -n1 | awk '{print $1}') || true
  if [[ -z "${tput:-}" || "${tput}" == "0" ]]; then
    if [[ -n "${secs:-}" && "$secs" != "0" ]]; then
      tput=$(awk -v b="$size" -v s="$secs" 'BEGIN{mib=b/1048576; printf("%.2f", mib/s)}')
    else
      tput="0"
    fi
  fi

  local mib=$(( size / 1024 / 1024 ))
  printf "%s: %s MiB | Time %ss | CPU %s%% | %s MiB/s\n" "$mode" "$mib" "${secs:-}" "${cpu:-}" "$tput"
  echo "$mode,$size,$mib,${secs:-},${cpu:-},$tput" >> "$RESULTS"
}

for SIZE in "${SIZES[@]}"; do
  echo
  log "===== Testing $((SIZE/1024/1024)) MiB ====="
  run_one "EVP"    "./aes_evp"   "$SIZE"
  run_one "AF_ALG" "./aes_afalg" "$SIZE"
  run_one "PURE"   "./aes_pure"  "$SIZE"
done

echo
log "Benchmark complete. Results saved to $RESULTS"
