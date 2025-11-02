**bench_kex.rs** 
Compare RSA-OAEP (SHA-256) vs ECDH (P-256 + HKDF) performance.
cargo build --release
cargo run --release --bin bench_kex
cargo run --release --bin bench_kex -- --iters 1000 --rsa-bits 3072 --salt-len 32
cargo run --release --bin bench_kex -- --iters 500 --rsa-bits 2048 --salt-len 32

EXAMPLE OUTPUT:
ECDH(P-256)+HKDF                 count=  500  mean=  1.105 ms  p50=  1.100  p95=  1.190  p99=  1.233
RSA-2048 keygen                  count=   50  mean= 21.543 ms  p50= 20.981  p95= 24.221  p99= 25.912
RSA-2048 OAEP wrap+unwrap        count=  500  mean=  2.841 ms  p50=  2.812  p95=  3.014  p99=  3.089
CSV,iters=500,rsa_bits=2048,salt_len=32,ecdh_ms_mean=1.105,rsa_keygen_ms_mean=21.543,rsa_wrapunwrap_ms_mean=2.841

**bench_aesgcm.rs** executable instructions
Crypto-Engine Enabled(on the RPi5):
cargo run --release --bin bench_aesgcm -- --total-bytes 268435456 --chunk 16384 --aad-len 16
Crypto-Engine Disabled(on the RPi5):
RUSTFLAGS="-C target-feature=-aes,-pmull" cargo run --release --bin bench_aesgcm -- --total-bytes 268435456 --chunk 16384

EXAMPLE OUTPUT:
ARMv8 CE — AES:true PMULL:true SHA1:true SHA2:true
AES-128-GCM bench: total=268435456 bytes, chunk=16384, aad_len=16, verify=true
RESULT: enc_bytes=268435456 time=0.523s throughput=496.1 MiB/s (16384 iters, chunk=16384, tags=262144)
CSV,total_bytes=268435456,chunk=16384,aad_len=16,verify=true,mib_per_s=496.120


**bench_stream.rs** executable instructions
cargo run --release --bin bench_stream -- \
  --seconds 60 \
  --width 1280 --height 720 --fps 30 \
  --device /dev/video0

RESULT: seconds=60 frames=889 pt_mib=390.67 ct_mib=390.69 avg_fps=14.82



THREE SCENARIOS
./target/release/bench_stream --seconds 30 --width 1280 --height 720 --fps 30 --device /dev/video0
RUSTFLAGS="-C target-feature=-aes,-pmull" cargo run --release --bin bench_aesgcm -- --total-bytes 268435456 --chunk 16384
cargo run --release --bin bench_kex -- --iters 1000 --rsa-bits 2048 --salt-len 32
