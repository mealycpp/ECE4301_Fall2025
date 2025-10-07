import os, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ----- One-shot encryption of your exact string (good for latency) -----
PLAINTEXT = b"Hi this is plain text                             "

key = os.urandom(32)
nonce = os.urandom(12)

t0 = time.perf_counter()
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
encryptor = cipher.encryptor()
t1 = time.perf_counter()  # setup done

t2 = time.perf_counter()
ct = encryptor.update(PLAINTEXT) + encryptor.finalize()
t3 = time.perf_counter()

setup_time = (t1 - t0)         # seconds
encrypt_time = (t3 - t2)       # seconds (execution time for the message)
total_time = (t3 - t0)         # setup + encrypt
throughput_small = len(PLAINTEXT) / encrypt_time  # bytes/s (noisy for tiny msgs)

print("One-shot (21 bytes):")
print(f"  setup latency:   {setup_time*1e6:.2f} µs")
print(f"  encrypt latency: {encrypt_time*1e6:.2f} µs  (execution time for message)")
print(f"  total latency:   {total_time*1e6:.2f} µs  (setup + encrypt)")
print(f"  'throughput' on tiny msg: {throughput_small/1e6:.2f} MB/s (not very meaningful for small inputs)")
print()

# ----- Streaming benchmark (good for throughput & per-call latency) -----
BLOCK = 16_384  # 16 KB chunk (hits the throughput plateau)
buf = b"\x00" * BLOCK
key = os.urandom(32)
nonce = os.urandom(12)

cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
enc = cipher.encryptor()

duration = 3.0  # seconds of streaming
total = 0
calls = 0
t_start = time.perf_counter()
deadline = t_start + duration
while True:
    now = time.perf_counter()
    if now >= deadline:
        break
    enc.update(buf)
    total += BLOCK
    calls += 1
enc.finalize()
t_end = time.perf_counter()

elapsed = t_end - t_start
throughput = total / elapsed                 # bytes/s
per_call_latency = elapsed / calls           # seconds per update() call

print("Streaming (throughput focus):")
print(f"  elapsed:          {elapsed:.3f} s")
print(f"  bytes processed:  {total:,}")
print(f"  throughput:       {throughput/1e9:.3f} GB/s  ({throughput/1e6:.1f} MB/s)")
print(f"  per-call latency: {per_call_latency*1e6:.2f} µs per update() (with 16 KB chunks)")
print(f"  calls made:       {calls}")
