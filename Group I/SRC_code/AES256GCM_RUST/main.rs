use aes_gcm::{
    Aes256Gcm,
    KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray, Key},
};
use rand::RngCore;
use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"Hi this is plaintext"; // 21 bytes
const STREAM_BLOCK: usize = 16 * 1024;          // 16 KB per chunk
const STREAM_SECS: f64 = 3.0;                   // ~3 seconds

fn fmt_bytes_per_sec(bps: f64) -> String {
    if bps >= 1e9 { format!("{:.3} GB/s ({:.1} MB/s)", bps/1e9, bps/1e6) }
    else if bps >= 1e6 { format!("{:.1} MB/s", bps/1e6) }
    else if bps >= 1e3 { format!("{:.1} kB/s", bps/1e3) }
    else { format!("{:.0} B/s", bps) }
}

/// Increment a 96-bit (12-byte) nonce as a big-endian counter.
fn inc_nonce_be(n: &mut [u8; 12]) {
    for b in n.iter_mut().rev() {
        let (nb, carry) = b.overflowing_add(1);
        *b = nb;
        if !carry { break; }
    }
}

fn main() {
    // -----------------------------
    // One-shot (latency) with AES-GCM
    // -----------------------------
    let mut key_bytes = [0u8; 32];   // 32B key → AES-256
    let mut nonce_bytes = [0u8; 12]; // GCM fast path nonce size
    rand::thread_rng().fill_bytes(&mut key_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let t0 = Instant::now();
    let cipher = Aes256Gcm::new(key); // setup / key schedule
    let t1 = Instant::now();

    let mut buf = MESSAGE.to_vec();   // encrypt in place
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let t2 = Instant::now();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buf)
        .expect("encrypt");
    let t3 = Instant::now();

    let setup_time   = (t1 - t0).as_secs_f64();
    let encrypt_time = (t3 - t2).as_secs_f64();
    let total_time   = (t3 - t0).as_secs_f64();
    let tiny_tp_bps  = (MESSAGE.len() as f64) / encrypt_time;

    println!("== One-shot (AES-256-GCM, 21-byte message) ==");
    println!("plaintext:           {}", String::from_utf8_lossy(MESSAGE));
    println!("key (hex):           {}", hex::encode(key_bytes));
    println!("nonce (hex):         {}", hex::encode(nonce_bytes));
    println!("ciphertext (hex):    {}", hex::encode(&buf));
    println!("tag (hex):           {}", hex::encode(tag));
    println!("setup latency:       {:.2} µs", setup_time * 1e6);
    println!("encrypt latency:     {:.2} µs  (execution time)", encrypt_time * 1e6);
    println!("total latency:       {:.2} µs  (setup + encrypt)", total_time * 1e6);
    println!("throughput (tiny):   {}", fmt_bytes_per_sec(tiny_tp_bps));
    println!();

    // Decrypt check
    let mut dec = buf.clone();
    let nonce = GenericArray::from_slice(&nonce_bytes);
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut dec, &tag)
        .expect("decrypt");
    println!("== Decrypt check ==");
    println!("decrypted:           {}", String::from_utf8_lossy(&dec));
    println!();

    // ------------------------------------------------
    // Streaming-style throughput (fresh nonce per chunk)
    // Each 16 KB chunk is treated as its own AEAD message (new nonce + tag).
    // ------------------------------------------------
    let mut key2 = [0u8; 32];
    let mut nonce2 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key2);
    rand::thread_rng().fill_bytes(&mut nonce2);

    let cipher2 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key2));
    let mut block = vec![0u8; STREAM_BLOCK];
    let mut total_bytes: usize = 0;
    let mut calls: u64 = 0;
    let mut sink: u8 = 0; // touch outputs to keep optimizer honest

    let t_start = Instant::now();
    let deadline = t_start + Duration::from_secs_f64(STREAM_SECS);

    while Instant::now() < deadline {
        // fresh nonce per chunk (required for GCM)
        let nonce = GenericArray::from_slice(&nonce2);
        let tag = cipher2
            .encrypt_in_place_detached(nonce, b"", &mut block)
            .expect("encrypt");
        sink ^= tag[0]; // use the tag so it isn't optimized out
        inc_nonce_be(&mut nonce2);

        total_bytes += block.len();
        calls += 1;
    }
    let t_end = Instant::now();

    let elapsed = (t_end - t_start).as_secs_f64();
    let bps = (total_bytes as f64) / elapsed;
    let per_call_latency = elapsed / (calls as f64);

    println!("== Streaming (AES-256-GCM, software-only) ==");
    println!("duration:            {:.3} s", elapsed);
    println!("bytes processed:     {}", total_bytes);
    println!("throughput:          {}", fmt_bytes_per_sec(bps));
    println!("per-call latency:    {:.2} µs per {}B chunk", per_call_latency * 1e6, STREAM_BLOCK);
    println!("calls made:          {}", calls);
    println!("(ignore) sink byte:  {}", sink);
}
