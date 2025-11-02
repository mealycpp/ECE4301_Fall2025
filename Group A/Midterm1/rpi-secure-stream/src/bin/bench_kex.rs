use anyhow::{anyhow, Result};
use clap::Parser;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use rpi_secure_stream::crypto;
use rpi_secure_stream::net;
use rpi_secure_stream::video;


const AES128_KEY_LEN: usize = 16;
const NONCE_BASE_LEN: usize = 12;

#[derive(Parser, Debug)]
#[command(author, version, about = "Key exchange micro-benchmarks: ECDH(P-256)+HKDF and RSA-OAEP(SHA-256)")]
struct Args {
    /// Number of iterations per benchmark
    #[arg(long, default_value_t = 500)]
    iters: usize,

    /// RSA modulus size (bits)
    #[arg(long, default_value_t = 2048)]
    rsa_bits: usize,

    /// HKDF salt length (bytes)
    #[arg(long, default_value_t = 32)]
    salt_len: usize,

    /// Context string for HKDF
    #[arg(long, default_value = "ECE4301-midterm-2025")]
    context: String,

    /// Print a single CSV line (in addition to pretty output)
    #[arg(long, default_value_t = true)]
    csv: bool,
}

fn stats(label: &str, samples: &[Duration]) {
    let mut v: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect(); // ms
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len().max(1);
    let mean = v.iter().sum::<f64>() / (n as f64);
    let p = |q: f64| -> f64 {
        let idx = ((n as f64 - 1.0) * q).round() as usize;
        v[idx.min(n - 1)]
    };
    println!(
        "{label:<30} count={n:>5}  mean={mean:>8.3} ms  p50={p50:>8.3}  p95={p95:>8.3}  p99={p99:>8.3}",
        n = n,
        mean = mean,
        p50 = p(0.50),
        p95 = p(0.95),
        p99 = p(0.99)
    );
}

fn bench_ecdh_hkdf(iters: usize, salt_len: usize, ctx: &[u8]) -> Result<Vec<Duration>> {
    let mut out = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();

        // Ephemeral keypairs A and B
        let a_sec = EphemeralSecret::random(&mut OsRng);
        let a_pub = PublicKey::from(&a_sec);
        let a_pub_bytes = EncodedPoint::from(a_pub).as_bytes().to_vec();

        let b_sec = EphemeralSecret::random(&mut OsRng);
        let b_pub = PublicKey::from(&b_sec);
        let b_pub_bytes = EncodedPoint::from(b_pub).as_bytes().to_vec();

        // Derive shared secret both ways and HKDF → AES key & nonce base
        let salt_a = {
            let mut s = vec![0u8; salt_len];
            OsRng.fill_bytes(&mut s);
            s
        };
        let salt_b = {
            let mut s = vec![0u8; salt_len];
            OsRng.fill_bytes(&mut s);
            s
        };

        // A derives
        let peer_pub_a = PublicKey::from_sec1_bytes(&b_pub_bytes)?;
        let shared_a = a_sec.diffie_hellman(&peer_pub_a);

        let mut ss_a = [0u8; 32];
        ss_a.copy_from_slice(shared_a.raw_secret_bytes().as_ref());
        let hk_a = if salt_len == 0 {
            Hkdf::<Sha256>::new(None, &ss_a)
        } else {
            Hkdf::<Sha256>::new(Some(&salt_a), &ss_a)
        };
        let mut key_a = [0u8; AES128_KEY_LEN];
        let mut nonce_a = [0u8; NONCE_BASE_LEN];
        hk_a.expand(&[ctx, b":aes128"].concat(), &mut key_a)
            .map_err(|_| anyhow!("hkdf expand aes key failed"))?;
        hk_a.expand(&[ctx, b":gcm-nonce-base"].concat(), &mut nonce_a)
            .map_err(|_| anyhow!("hkdf expand nonce failed"))?;
        ss_a.zeroize();

        // B derives
        let peer_pub_b = PublicKey::from_sec1_bytes(&a_pub_bytes)?;
        let shared_b = b_sec.diffie_hellman(&peer_pub_b);

        let mut ss_b = [0u8; 32];
        ss_b.copy_from_slice(shared_b.raw_secret_bytes().as_ref());
        let hk_b = if salt_len == 0 {
            Hkdf::<Sha256>::new(None, &ss_b)
        } else {
            Hkdf::<Sha256>::new(Some(&salt_b), &ss_b)
        };
        let mut key_b = [0u8; AES128_KEY_LEN];
        let mut nonce_b = [0u8; NONCE_BASE_LEN];
        hk_b.expand(&[ctx, b":aes128"].concat(), &mut key_b)
            .map_err(|_| anyhow!("hkdf expand aes key failed"))?;
        hk_b.expand(&[ctx, b":gcm-nonce-base"].concat(), &mut nonce_b)
            .map_err(|_| anyhow!("hkdf expand nonce failed"))?;
        ss_b.zeroize();

        // We’re measuring cost, not equality (salts differ intentionally).

        out.push(t0.elapsed());
    }
    Ok(out)
}

fn bench_rsa_keygen(bits: usize, iters: usize) -> Result<Vec<Duration>> {
    let mut out = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let _sk = RsaPrivateKey::new(&mut OsRng, bits)?;
        out.push(t0.elapsed());
    }
    Ok(out)
}

fn bench_rsa_oaep_wrap_unwrap(bits: usize, iters: usize) -> Result<Vec<Duration>> {
    // Use one keypair for the wrap/unwrap loop (typical in practice).
    let sk = RsaPrivateKey::new(&mut OsRng, bits)?;
    let pk = RsaPublicKey::from(&sk);

    let mut out = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();

        let mut session_key = [0u8; 16];
        OsRng.fill_bytes(&mut session_key);

        // FIX: construct label per-iteration to avoid move issues.
        let label = Oaep::new::<Sha256>();

        let wrapped = pk.encrypt(&mut OsRng, label, &session_key)?;
        // re-create label (separate move) for decrypt:
        let label = Oaep::new::<Sha256>();
        let mut unwrapped = sk.decrypt(label, &wrapped)?;

        // hygiene
        session_key.zeroize();
        unwrapped.zeroize();

        out.push(t0.elapsed());
    }
    Ok(out)
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("== Key Exchange Micro-Benchmarks ==");
    println!("iters          : {}", args.iters);
    println!("rsa_bits       : {}", args.rsa_bits);
    println!("hkdf_salt_len  : {}", args.salt_len);
    println!("hkdf_context   : {:?}", args.context);

    // ECDH(P-256)+HKDF
    let ecdh = bench_ecdh_hkdf(args.iters, args.salt_len, args.context.as_bytes())?;
    stats("ECDH(P-256)+HKDF", &ecdh);

    // RSA keygen (cap to 50 by default to keep runtime reasonable)
    let rsa_gen = bench_rsa_keygen(args.rsa_bits, args.iters.min(50))?;
    stats(&format!("RSA-{} keygen", args.rsa_bits), &rsa_gen);

    // RSA OAEP wrap+unwrap
    let rsa_wrap = bench_rsa_oaep_wrap_unwrap(args.rsa_bits, args.iters)?;
    stats(&format!("RSA-{} OAEP wrap+unwrap", args.rsa_bits), &rsa_wrap);

    // Optional CSV summary (means only)
    if args.csv {
        let mean_ms = |v: &[Duration]| {
            let n = v.len().max(1);
            v.iter().map(|d| d.as_secs_f64() * 1e3).sum::<f64>() / n as f64
        };
        let ecdh_mean = mean_ms(&ecdh);
        let rsa_wrap_mean = mean_ms(&rsa_wrap);
        let rsa_gen_mean = mean_ms(&rsa_gen);

        println!(
            "CSV,iters={},rsa_bits={},salt_len={},ecdh_ms_mean={:.3},rsa_keygen_ms_mean={:.3},rsa_wrapunwrap_ms_mean={:.3}",
            args.iters, args.rsa_bits, args.salt_len, ecdh_mean, rsa_gen_mean, rsa_wrap_mean
        );
    }

    Ok(())
}
