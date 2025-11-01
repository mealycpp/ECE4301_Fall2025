mod crypto;

use crypto::rsa_kem::*;
use crypto::ecdh::*;

fn main() -> anyhow::Result<()> {
    println!("🔐 Testing RSA + ECDH crypto modules...");

    // --- RSA Test ---
    let (sk, pk) = generate_rsa_keypair(2048)?;
    let (wrapped, session_key) = rsa_wrap(&pk)?;
    let unwrapped = rsa_unwrap(&sk, &wrapped)?;
    assert_eq!(session_key, unwrapped);
    println!("RSA OAEP-SHA256 ✅ OK");

    // --- ECDH Test ---
    let (a_sec, a_pub) = generate_ephemeral();
    let (b_sec, b_pub) = generate_ephemeral();
    let salt = [0u8; 32];
    let ctx = b"ECE4301-midterm-2025";
    let a = ecdh_derive(&a_sec, &b_pub, &salt, ctx)?;
    let b = ecdh_derive(&b_sec, &a_pub, &salt, ctx)?;
    assert_eq!(a, b);
    println!("ECDH + HKDF ✅ OK");

    Ok(())
}
