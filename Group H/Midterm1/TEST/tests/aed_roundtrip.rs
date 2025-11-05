use rpi_secure_stream::aead::{AeadCtx, NonceCtr};

#[test]
fn aead_roundtrip_and_unique_nonces() {
    let key = [0x11u8;16];
    let mut ctr = NonceCtr::new([0x22;8]);
    let a = AeadCtx::new(key);

    let mut seen = std::collections::HashSet::new();
    for seq in 0..1000u64 {
        let nonce = ctr.next();
        assert!(seen.insert(nonce), "nonce reused!");
        let ct = a.seal(nonce, seq, b"hello frame");
        let pt = a.open(nonce, seq, &ct);
        assert_eq!(&pt, b"hello frame");
    }
}
