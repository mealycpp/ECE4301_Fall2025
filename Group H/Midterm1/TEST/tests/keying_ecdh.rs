use rpi_secure_stream::keying;

#[test]
fn ecdh_p256_roundtrip_same_salt_same_params() {
    // Alice and Bob each create an offer (ephemeral pubkey + random salt).
    let (offer_a, secret_a) = keying::start_offer();
    let (offer_b, secret_b) = keying::start_offer();

    // Choose one salt to use for both (common pattern: use the initiator's).
    let salt = offer_a.salt;

    // Each derives using their secret, the other's public key, and the agreed salt.
    let params_a = keying::derive_params(&secret_a, &offer_b.pubkey_sec1, &salt);
    let params_b = keying::derive_params(&secret_b, &offer_a.pubkey_sec1, &salt);

    assert_eq!(params_a.enc_key, params_b.enc_key, "AES keys must match");
    assert_eq!(params_a.nonce_base, params_b.nonce_base, "nonce bases must match");
}

#[test]
fn changing_salt_changes_output() {
    let (offer_a, secret_a) = keying::start_offer();
    let (offer_b, _secret_b) = keying::start_offer();

    let p1 = keying::derive_params(&secret_a, &offer_b.pubkey_sec1, &offer_a.salt);

    // Make a different salt and expect different params.
    let mut other_salt = offer_a.salt;
    other_salt[0] ^= 0xFF;

    let p2 = keying::derive_params(&secret_a, &offer_b.pubkey_sec1, &other_salt);

    assert_ne!(p1.enc_key, p2.enc_key, "AES key should change with salt");
    assert_ne!(p1.nonce_base, p2.nonce_base, "nonce base should change with salt");
}
