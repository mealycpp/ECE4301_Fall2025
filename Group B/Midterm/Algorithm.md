## Architecture (at a glance)

Camera → GStreamer → H.264 AU + FrameHeader → AES-GCM → TCP (len | nonce | ciphertext)      → Receiver → AES-GCM → AU → Decode/Display

---

## Algorithm — Sender (RSA mode)

1. Parse CLI arguments: destination IP/port, width, height, fps.
    
2. Initialize GStreamer.
    
3. Open a TCP connection to the receiver and enable `TCP_NODELAY`.
    
4. Generate session material: a random **16-byte AES key** and an **8-byte nonce_base**.
    
5. **Handshake (RSA):**
    
    1. Read a 4-byte big-endian length `der_len` from the socket.
        
    2. Read `der_len` bytes: receiver’s **DER-encoded RSA public key**.
        
    3. Wrap the AES key with **RSA-OAEP(SHA-256)** → `wrapped_key`.
        
    4. Send `u32_be(len(wrapped_key)) || wrapped_key || nonce_base`.
        
6. Initialize `Aes128Gcm(aes_key)`.
    
7. Start the metrics sampler thread (≈ every 250 ms).
    
8. Build and start the GStreamer pipeline:  
    `libcamerasrc → videoconvert → x264enc(ultrafast, zerolatency) → video/x-h264(byte-stream, alignment=au) → appsink`.
    
9. Initialize `counter = 0`.
    
10. **For each `appsink.new_sample()` callback:**
    
    1. Extract H.264 AU bytes `au`.
        
    2. Create `FrameHeader { seq = counter, ts_ns = monotonic_now_ns() }`.
        
    3. Increment `counter` with 32-bit wrapping.
        
    4. Concatenate plaintext `pt = header || au`.
        
    5. Build 12-byte nonce `nonce = nonce_base(8B) || counter_be(4B)`.
        
    6. Compute `ct = AES_GCM_Encrypt(pt, nonce)`.
        
    7. Let `total = 12 + len(ct)`.
        
    8. Send **one record**: `u32_be(total) || nonce || ct`.
        
    9. Update metrics (bytes, fps counters).
        
11. On EOS or error: stop pipeline, join threads, close socket, exit.
    

---

## Algorithm — Receiver (RSA mode)

1. Generate or load an RSA keypair.
    
2. Bind a TCP listener and `accept()` the sender connection.
    
3. **Handshake (RSA):**
    
    1. Serialize the receiver’s RSA public key to DER → `pub_der`.
        
    2. Send `u32_be(len(pub_der)) || pub_der`.
        
    3. Read `u32_be(wrap_len)`; read `wrap_len` bytes → `wrapped_key`.
        
    4. Read **8 bytes** → `nonce_base`.
        
    5. Unwrap AES key with **RSA-OAEP(SHA-256)** → `aes_key`.
        
4. Initialize `Aes128Gcm(aes_key)`.
    
5. Start the metrics sampler thread (≈ every 250 ms).
    
6. **Receive loop:**
    
    1. Read `u32_be(total)`.
        
    2. Read 12-byte `nonce`.
        
    3. Read `(total − 12)`-byte `ct`.
        
    4. Compute `pt = AES_GCM_Decrypt(ct, nonce)` (abort on auth failure).
        
    5. Parse `FrameHeader` from `pt[0..12]` → `(seq:u32, ts_ns:u64)` (big-endian).
        
    6. Extract `au = pt[12..]`.
        
    7. Compute `latency_ms = (monotonic_now_ns() − ts_ns) / 1e6` and log to metrics.
        
    8. Feed `au` to H.264 decoder (display or save).
        
7. On stream end or error: close socket and exit.
    

---

## ECDH Handshake (drop-in replacement for RSA steps)

1. Generate an ephemeral **P-256** keypair `(pub_local, sec_local)`.
    
2. Send `pub_local`; receive `pub_peer`.
    
3. Compute shared secret `z = ECDH(sec_local, pub_peer)`.
    
4. Derive with **HKDF-SHA256**:
    
    1. `aes_key = HKDF(z, info="ECE4301-midterm-2025-aes")[0..16]`.
        
    2. `nonce_base = HKDF(z, info="nonce-base")[0..8]`.
        
5. Proceed to steady state (Sender step 6 / Receiver step 4 onward).
