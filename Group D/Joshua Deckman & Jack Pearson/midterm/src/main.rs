/*
 * NOTES:
 * Packet format:
 * [u8 start_byte][u8 packet_type][u32 length_of_data][data][[u8;17] packet_time][u8 stop_byte]
 *
 * Packet types:
 * - A general, encrypted data packet:
 * - An unencrypted public key packet
 * - An encrypted session key packet
 * - A rekey request packet or rekey initiation packet
 */

mod video;

// AES
use aes_gcm::aead::Payload;
use aes_gcm::aes::cipher::consts::{B0, B1};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use aes_gcm::aes::cipher::typenum::{UInt, UTerm};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit}};

use clap::{Parser, ValueEnum, arg};
// Elliptic Curve
use p256::ecdh::EphemeralSecret;
// use p256::elliptic_curve::ecdh::EphemeralSecret; // Use this when we need to use ECDH
use p256::elliptic_curve::PublicKey;
use p256::{EncodedPoint, NistP256};
use hkdf::Hkdf;

// RSA
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::der::{Decode, Encode};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rand::rngs::OsRng;

// Misc.
use sha2::Sha256;
use rand::RngCore;
use std::fmt::Debug;
use std::fs::File;
use std::{env, thread};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::SocketAddr;
use std::sync::OnceLock;

#[macro_use]
extern crate fstrings;

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};


const START_BYTE: u8 = 0x05;
const STOP_BYTE: u8 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq)]
enum CryptoPacketType {
    General = 0x00,
    PublicKey = 0x01,
    SessionKey = 0x02,
    RekeyRequest = 0x03,
}

#[derive(Debug, Clone)]
struct CryptoPacket {
    packet_type: CryptoPacketType,
    data: Vec<u8>,
    packet_time: SystemTime,
}

impl CryptoPacket {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized_packet: Vec<u8> = Vec::new();

        // Add the start byte.
        serialized_packet.push(START_BYTE);

        // Add the packet type.
        serialized_packet.push(self.packet_type as u8);

        // Add the length of the data.
        serialized_packet.extend_from_slice(&(self.data.len() as u32).to_be_bytes());

        // Add the data.
        serialized_packet.extend_from_slice(&self.data);

        // Add the system time.
        let mut st = vec![];
        self.packet_time.encode_to_vec(&mut st).unwrap();
        serialized_packet.extend_from_slice(&st);

        // Add the stop byte.
        serialized_packet.push(STOP_BYTE);

        return serialized_packet;
    }
}


fn get_input_data(camera: &video::Camera) -> Vec<u8> {
    // When the program generates data that needs to be transmitted to the client
    // (such as a video frame), the tx_loop() function calles this function to read that data.
    #[cfg(debug_assertions)] {
        println!("Type input: ");
        // Get user input from console
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        return input.as_bytes().to_vec();
    }
    let vec = camera.pull();
    #[cfg(debug_assertions)] {
        println!("Grabbed input data");
    }
    vec
}

fn consume_plaintext(gui: &video::GUI, data: Vec<u8>) {
    // After data is received from a client and decrypted, then data is passed to this function.
    #[cfg(debug_assertions)] {
        println!("Consuming plaintext: {data:?}");
    }

    gui.push(data);
}

fn get_packet_from_network(tcp_stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    // This function flushes all data in the network buffer until it receives a start byte.
    // Once it receives a start byte, then it reads the next bytes for the packet type and size of the data portion.
    // It then reads the data portion of the packet and the final stop byte.
    // It then returns the packet as a Vec<u8>.

    let mut packet: Vec<u8> = vec![];
    let mut next_byte = [0u8; 1];
    let mut data_length: u32 = 0;
    let mut done = false;
    let mut state: u8 = 0;

    while !done {

        if state == 0 {
            // Read the next byte.
            if tcp_stream.read_exact(&mut next_byte).is_err() {
                return Err("Error reading from network");
            }

            // If the byte that was read is a start byte, then push it onto our packet.
            // Otherwise, flush it.
            if next_byte[0] == START_BYTE {
                packet.push(next_byte[0]);
                state = 1;
            }
        }

        if state == 1 {
            for _ in 0..5 {
                if tcp_stream.read_exact(&mut next_byte).is_err() {
                    return Err("Error reading from network");
                }
                packet.push(next_byte[0]);
            }

            state = 2;

            // Compute the size of the data portion.
            data_length = u32::from_be_bytes(packet[2..6].try_into().unwrap());
        }

        if state == 2 {
            for _ in 0..data_length {
                if tcp_stream.read_exact(&mut next_byte).is_err() {
                    return Err("Error reading from network");
                }
                packet.push(next_byte[0]);
            }

            state = 3;
        }

        if state == 3 {
            let mut packet_time= [0u8; 17];
            if tcp_stream.read_exact(&mut packet_time).is_err() {
                return Err("Error reading from network");
            }

            packet.append(&mut packet_time.to_vec());
            state = 4;
        }

        if state == 4 {
            if tcp_stream.read_exact(&mut next_byte).is_err() {
                return Err("Error reading from network");
            }

            // This byte should be the stop byte. For now we will just push it without asking questions.
            packet.push(next_byte[0]);
            state = 0;
            done = true;
            // if next_byte[0] == STOP_BYTE {
            //     packet.push(next_byte[0]);
            //     done = true;
            // }
        }
    }

    return Ok(packet);
}

fn receive_public_key(tcp_stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    // Flush all data until we receive a public key packet. Note: we may want to implement a timeout feature.
    // This function is supposed to return the data transmitted by the function transmit_public_key(). Currently, this is supposed to work for both ECDH and RSA.

    let done = false;

    while !done {
        match receive_data(tcp_stream) {
            Ok(packet) => {
                if packet.packet_type == CryptoPacketType::PublicKey {
                    return Ok(packet.data);
                }
            },

            Err(e) => {return Err(e)},
        }
    }

    return Err("Failed to acquire public key");
}

fn receive_session_key(tcp_stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    // Flush all data until we receive a session key packet. Note: we may want to implement a timeout feature.
    // This is supposed to return the session key that is transmitted by the function transmit_session_key(). This will be encrypted.
    let done = false;

    while !done {
        match receive_data(tcp_stream) {
            Ok(packet) => {
                if packet.packet_type == CryptoPacketType::SessionKey {
                    return Ok(packet.data);
                }
            },

            Err(e) => {return Err(e)},
        }
    }

    return Err("Failed to acquire session key");
}

fn transmit_data(data_packet: CryptoPacket, tcp_stream: &mut TcpStream) {
    // Take a CryptoPacket object and serialize it for transmission.
    let serialized_packet = data_packet.serialize();
    // push_packet_to_network(serialized_packet.clone());
    tcp_stream.write_all(&serialized_packet).unwrap();
}

fn receive_data(tcp_stream: &mut TcpStream) -> Result<CryptoPacket, &'static str> {
    // Receive a data packet.
    let serialized_packet: Vec<u8>;

    match get_packet_from_network(tcp_stream) {
        Ok(p) => {serialized_packet = p},
        Err(e) => {return Err(e)},
    }

    let start_byte: u8 = serialized_packet[0];
    let packet_type: u8 = serialized_packet[1];
    let length_of_data: u32 = u32::from_be_bytes(serialized_packet[2..6].try_into().unwrap());
    let data: Vec<u8> = serialized_packet[6..6+length_of_data as usize].to_vec();
    let system_time: Vec<u8> = serialized_packet[6+length_of_data as usize..6+length_of_data as usize + 17].to_vec();
    let stop_byte: u8 = serialized_packet[6+length_of_data as usize + 17];

    let packet_start = SystemTime::from_der(&system_time).unwrap();

    let packet = CryptoPacket {
        packet_type: match packet_type {
            0x00 => CryptoPacketType::General,
            0x01 => CryptoPacketType::PublicKey,
            0x02 => CryptoPacketType::SessionKey,
            0x03 => CryptoPacketType::RekeyRequest,
            _ => panic!("Invalid packet type"),
        },
        data: data,
        packet_time: packet_start,
    };

    return Ok(packet);
}

fn transmit_public_key(key: Vec<u8>, tcp_stream: &mut TcpStream) {
    // Transmit an unencrypted public key via either ECDH or RSA. (Perhaps this should be split into two functions--one for ECDH and one for RSA.)
    let packet = CryptoPacket {
        packet_type: CryptoPacketType::PublicKey,
        data: key,
        packet_time: SystemTime::now(),
    };

    #[cfg(debug_assertions)] {
        println!("Transmitting public key packet: {:?}", packet.serialize());
    }
    transmit_data(packet, tcp_stream);
}

fn transmit_rekey_request(tcp_stream: &mut TcpStream) {
    // This function is supposed to send a data packet to the follower(s) to tell it/them to enter the on_rsa_rekey() method.
    #[cfg(debug_assertions)] {
        println!("Initiating rekey process...");
    }

    let packet = CryptoPacket {
        packet_type: CryptoPacketType::RekeyRequest,
        data: vec![],
        packet_time: SystemTime::now(),
    };

    #[cfg(debug_assertions)] {
        println!("Transmitting rekey request: {:?}", packet.serialize());
    }
    transmit_data(packet, tcp_stream);
}

fn transmit_session_key(key: Vec<u8>, tcp_stream: &mut TcpStream) {
    // Transmit an encrypted session key. This probably should NOT be replaced with the transmit_data() function, because
    // this message should probably be wrapped differently from a general data packet.
    let packet = CryptoPacket {
        packet_type: CryptoPacketType::SessionKey,
        data: key,
        packet_time: SystemTime::now(),
    };

    #[cfg(debug_assertions)] {
        println!("Transmitting session key packet: {:?}", packet.serialize());
    }
    transmit_data(packet, tcp_stream);
}

fn hkdf_rekey(tcp_stream: &mut TcpStream, csv_file: &mut Option<File>) -> Result<[u8; 16], &'static str> {
    let rekey_start = SystemTime::now();

    // Generate private and public keys
    let private_key = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let public_key = PublicKey::from(&private_key);
    let public_key_bytes = EncodedPoint::from(public_key).as_bytes().to_vec();
    let bytes_tx = public_key_bytes.len();
    transmit_public_key(public_key_bytes, tcp_stream);

    // Receive the peer's public key.
    let peer_public_key_bytes: Vec<u8>;
    match receive_public_key(tcp_stream) {
        Ok(p) => { peer_public_key_bytes = p; },
        Err(e) => { return Err(e); },
    }

    // HKDH exchange
    let peer_public_key = PublicKey::from_sec1_bytes(&peer_public_key_bytes).unwrap();
    let shared = private_key.diffie_hellman(&peer_public_key);
    let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
    let mut aes_key = [0u8; 16];
    hk.expand(b"ECE4301-midterm-2025-aes", &mut aes_key).unwrap();

    let rekey_time = rekey_start.elapsed().unwrap().as_millis();
    let start_time = rekey_start.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let end_time_object = SystemTime::now();
    let end_time = end_time_object.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let bytes_rx = peer_public_key_bytes.len();
    let csv_line = f!("{start_time},{end_time},{rekey_time},ECDH,{bytes_tx},{bytes_rx},\n");

    if !csv_file.is_none() {
        match csv_file.as_mut().unwrap().write_all(csv_line.as_bytes()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    return Ok(aes_key);
}

fn leader_rsa_rekey(tcp_stream: &mut TcpStream) -> Result<[u8; 16], &'static str> {
    transmit_rekey_request(tcp_stream);

    let mut rng = OsRng;

    // Get the peer's public key.
    let peer_public_key_bytes: Vec<u8>;

    match receive_public_key(tcp_stream) {
        Ok(p) => {peer_public_key_bytes = p;},
        Err(e) => {return Err(e)},
    }

    // Convert the peer's public key bytes to a PublicKey object.
    let peer_public_key = RsaPublicKey::from_pkcs1_der(&peer_public_key_bytes).expect("Failed to convert public key bytes into public key object");

    // Generate a session key.
    let mut session_key = [0u8; 16];
    rng.fill_bytes(&mut session_key);

    // Encrypt with the peer's public key.
    let wrapped_session_key = peer_public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &session_key).expect("Failed to encrypt session key");

    // Transmit the wrapped session key.
    transmit_session_key(wrapped_session_key, tcp_stream);

    return Ok(session_key);
}

fn follower_rsa_rekey(tcp_stream: &mut TcpStream, csv_file: &mut Option<File>) -> Result<[u8; 16], &'static str> {
    let rekey_start = SystemTime::now();

    // Generate a new private and public key pair.
    let mut rng = OsRng;
    let bits = 3072;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    // Prepare the byte array to send our public key.
    let public_key_bytes = public_key.to_pkcs1_der().unwrap().to_der().unwrap();

    let bytes_tx = public_key_bytes.len();

    transmit_public_key(public_key_bytes, tcp_stream);

    // Receive the session key.
    let wrapped_session_key: Vec<u8>;
    match receive_session_key(tcp_stream) {
        Ok(k) => { wrapped_session_key = k; },
        Err(e) => {return Err(e);}
    }

    let session_key_bytes: Vec<u8> = private_key.decrypt(Oaep::new::<Sha256>(), &wrapped_session_key).expect("Failed to decrypt session key.");
    let session_key: [u8; 16] = session_key_bytes.as_slice().try_into().expect("Failed to convert session key bytes into session key array.");

    let rekey_time = rekey_start.elapsed().unwrap().as_millis();
    let start_time = rekey_start.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let end_time_object = SystemTime::now();
    let end_time = end_time_object.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let bytes_rx = wrapped_session_key.len();
    let csv_line = f!("{start_time},{end_time},{rekey_time},RSA,{bytes_tx},{bytes_rx},\n");

    if !csv_file.is_none() {
        match csv_file.as_mut().unwrap().write_all(csv_line.as_bytes()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    return Ok(session_key);
}

fn new_nonce(ctr: u32) -> [u8; 12] {
    let mut nonce_base = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_base);
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_base);
    nonce[8..].copy_from_slice(&ctr.to_be_bytes());

    return nonce;
}

fn next_nonce(&current_nonce: &[u8; 12]) -> [u8; 12] {
    // Extract the counter value.
    let mut ctr = u32::from_be_bytes(current_nonce[8..].try_into().unwrap());

    // Increment the counter with wrapping_add.
    ctr = ctr.wrapping_add(1);

    // Copy over the current nonce and change its counter section.
    let mut next_nonce = current_nonce.clone();
    next_nonce[8..].copy_from_slice(&ctr.to_be_bytes());

    return next_nonce;
}

fn tx_loop(tcp_stream: &mut TcpStream) {
    // Start by acquiring an AES key.
    let mut aes_key: [u8; 16];
    if *K_GEN.get().unwrap() == Mech::Rsa {
        match leader_rsa_rekey(tcp_stream) {
            Ok(k) => {aes_key = k},
            Err(e) => { println!("Error acquiring session key: {e}"); return; }
        }
    }
    else {
        match hkdf_rekey(tcp_stream, &mut None) {
            Ok(k) => {aes_key = k},
            Err(e) => { println!("Error acquiring HKDF shared key: {e}"); return; }
        }
    }

    // Set up the cipher
    let mut cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();

    // Generate a nonce.
    let mut current_nonce = new_nonce(0);

    let mut frame_number: u32 = 0;
    let mut last_rekey = Instant::now();

    let mut done = false;
    let mut rekey = false;

    let camera = video::get_camera();

    while !done {
        // Determine if we should rekey.
        if rekey {
            println!("Rekeying...");

            // Generate a new nonce, reset the counter and timer.
            frame_number = 0;
            last_rekey = Instant::now();
            current_nonce = new_nonce(0);

            // let new_aes_key: [u8; 16];

            if *K_GEN.get().unwrap() == Mech::Rsa {

                match leader_rsa_rekey(tcp_stream) {
                    Ok(k) => {aes_key = k},
                    Err(e) => { println!("Error on leader rekeying with RSA: {e}"); done = true; continue; }
                }
            }
            else {
                transmit_rekey_request(tcp_stream);

                match hkdf_rekey(tcp_stream, &mut None) {
                    Ok(k) => { aes_key = k; },
                    Err(e) => { println!("Error rekeying with HKDF: {e}"); done = true; continue; }
                }
            }

            cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();

            rekey = false;
            continue;
        }

        // Attempt to get the next input data.
        let input_data = get_input_data(&camera);

        // Extract the frame number (counter value) from the current nonce.
        let current_frame = current_nonce[8..12].to_vec();

        // Wrap the plaintext and the current nonce value into a Payload struct.
        let plain_payload = Payload { msg: &input_data, aad: &current_frame };

        // Get the ciphertext via AES-GCM encryption.
        let ciphertext = cipher.encrypt((&current_nonce).into(), plain_payload).unwrap();

        // Assemble the data payload.
        let encrypted_payload = [current_nonce.as_ref(), ciphertext.as_ref()].concat();

        let data_packet = CryptoPacket {
            packet_type: CryptoPacketType::General,
            data: encrypted_payload,
            packet_time: SystemTime::now(),
        };

        // Transmit the payload.
        transmit_data(data_packet, tcp_stream);

        // Get the next nonce value.
        current_nonce = next_nonce(&current_nonce);

        // Increment the current frame number.
        frame_number = frame_number + 1;

        // If 2^20 frames have been sent or 10 minutes have passed, then rekey.
        if (frame_number >= 1048576) || (last_rekey.elapsed().as_secs() >= (10 * 60)) {
            rekey = true;
        }
    }

    aes_key = [0u8; 16];
    tcp_stream.shutdown(Shutdown::Both).expect("Failed to shut down server");
}

fn rx_loop(tcp_stream: &mut TcpStream) {
    let mut csv_file = None;
    match File::create("steady_stream.csv") {
        Ok(f) => { csv_file = Some(f); },
        Err(_) => {},
    }

    let csv_line_start = f!("Transmit Start Time (since epoch as ms),Throughput (bytes per second),Latency (ms),Frames per Second,CPU Usage (%),Memory Used (bytes)\n");

    if !csv_file.is_none() {
        match csv_file.as_mut().unwrap().write_all(csv_line_start.as_bytes()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    let mut hs_file: Option<File> = None;

    let mut aes_key: [u8; 16];

    if *K_GEN.get().unwrap() == Mech::Rsa {
        match File::create("handshake_rsa.csv") {
            Ok(f) => { hs_file = Some(f); },
            Err(_) => {},
        }

        let hs_csv_line_start = f!("Rekey Start Time (since epoch),End Time,Rekey Time (ms),Rekey Mechanism,Bytes Transmitted,Bytes Received\n");

        if !hs_file.is_none() {
            match hs_file.as_mut().unwrap().write_all(hs_csv_line_start.as_bytes()) {
                Ok(_) => {},
                Err(_) => {},
            }
        }

        match follower_rsa_rekey(tcp_stream, &mut hs_file) {
            Ok(k) => { aes_key = k; },
            Err(e) => { println!("Error acquiring session key (follower): {e}"); return; }
        }
    }
    else {
        match File::create("handshake_ecdh.csv") {
            Ok(f) => { hs_file = Some(f); },
            Err(_) => {},
        }

        let hs_csv_line_start = f!("Rekey Start Time (since epoch),End Time,Rekey Time (ms),Rekey Mechanism,Bytes Transmitted,Bytes Received\n");

        if !hs_file.is_none() {
            match hs_file.as_mut().unwrap().write_all(hs_csv_line_start.as_bytes()) {
                Ok(_) => {},
                Err(_) => {},
            }
        }

        match hkdf_rekey(tcp_stream, &mut hs_file) {
            Ok(k) => { aes_key = k; },
            Err(e) => { println!("Error acquiring HKDF shared key: {e}"); return; }
        }
    }

    // Set up the AES-GCM cipher object with the shared AES key.
    let mut cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();

    // Set up the loop to receive data.
    let mut done = false;

    let gui = video::get_gui();

    while !done {
        let received_packet: CryptoPacket;

        match receive_data(tcp_stream) {
            Ok(packet) => {received_packet = packet},
            Err(e) => {println!("Error: {:?}", e); break;}
        }

        #[cfg(debug_assertions)] {
            println!("Received packet: {:?}", received_packet.serialize());
        }

        // If the packet is a general packet, then decrypt it.
        // If the packet is a rekey request, then update the cipher with a new AES key via the rekey protocol.
        if received_packet.packet_type == CryptoPacketType::RekeyRequest {
            println!("Received rekey request...");
            // let new_aes_key: [u8; 16];

            if *K_GEN.get().unwrap() == Mech::Rsa {
                match follower_rsa_rekey(tcp_stream, &mut hs_file) {
                    Ok(k) => { aes_key = k; },
                    Err(e) => { println!("Error rekeying with RSA (follower): {e}"); done = true; continue; }
                }
            }
            else {
                match hkdf_rekey(tcp_stream, &mut hs_file) {
                    Ok(k) => { aes_key = k; },
                    Err(e) => { println!("Error rekeying with HKDF: {e}"); done = true; continue; }
                }
            }

            cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();
        }
        else if received_packet.packet_type == CryptoPacketType::General {
            // The packet it a general packet.
            let received_payload = received_packet.data;
            let number_of_bytes = received_payload.len();
            
            // Calculate the latency.
            let packet_start_time = received_packet.packet_time.duration_since(UNIX_EPOCH).unwrap().as_millis();
            let latency = received_packet.packet_time.elapsed().unwrap().as_millis();

            // Extract the nonce from the payload. The nonce takes up the first 12 bytes.
            let nonce: &GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>> = (&received_payload.as_slice()[..12]).try_into().unwrap();
            #[cfg(debug_assertions)] {
                println!("Received nonce: {:?}", nonce);
            }

            // Extract the counter part of the nonce (called "frame" here), which is the last four bytes of the nonce.
            let frame = nonce[8..12].to_vec();
            #[cfg(debug_assertions)] {
                println!("Received frame: {:?}", frame);
            }

            // Extract the ciphertext from the rest of the payload.
            let ciphertext = received_payload[12..].to_vec();
            #[cfg(debug_assertions)] {
                println!("Received ciphertext: {:?}", ciphertext);
            }

            // Wrap the frame number and the ciphertext into a Payload struct for decryption.
            let encrypted_payload = Payload { msg: &ciphertext, aad: &frame};

            // Decrypt the message.
            let decrypted = cipher.decrypt(nonce, encrypted_payload).unwrap();
            #[cfg(debug_assertions)] {
                println!("Decrypted: {:?}", decrypted);
            }

            // Send the message off to the rest of the program.
            consume_plaintext(&gui, decrypted);

            // let elapsed_time = packet_start_time.elapsed().as_micros();
            let Bps = 1000 as f32 * (number_of_bytes as f32 / latency as f32);
            let fps = gui.get_fps();
            let fps_str = match fps {
                Some(fps) => fps.to_string(),
                None => "".to_string()
            };
            let sys = sysinfo::System::new_all();
            let cpu_pct = sys.global_cpu_usage();
            let mem_used_bytes = sys.used_memory();

            let csv_line = f!("{packet_start_time},{Bps},{latency},{fps_str},{cpu_pct},{mem_used_bytes}\n");

            if !csv_file.is_none() {
                match csv_file.as_mut().unwrap().write_all(csv_line.as_bytes()) {
                    Ok(_) => {},
                    Err(_) => {},
                }
            }
        }
    }

    aes_key = [0u8; 16];
}

static K_GEN: OnceLock<Mech> = OnceLock::new();

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Mode {
    Sender,
    Receiver,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Mech {
    Rsa,
    Ecdh,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long, value_enum)]
    mech: Mech,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    print_config: bool,
}



fn main() {
    gstreamer::init().unwrap();

    let args = Args::parse();

    K_GEN.set(args.mech).ok();

    println!("Starting program...");
    if args.print_config {
        log_arm_crypto_support();
    }

    if args.mode == Mode::Sender {
        // Server mode
        let tcp_listener = TcpListener::bind((args.host, args.port)).expect("Failed to bind to address");

        // Wait for a connections.
        println!("Waiting for client to connect...");
        for stream in tcp_listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    println!("Accepted connection. Continuing...");
                    thread::spawn(move || { tx_loop(&mut stream); });
                },
                Err(e) => {
                    println!("Failed to accept connection: {e}");
                }
            }
        }
    }
    else if args.mode == Mode::Receiver {
        // Client mode
        let mut tcp_stream = TcpStream::connect((args.host, args.port)).expect("Could not connect to server");

        // Start RX loop.
        rx_loop(&mut tcp_stream);

        // Shutdown the socket.
        tcp_stream.shutdown(Shutdown::Both).expect("Failed to shut down client TCP stream");
    }
}

fn log_arm_crypto_support() {
    #[cfg(any (target_arch = "aarch64" , target_arch = "arm64ec"))]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        eprintln!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
    }
}
