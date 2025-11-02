// src/main.rs
use rpi_secure_stream::crypto;
use rpi_secure_stream::net;
use rpi_secure_stream::video;


use rpi_secure_stream::crypto::ecdh::*;
use rpi_secure_stream::net::Aes128GcmStream;
use rpi_secure_stream::video::{Sender, Receiver};


use anyhow::Result;
use clap::Parser;
use crypto::ecdh::{generate_ephemeral, ecdh_derive};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(clap::Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    role: String, // "sender" or "receiver"

    #[arg(long, default_value = "v4l2:/dev/video0")]
    video_src: String,

    #[arg(long, default_value = "0.0.0.0:5000")]
    bind: String,

    #[arg(long, default_value = "127.0.0.1:5000")]
    leader: String,

    #[arg(long, default_value_t = 640)]
    width: i32,

    #[arg(long, default_value_t = 480)]
    height: i32,

    #[arg(long, default_value_t = 15)]
    fps: i32,

    /// Use 720p@30 (preferred requirement) quickly
    #[arg(long, default_value_t = false)]
    prefer_720p: bool,

    /// Print runtime crypto features and exit
    #[arg(long, default_value_t = false)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    if args.print_config {
        #[cfg(target_arch = "aarch64")]
        {
            use std::fs;

            let aes   = std::arch::is_aarch64_feature_detected!("aes");
            let pmull = std::arch::is_aarch64_feature_detected!("pmull");
            let sha2  = std::arch::is_aarch64_feature_detected!("sha2");

            // sha1 isn't supported by the macro on stable; detect via /proc/cpuinfo
            let sha1 = fs::read_to_string("/proc/cpuinfo")
                .map(|s| s.contains(" sha1"))
                .unwrap_or(false);

            eprintln!(
                "ARMv8 Crypto Extensions — AES:{aes} PMULL:{pmull} SHA1:{sha1} SHA2:{sha2}"
            );
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            eprintln!("(Not ARMv8)");
        }
        return Ok(());
    }


    if args.prefer_720p {
        args.width = 1280;
        args.height = 720;
        args.fps = 30;
    }

    // ECDH derive a stream key + nonce base (quick demo; replace with your full handshake)
    let (my_sec, my_pub) = generate_ephemeral();
    let (_peer_sec, peer_pub) = generate_ephemeral(); // loopback demo for now
    let mut salt = [0u8; 32]; OsRng.fill_bytes(&mut salt);
    let ctx = b"ECE4301-midterm-2025";

    let d = ecdh_derive(&my_sec, &peer_pub, &salt, ctx)?;
    let key = d.aes_key;
    let nonce_base = d.nonce_base;

    match args.role.as_str() {
        "sender" => {
            let device = args.video_src.strip_prefix("v4l2:").unwrap_or("/dev/video0");
            let (pipeline, sink) = video::make_sender_pipeline(device, args.width, args.height, args.fps)?;
            drop(pipeline); // owned by sink parent; kept alive
            let aead = Aes128GcmStream::new(key, nonce_base)?;   // was aead_stream::Aes128GcmStream
            let app  = Sender::new(aead, sink, args.width, args.height, args.fps); // was sender::Sender
            app.run(&args.leader).await?;
        }
        "receiver" => {
            let (pipeline, src) = video::make_receiver_pipeline(args.width, args.height, args.fps)?;
            drop(pipeline);
            let aead = Aes128GcmStream::new(key, nonce_base)?;
            let app  = Receiver::new(aead, src, args.width, args.height); // was receiver::Receiver
            app.run(&args.bind).await?;
        }
        _ => eprintln!("--role must be sender or receiver"),
    }
    Ok(())
}
