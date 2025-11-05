# ECE4301-Midterm: Secure Video Streaming using Raspberry Pi 5 

### 1. Setup Steps ###

#### Install Packages ####

    sudo apt install libx264-dev libjpeg-dev
    sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-ugly gstreamer1.0-tools gstreamer1.0-gl gstreamer1.0-gtk3
    sudo apt install clang pkg-config libssl-dev gstreamer1.0-libav   gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad

#### Hardware Acceleration #### 

With hardware acceleration:

    RUSTFLAGS="-C target-cpu=native" cargo build --release

Without hardware acceleration:

    cargo build --release

### 2. Dependencies ###

System dependencies: `libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-ugly gstreamer1.0-tools gstreamer1.0-gl gstreamer1.0-gtk3 clang pkg-config libssl-dev gstreamer1.0-libav gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad`

Program Dependencies: `aes-gcm, bytes, csv, getrandom, gobject-sys, gstreamer, gstreamer-app, hkdf, p256, rand, rsa, sha2, sysinfo, clap, fstrings`


### 3. Run Commands ###

Sender example (RSA):

    ./ECE4301-midterm --mode sender --mech rsa --host <receiver-ip> --port 1234

Receiver example (ECDH):

    ./ECE4301-midterm --mode receiver --mech ecdh --host <sender-ip> --port 1234


### 4. Network Diagram ###

```
        ┌───────────────────────┐
        │       Sender Pi       │
        │ (RSA/ECDH Handshake + │
        │ AES-GCM Encryption)   │
        └────────────┬──────────┘
                     │  TCP Stream
                     ▼
        ┌───────────────────────┐
        │      Receiver Pi      │
        │ (Decrypt + Display)   │
        └───────────────────────┘

```

