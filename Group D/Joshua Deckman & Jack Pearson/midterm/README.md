# ECE4301-midterm # 

### Setup Steps ###

#### Install Necessary Packages ####

    sudo apt install libx264-dev libjpeg-dev    # Required dependencies
    sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-ugly gstreamer1.0-tools gstreamer1.0-gl gstreamer1.0-gtk3
    sudo apt install clang pkg-config libssl-dev gstreamer1.0-libav   gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad

#### Building the Application #### 

To build the project with hardware acceleration:

    RUSTFLAGS="-C target-cpu=native" cargo build --release

To build the project without hardware acceleration:

    cargo build --release

Note that debug builds built with `cargo build` will produce a program without video transmission for the sake of debugging the encryption system.

### Dependencies ###

System dependencies: `libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev`

Program Dependencies: `aes-gcm, bytes, csv, getrandom, gobject-sys, gstreamer, gstreamer-app, hkdf, p256, rand, rsa, sha2, sysinfo, clap, fstrings`


### Run Commands ###

Sender with RSA rekeying example:

    ./ECE4301-midterm --mode sender --mech rsa --host 127.0.0.1 --port 1234

Receiver with ECDH rekeying example:

    ./ECE4301-midterm --mode receiver --mech ecdh --host 127.0.0.1 --port 1234


### Network Diagram ###

![Network Diagram](./20251031_214802.jpg "Network Diagram")

