# rpi-secure-stream (ECE4301)


Two-node secure H.264 video stream on Raspberry Pi 5 using AES-128-GCM, with RSA and ECDH handshakes, Wayland/WayVNC-friendly sinks, and measurement hooks.


## Build


sudo apt update && sudo apt install -y clang pkg-config libssl-dev \
gstreamer1.0-tools gstreamer1.0-libav \
gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-gl


cargo build --release


## Run


# Receiver (Wayland desktop via WayVNC is fine):
./target/release/rpi-secure-stream --mode receiver --port 5000


# Sender (C922 on /dev/video0):
./target/release/rpi-secure-stream --mode sender --host <receiver-ip> --port 5000 --mech ecdh


# RSA path:
./target/release/rpi-secure-stream --mode sender --host <receiver-ip> --port 5000 --mech rsa


## Bench (HW accel proof)
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin bench_aesgcm
RUSTFLAGS='-C target-feature=-aes,-pmull' cargo run --release --bin bench_aesgcm