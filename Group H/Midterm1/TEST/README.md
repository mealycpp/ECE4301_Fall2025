# rpi-secure-stream (ECE4301 Midterm)

Secure, real‑time H.264 video streaming between **two Raspberry Pi 5** nodes using **AES‑128‑GCM** with **RSA** and **ECDH** handshakes. Rust‑first implementation with GStreamer capture/display, optional rekey, and hooks for measurements and hardware‑acceleration proof.

---

## 0) TL;DR — run it
**Receiver (on the Pi that shows the window):**
```bash
./target/release/rpi-secure-stream --mode receiver --port 5000
```
**Sender:**
```bash
./target/release/rpi-secure-stream --mode sender --host <RECEIVER_IP> --port 5000 --mech ecdh
# also try: --mech rsa
```
If the window doesn’t appear over WayVNC, use **software decode + GL sink** (already set in code) or swap last element to `glimagesink sync=false`.

---

## 1) Requirements
**Hardware**
- 2× Raspberry Pi 5 (wired **Ethernet recommended**)
- USB webcam (e.g., Logitech C922) on the **sender** Pi
- Optional: INA219/INA226 power sensor or USB‑C inline watt meter

**OS & toolchain**
- Raspberry Pi OS 64‑bit (Bookworm)
- Rust (stable): `rustup` / `cargo`
- GStreamer packages:
  ```bash
  sudo apt update
  sudo apt install -y clang pkg-config libssl-dev gstreamer1.0-tools gstreamer1.0-libav \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly gstreamer1.0-gl
  ```
- Python (for plotting): `python3-numpy python3-matplotlib` (optional)

**Rust deps (Cargo.toml)**
```
aes-gcm = { version = "0.10", features = ["aes"] }
hkdf = "0.12"
sha2 = "0.10"
rand = "0.8"
p256 = { version = "0.13", features = ["ecdh"] }
rsa = "0.9.8"           # no extra features
serde = { version = "1", features = ["derive"] }
bincode = "1"
tokio = { version = "1", features = ["full"] }
bytes = "1"
anyhow = "1"
chrono = { version = "0.4", features = ["clock"] }
gstreamer = "0.22"
gstreamer-app = "0.22"
```

**CPU features (recommended):** build with native flags:
```toml
# .cargo/config.toml
[build]
rustflags = ["-C","target-cpu=native"]
```

---

## 2) Repo layout
```
rpi-secure-stream/
├─ Cargo.toml
├─ .cargo/config.toml
├─ src/
│  ├─ main.rs        # CLI, handshake, network, stream loop
│  ├─ video.rs       # GStreamer sender/receiver pipelines
│  ├─ aead.rs        # AES-128-GCM ctx + NonceCtr
│  ├─ session.rs     # HKDF bidirectional derivation (fixed symmetric labels)
│  └─ keying.rs      # ECDH offer helper (P-256 + salt)
└─ src/bin/
   └─ bench_aesgcm.rs  # AES-GCM throughput micro-bench
```

---

## 3) Build
On **each Pi**:
```bash
cargo build --release
```
(For max speed on Pi 5 add: `RUSTFLAGS="-C target-cpu=native"` before the command.)

---

## 4) Network setup (Ethernet strongly recommended)
**A) Both Pis on the same router/switch**
1. Plug both Pis into the router via Ethernet.
2. On the **receiver**: `ip -4 addr show dev eth0` → note IP (e.g., `192.168.0.130`).
3. Use that IP in the sender’s `--host`.

**B) Direct cable (no router)**
```bash
# Receiver
sudo ip addr add 10.0.0.1/24 dev eth0; sudo ip link set eth0 up
# Sender
sudo ip addr add 10.0.0.2/24 dev eth0; sudo ip link set eth0 up
```
Then run `--host 10.0.0.1`.

---

## 5) Run
**Receiver (Wayland desktop via WayVNC is fine):**
```bash
./target/release/rpi-secure-stream --mode receiver --port 5000
```
**Sender (C922 is typically `/dev/video0`):**
```bash
./target/release/rpi-secure-stream --mode sender --host <RECEIVER_IP> --port 5000 --mech ecdh
# try RSA too:
./target/release/rpi-secure-stream --mode sender --host <RECEIVER_IP> --port 5000 --mech rsa
```
Expected logs:
- `ARMv8 Crypto Extensions ? AES:..., PMULL:...`
- `DERIVE(sender/receiver): tx_key=... rx_key=...` (fingerprints)
- `handshake complete`
- Receiver prints `frame seq=... len=... ~X.Y ms` and a window opens.

**If the window doesn’t show:**
- The receiver pipeline uses software decode + auto sink; over WayVNC this is reliable.
- You can swap the last element to `glimagesink sync=false` in `src/video.rs` and rebuild.
- Debug run:
  ```bash
  GST_DEBUG=2,appsrc:6,h264parse:6,avdec_h264:5,autovideosink:5 \
  ./target/release/rpi-secure-stream --mode receiver --port 5000
  ```

---

## 6) Handshakes & security notes
- **ECDH (default):** both sides generate ephemeral P‑256 keys + salts; shared secret → HKDF‑SHA256 → **directional keys** using labels `SENDER->RECEIVER` / `RECEIVER->SENDER`.
- **RSA:** receiver creates ephemeral RSA‑2048, sender OAEP‑wraps `salt||prekey`; both sides HKDF as above.
- **AEAD:** AES‑128‑GCM with 96‑bit nonces (`nonce_base || counter`), AAD = frame `seq` (u64, BE). First message after handshake is `Confirm` with `seq=0`.
- **Rekey:** helpers are implemented; you can call rekey from the sender on a timer and handle `RekeyHello` on the receiver. Rekey should be seamless.

---

## 7) Measurements (what to capture for the report)
- **Latency:** receiver logs `~X.Y ms` using sender’s `ts_ns`; capture mean/p50/p95.
- **Throughput / FPS:** compute from sender bytes and receiver frames; a simple 1‑second ticker can write CSV if needed.
- **CPU/Temp (quick):** `top -d 1`, `/sys/class/thermal/thermal_zone0/temp`.

**Energy (choose one):**
- **INA219/INA226**: sample ≥10 Hz and write `data/power_samples.csv` with `ts,volts,amps,watts,phase,node_id`.
- **USB‑C meter**: log Wh before/after a 60‑s run (convert Wh→J by ×3600). Optionally type a CSV by hand.

**Plot/integrate energy:**
```bash
python3 scripts/plot_energy.py
# prints Joules and writes plots/power.png
```

---

## 8) Hardware‑acceleration proof (required)
1. Build/run on Pi 5 with native CPU:
   ```bash
   RUSTFLAGS="-C target-cpu=native" cargo run --release --bin bench_aesgcm
   ```
2. Control build without AES/PMULL:
   ```bash
   RUSTFLAGS='-C target-feature=-aes,-pmull' cargo run --release --bin bench_aesgcm
   ```
3. Record both **MB/s** and the runtime detection line `AES: true, PMULL: true` in **HW_ACCEL.md**.
4. Also include `/proc/cpuinfo` features line in the report.

---

## 9) Group extension (≥3 nodes)
Minimal leader‑distributed demo (KEM‑style):
- Start **two receivers** (e.g., different ports).
- Sender forms pairwise secure channels as usual.
- Leader (sender) samples a `group_secret` and sends it encrypted (seq=0 in each channel). Each receiver derives its stream keys from the group secret.
- Stream to both; measure energy/latency for N=3. Fit a simple model (≈ linear in N−1) and plot predicted vs measured.

> Note: The skeleton here is 1:1 sender→receiver. For a polished group demo, add a tiny control message and reuse the existing per‑direction HKDF to derive per‑connection keys from the shared `group_secret`.

---

## 10) Troubleshooting
- **“bad confirm” / Broken pipe:** make sure both Pis rebuilt with the same `session.rs` (symmetric labels), and that `Confirm` is the first encrypted message. If needed, temporarily print key fingerprints (already in code).
- **Window doesn’t show:** prefer `avdec_h264` + `autovideosink` or `glimagesink`. Don’t use `force-aspect-ratio` on `waylandsink` (not supported in your build). No `#` comments inside pipeline strings.
- **GStreamer parse errors:** use `gst::parse::launch(...)` (not `gst::launch`). Keep `video/x-h264, stream-format=byte-stream, alignment=au` caps on `appsrc`.
- **Camera path:** verify with `ls -l /dev/video*` and adjust `start_sender_pipeline("/dev/video0", ...)` if needed.

---

## 11) GitHub workflows for this project

### A) Push your local project into the repo **branch `TEST`**
```bash
cd /path/to/rpi-secure-stream
git init
printf '%s\n' 'target/' 'data/' 'plots/' '.DS_Store' > .gitignore
git add -A
git commit -m "Add rpi-secure-stream project on TEST branch"
git branch -M TEST
git remote add origin git@github.com:CalebJalapeno/ECE4301_GroupH.git
git push -u origin TEST
```

### B) Replace the **TEST/** directory on `main` with your local files
```bash
DEST="git@github.com:CalebJalapeno/ECE4301_GroupH.git"
DEST_BRANCH="main"
SRC_DIR="$HOME/rpi-secure-stream"
WORKDIR="$(mktemp -d)"; cd "$WORKDIR"

git clone "$DEST" dest && cd dest && git switch "$DEST_BRANCH"
mkdir -p TEST
rsync -av --delete --exclude='.git' --exclude='target' --exclude='data' --exclude='plots' --exclude='.DS_Store' \
  "$SRC_DIR"/ TEST/

git add TEST
git commit -m "Replace TEST/ with rpi-secure-stream contents"
git push origin "$DEST_BRANCH"
```

### C) Pull the `TEST/` directory only (sparse checkout)
```bash
git clone --filter=blob:none --no-checkout git@github.com:CalebJalapeno/ECE4301_GroupH.git
cd ECE4301_GroupH
git sparse-checkout init --cone
git sparse-checkout set TEST
git switch main   # or TEST branch if you used one
git pull
ls TEST/
```

---

## 12) What to turn in (rubric‑aligned)
- **Source** (Rust) with README and small diagrams.
- **Report (≤8 pages):** protocol diagrams, nonce handling, RSA vs ECDH timings/bytes/CPU, latency/throughput graphs, energy bars + methodology, HW‑accel proof, group demo + scaling.
- **Data/** CSVs and **Plots/**.
- **Short demo video** (≤2 min) showing encrypted stream and a rekey event.

---

## 13) License / notes
Academic use for ECE4301 midterm. Keep keys and captures private until grading is complete.

