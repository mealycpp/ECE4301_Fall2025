#!/usr/bin/env bash
set -euo pipefail

### --- EDITABLE DEFAULTS ---
REPO_URL="${REPO_URL:-https://github.com/mealycpp/ECE4301_Fall2025}"
SUBDIR="${SUBDIR:-Group A/Midterm1}"            # path inside repo (with space)
BRANCH="${BRANCH:-main}"
BIN_NAME="${BIN_NAME:-rpi-secure-stream}"       # set to your actual binary name
LEADER_HOSTNAME="${LEADER_HOSTNAME:-pi-leader}"
BIND_ADDR="${BIND_ADDR:-0.0.0.0:5000}"
MEMBERS_FILE="/etc/rpisec/members.txt"
CSV_DIR="/var/log/rpisec"
VIDEO_SRC="${VIDEO_SRC:-v4l2:/dev/video0}"      # USB camera via V4L2
MECH="${MECH:-ecdh}"                            # ecdh|rsa for pairwise channels
SERVICE_ENABLE="${SERVICE_ENABLE:-yes}"
### -------------------------

echo "[1/9] APT deps (Rust/GStreamer/SSL)"
sudo apt-get update
sudo apt-get install -y \
  clang pkg-config libssl-dev git curl \
  gstreamer1.0-tools gstreamer1.0-libav \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
  gstreamer1.0-gl

echo "[2/9] Hostname, SSH, NTP"
if [[ "$(hostname)" != "$LEADER_HOSTNAME" ]]; then
  echo "$LEADER_HOSTNAME" | sudo tee /etc/hostname >/dev/null
  sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$LEADER_HOSTNAME/g" /etc/hosts || true
fi
sudo systemctl enable --now ssh
sudo timedatectl set-ntp true

echo "[3/9] Rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi
rustup default stable

echo "[4/9] Checkout repo"
sudo mkdir -p /opt/rpisec && sudo chown -R "$USER":"$USER" /opt/rpisec
cd /opt/rpisec
if [[ ! -d ECE4301_Fall2025 ]]; then
  git clone --branch "$BRANCH" "$REPO_URL" ECE4301_Fall2025
fi
cd ECE4301_Fall2025
git fetch --all --tags
git checkout "$BRANCH"
WS_DIR="/opt/rpisec/ECE4301_Fall2025/$SUBDIR"

echo "[5/9] Build with ARMv8 CE"
mkdir -p "$WS_DIR/.cargo"
cat > "$WS_DIR/.cargo/config.toml" <<'EOF'
[build]
rustflags = ["-C","target-cpu=native"]
EOF
RUSTFLAGS="-C target-cpu=native" cargo build --manifest-path "$WS_DIR/Cargo.toml" --release

BIN_PATH="$(dirname "$WS_DIR")/target/release/$BIN_NAME"
if [[ ! -x "$BIN_PATH" ]]; then
  # fallback if target is inside subdir: try local target
  BIN_PATH="$WS_DIR/target/release/$BIN_NAME"
fi
if [[ ! -x "$BIN_PATH" ]]; then
  echo "ERROR: Binary '$BIN_NAME' not found. Set BIN_NAME=... and rebuild."; exit 1
fi

echo "[6/9] Members file & CSV dir"
sudo mkdir -p "$(dirname "$MEMBERS_FILE")" "$CSV_DIR"
sudo touch "$MEMBERS_FILE"
sudo chown -R "$USER":"$USER" /etc/rpisec "$CSV_DIR" || true
# placeholder members (edit with actual listener IPs)
if ! grep -q ":" "$MEMBERS_FILE" 2>/dev/null; then
  cat > "$MEMBERS_FILE" <<EOF
# one <ip:port> per line
192.168.1.21:5001
192.168.1.22:5001
192.168.1.23:5001
EOF
fi

echo "[7/9] Env file"
sudo tee /etc/rpisec/env >/dev/null <<EOF
ROLE=leader
MECH=$MECH
BIND=$BIND_ADDR
LEADER=
MEMBERS_FILE=$MEMBERS_FILE
VIDEO_SRC=$VIDEO_SRC
CSV_DIR=$CSV_DIR
BIN=$BIN_PATH
EXTRA_ARGS=--rekey-interval 600
EOF

echo "[8/9] systemd unit"
sudo tee /etc/systemd/system/rpisec.service >/dev/null <<'EOF'
[Unit]
Description=RPi Secure Stream (Leader KEM)
After=network-online.target time-sync.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/rpisec/env
ExecStartPre=/bin/sh -c 'grep -m1 -i features /proc/cpuinfo || true'
ExecStartPre=/bin/sh -c 'echo "Expect ARMv8 CE: aes pmull sha1 sha2"; true'
ExecStart=${BIN} \
  --role=${ROLE} \
  --mech=${MECH} \
  --bind=${BIND} \
  --members-file=${MEMBERS_FILE} \
  --video-src=${VIDEO_SRC} \
  --log-csv-dir=${CSV_DIR} \
  ${EXTRA_ARGS}
Restart=on-failure
RestartSec=2
User=pi
WorkingDirectory=/opt/rpisec
EOF

echo "[9/9] Enable service?"
if [[ "$SERVICE_ENABLE" == "yes" ]]; then
  sudo systemctl daemon-reload
  sudo systemctl enable --now rpisec.service
  systemctl status rpisec.service --no-pager || true
else
  echo "Service created but not enabled."
fi

echo "Leader setup complete."




#Save as setup_leader.sh, then:
#chmod +x setup_leader.sh && sudo ./setup_leader.sh