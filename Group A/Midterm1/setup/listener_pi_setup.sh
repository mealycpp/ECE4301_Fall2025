#!/usr/bin/env bash
set -euo pipefail

### --- EDITABLE DEFAULTS ---
REPO_URL="${REPO_URL:-https://github.com/mealycpp/ECE4301_Fall2025}"
SUBDIR="${SUBDIR:-Group A/Midterm1}"
BRANCH="${BRANCH:-main}"
BIN_NAME="${BIN_NAME:-rpi-secure-stream}"
LISTENER_HOSTNAME_PREFIX="${LISTENER_HOSTNAME_PREFIX:-pi-m}"    # becomes pi-m<suffix>
LEADER_ADDR="${LEADER_ADDR:-192.168.1.20:5000}"
LISTEN_PORT="${LISTEN_PORT:-5001}"
CSV_DIR="/var/log/rpisec"
VIDEO_SRC="${VIDEO_SRC:-v4l2:/dev/video0}"
MECH="${MECH:-ecdh}"
SERVICE_ENABLE="${SERVICE_ENABLE:-yes}"
### -------------------------

echo "[1/9] APT deps"
sudo apt-get update
sudo apt-get install -y \
  clang pkg-config libssl-dev git curl \
  gstreamer1.0-tools gstreamer1.0-libav \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
  gstreamer1.0-gl

echo "[2/9] Hostname, SSH, NTP"
OCTET=$(hostname -I | awk '{print $1}' | awk -F. '{print $4}')
SUFFIX=${SUFFIX:-$(( OCTET % 10 ))}
NEW_HOST="${LISTENER_HOSTNAME_PREFIX}${SUFFIX}"
if [[ "$(hostname)" != "$NEW_HOST" ]]; then
  echo "$NEW_HOST" | sudo tee /etc/hostname >/dev/null
  sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOST/g" /etc/hosts || true
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
  BIN_PATH="$WS_DIR/target/release/$BIN_NAME"
fi
if [[ ! -x "$BIN_PATH" ]]; then
  echo "ERROR: Binary '$BIN_NAME' not found. Set BIN_NAME=... and rebuild."; exit 1
fi

echo "[6/9] CSV dir"
sudo mkdir -p "$CSV_DIR"
sudo chown -R "$USER":"$USER" "$CSV_DIR" || true

echo "[7/9] Env file"
sudo mkdir -p /etc/rpisec
sudo tee /etc/rpisec/env >/dev/null <<EOF
ROLE=member
MECH=$MECH
BIND=0.0.0.0:${LISTEN_PORT}
LEADER=$LEADER_ADDR
MEMBERS_FILE=
VIDEO_SRC=$VIDEO_SRC
CSV_DIR=$CSV_DIR
BIN=$BIN_PATH
EXTRA_ARGS=--rekey-interval 600
EOF

echo "[8/9] systemd unit"
sudo tee /etc/systemd/system/rpisec.service >/dev/null <<'EOF'
[Unit]
Description=RPi Secure Stream (Member)
After=network-online.target time-sync.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/rpisec/env
ExecStartPre=/bin/sh -c 'grep -m1 -i features /proc/cpuinfo || true'
ExecStartPre=/bin/sh -c 'echo "Expect ARMv8 CE: aes pmull sha1 sha2"; true'
ExecStart=${BIN} \
  --role=${ROLE} \
  --mech=${MECH} \
  --leader=${LEADER} \
  --bind=${BIND} \
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

echo "Listener setup complete."


#Save as setup_listener.sh, then on each listener:
#chmod +x setup_listener.sh && sudo LEADER_ADDR=192.168.1.20:5000 ./setup_listener.sh