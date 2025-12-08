#!/bin/bash
# PQC Chat Server Installation Script
# Run this script on your Raspberry Pi to install the PQC Chat server

set -e

echo "=== PQC Chat Server Installation ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/pqc-chat"
CONFIG_DIR="/etc/pqc-chat"
LOG_DIR="/var/log/pqc-chat"
SERVICE_USER="pqc-chat"

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y openssl build-essential pkg-config libssl-dev

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Create service user
echo "Creating service user..."
if ! id -u "$SERVICE_USER" > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Build application
echo "Building PQC Chat Server..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
cargo build --release --bin pqc-server

# Install binary
echo "Installing application..."
cp "$PROJECT_DIR/target/release/pqc-server" "$INSTALL_DIR/bin/"

# Install configuration
echo "Installing configuration..."
if [ ! -f "$CONFIG_DIR/server.toml" ]; then
    cp "$PROJECT_DIR/config/server.toml" "$CONFIG_DIR/"
fi

# Generate TLS certificates if not present
if [ ! -f "$CONFIG_DIR/server.crt" ] || [ ! -f "$CONFIG_DIR/server.key" ]; then
    echo "Generating TLS certificates..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CONFIG_DIR/server.key" \
        -out "$CONFIG_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/CN=pqc-chat-server/O=PQC Chat/C=US"
fi

# Set permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
chown -R root:root "$INSTALL_DIR"
chown -R root:"$SERVICE_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*
chmod 755 "$INSTALL_DIR/bin/pqc-server"

# Install systemd service
echo "Installing systemd service..."
cp "$PROJECT_DIR/systemd/pqc-chat-server.service" /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "To start the server:"
echo "  sudo systemctl start pqc-chat-server"
echo ""
echo "To enable on boot:"
echo "  sudo systemctl enable pqc-chat-server"
echo ""
echo "To check status:"
echo "  sudo systemctl status pqc-chat-server"
echo ""
echo "Configuration file: $CONFIG_DIR/server.toml"
echo "Log file: $LOG_DIR/server.log"
