#!/bin/bash
# PQC Chat Client Installation Script
# Run this script on your Raspberry Pi to install the PQC Chat client

set -e

echo "=== PQC Chat Client Installation ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/pqc-chat"
CONFIG_DIR="/etc/pqc-chat"
LOG_DIR="/var/log/pqc-chat"

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y openssl build-essential pkg-config libssl-dev

# GUI dependencies for egui
apt-get install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
    libxkbcommon-dev libgtk-3-dev || echo "Note: Some GUI dependencies may be missing"

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Build application
echo "Building PQC Chat Client and GUI..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
cargo build --release --bin pqc-interactive
cargo build --release --bin pqc-enhanced-gui --features gui || echo "Note: Enhanced GUI build may fail without display libraries"

# Install binaries
echo "Installing application..."
cp "$PROJECT_DIR/target/release/pqc-interactive" "$INSTALL_DIR/bin/"
cp "$PROJECT_DIR/target/release/pqc-enhanced-gui" "$INSTALL_DIR/bin/" 2>/dev/null || true

# Install configuration
echo "Installing configuration..."
if [ ! -f "$CONFIG_DIR/client.toml" ]; then
    cp "$PROJECT_DIR/config/client.toml" "$CONFIG_DIR/"
fi

# Set permissions
echo "Setting permissions..."
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod 755 "$LOG_DIR"

# Install systemd service (template for per-user startup)
echo "Installing systemd service..."
cp "$PROJECT_DIR/systemd/pqc-chat-client@.service" /etc/systemd/system/
systemctl daemon-reload

# Create desktop entry
echo "Creating desktop entry..."
cat > /usr/share/applications/pqc-chat.desktop << 'EOF'
[Desktop Entry]
Name=PQC Chat
Comment=Post-Quantum Secure Video Chat
Exec=/opt/pqc-chat/bin/pqc-enhanced-gui
Icon=video-display
Terminal=false
Type=Application
Categories=Network;Chat;VideoConference;
EOF

echo ""
echo "=== Installation Complete ==="
echo ""
echo "To start the client GUI:"
echo "  /opt/pqc-chat/bin/pqc-enhanced-gui"
echo ""
echo "To start the CLI client:"
echo "  /opt/pqc-chat/bin/pqc-interactive"
echo ""
echo "Or use the desktop shortcut 'PQC Chat'"
echo ""
echo "To enable auto-start for user 'pi':"
echo "  sudo systemctl enable pqc-chat-client@pi"
echo ""
echo "Configuration file: $CONFIG_DIR/client.toml"
echo ""
echo "Note: Edit $CONFIG_DIR/client.toml to set the server address"
