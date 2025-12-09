#!/bin/bash
# PQC Chat Raspberry Pi Network Deployment Guide
# This script helps deploy the PQC Chat application across 3 Raspberry Pi 5s

set -e

echo "=== PQC Chat Raspberry Pi Network Deployment ==="
echo ""

# Check if we need to run parts as sudo
if [ "$EUID" -ne 0 ]; then
    echo "Note: This script needs sudo privileges for installation steps."
    echo "Building will be done as current user, installation as sudo."
    echo ""
fi

# Function to detect which Pi this is based on IP
detect_pi_role() {
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    case $LOCAL_IP in
        "192.168.10.101")
            echo "server-client"
            ;;
        "192.168.10.102")
            echo "client1"
            ;;
        "192.168.10.103")
            echo "client2"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Function to setup server
setup_server() {
    echo "Setting up this Pi as PQC Chat Server (192.168.10.101)"
    
    # Ensure /etc/pqc-chat directory exists
    sudo mkdir -p /etc/pqc-chat
    
    # Copy server configuration
    sudo cp config/server_pi.toml /etc/pqc-chat/server.toml
    
    # Generate certificates if they don't exist
    if [ ! -f "/etc/pqc-chat/server.crt" ] || [ ! -f "/etc/pqc-chat/server.key" ]; then
        echo "Generating TLS certificates..."
        if [ -x "./scripts/generate_certs.sh" ]; then
            sudo ./scripts/generate_certs.sh
        else
            echo "Warning: generate_certs.sh not found or not executable"
        fi
    fi
    
    # Stop any running server before installation
    sudo systemctl stop pqc-chat-server 2>/dev/null || true
    
    # Install and enable server service
    if [ -x "./scripts/install_server.sh" ]; then
        sudo ./scripts/install_server.sh
        sudo systemctl enable pqc-chat-server
        sudo systemctl start pqc-chat-server
    else
        echo "Warning: install_server.sh not found or not executable"
        echo "You may need to install the server manually"
    fi
    
    echo "Server setup complete!"
    echo "Server is now running on:"
    echo "  - Signaling: https://192.168.10.101:8443"
    echo "  - Audio: udp://192.168.10.101:10000"
    echo "  - Video: udp://192.168.10.101:10001"
    echo ""
    echo "To also run a client on this server Pi:"
    echo "  - Copy client config: sudo cp config/server_client_pi.toml /etc/pqc-chat/client.toml"
    echo "  - Run GUI client: ./target/release/pqc-enhanced-gui"
    echo "  - Or install client: sudo ./scripts/install_client.sh"
}

# Function to setup client
setup_client() {
    CLIENT_NUM=$1
    echo "Setting up this Pi as PQC Chat Client $CLIENT_NUM"
    
    # Ensure /etc/pqc-chat directory exists
    sudo mkdir -p /etc/pqc-chat
    
    # Copy appropriate client configuration
    sudo cp config/client${CLIENT_NUM}_pi.toml /etc/pqc-chat/client.toml
    
    # Install client
    if [ -x "./scripts/install_client.sh" ]; then
        sudo ./scripts/install_client.sh
    else
        echo "Warning: install_client.sh not found or not executable"
        echo "You may need to install the client manually"
    fi
    
    echo "Client $CLIENT_NUM setup complete!"
    echo "To start the enhanced GUI, run: /opt/pqc-chat/bin/pqc-enhanced-gui"
    echo "The GUI will show connection options to connect to the server at 192.168.10.101"
}

# Main deployment logic
main() {
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ] || [ ! -d "src" ]; then
        echo "Error: Please run this script from the PQC Chat project root directory"
        exit 1
    fi
    
    # Find cargo binary (check both user and system paths)
    CARGO_CMD=""
    if command -v cargo >/dev/null 2>&1; then
        CARGO_CMD="cargo"
    elif [ -f "$HOME/.cargo/bin/cargo" ]; then
        CARGO_CMD="$HOME/.cargo/bin/cargo"
    elif [ -f "/home/$USER/.cargo/bin/cargo" ]; then
        CARGO_CMD="/home/$USER/.cargo/bin/cargo"
    else
        echo "Error: cargo not found. Please install Rust and Cargo first."
        echo "Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    
    # Build the project first (as current user, not sudo)
    echo "Building PQC Chat with: $CARGO_CMD"
    if [ "$EUID" -eq 0 ]; then
        # If running as root, run cargo as the original user
        if [ -n "$SUDO_USER" ]; then
            sudo -u "$SUDO_USER" "$CARGO_CMD" build --release
        else
            echo "Warning: Running as root. Cargo may not work properly."
            "$CARGO_CMD" build --release
        fi
    else
        "$CARGO_CMD" build --release
    fi
    
    # Detect Pi role
    ROLE=$(detect_pi_role)
    
    case $ROLE in
        "server")
            setup_server
            ;;
        "server-client")
            setup_server_client
            ;;
        "client1")
            setup_client 1
            ;;
        "client2")
            setup_client 2
            ;;
        "unknown")
            echo "Warning: Could not auto-detect Pi role based on IP address."
            echo "Current IP: $(hostname -I | awk '{print $1}')"
            echo ""
            echo "Please run setup manually:"
            echo "  For server (192.168.10.101): sudo ./scripts/setup_pi.sh server"
            echo "  For client 1 (192.168.10.102): sudo ./scripts/setup_pi.sh client1"
            echo "  For client 2 (192.168.10.103): sudo ./scripts/setup_pi.sh client2"
            exit 1
            ;;
    esac
    
    echo ""
    echo "=== Deployment Complete ==="
    echo "Network status:"
    echo "  Server Pi (192.168.10.101): $(ping -c1 192.168.10.101 &>/dev/null && echo "Online" || echo "Offline")"
    echo "  Client Pi 1 (192.168.10.102): $(ping -c1 192.168.10.102 &>/dev/null && echo "Online" || echo "Offline")"
    echo "  Client Pi 2 (192.168.10.103): $(ping -c1 192.168.10.103 &>/dev/null && echo "Online" || echo "Offline")"
    echo ""
    echo "Current network configuration:"
    echo "  Ethernet (eth0): $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo "Not configured")"
    echo "  WLAN (wlan0): $(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo "Not connected")"
    echo "  Internet access: $(ping -c1 google.com &>/dev/null && echo "Available" || echo "Not available")"
}

# Function to setup server + client
setup_server_client() {
    echo "Setting up this Pi as both PQC Chat Server AND Client"
    
    # First set up as server
    setup_server
    
    echo ""
    echo "=== Adding Client Capability ==="
    
    # Install client configuration for localhost connection
    sudo cp config/server_client_pi.toml /etc/pqc-chat/client.toml
    
    # Install client components
    if [ -x "./scripts/install_client.sh" ]; then
        sudo ./scripts/install_client.sh
    else
        echo "Warning: install_client.sh not found, client GUI may not be installed"
    fi
    
    echo ""
    echo "=== Server + Client Setup Complete ==="
    echo "Server is running as a service"
    echo "To join the chat as a client, run: /opt/pqc-chat/bin/pqc-enhanced-gui"
    echo "The client will connect to the local server (127.0.0.1)"
}

# Handle manual role specification
if [ $# -eq 1 ]; then
    case $1 in
        "server")
            setup_server
            ;;
        "server-client"|"server_client")
            setup_server_client
            ;;
        "client1")
            setup_client 1
            ;;
        "client2")
            setup_client 2
            ;;
        *)
            echo "Usage: $0 [server|server-client|client1|client2]"
            echo "  server       - Server only"
            echo "  server-client- Server + client capability"
            echo "  client1      - Client 1 (192.168.10.102)"
            echo "  client2      - Client 2 (192.168.10.103)"
            echo "If no argument is provided, role will be auto-detected based on IP address."
            exit 1
            ;;
    esac
else
    main
fi