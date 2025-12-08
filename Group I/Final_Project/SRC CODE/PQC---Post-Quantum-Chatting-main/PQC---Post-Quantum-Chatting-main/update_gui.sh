#!/bin/bash
# Update GUI with message broadcasting fix

echo "Building enhanced GUI..."
cargo build --release --bin pqc-enhanced-gui --features gui

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Installing to /opt/pqc-chat/bin/..."
    sudo cp ./target/release/pqc-enhanced-gui /opt/pqc-chat/bin/pqc-enhanced-gui
    echo "Installation complete!"
    echo ""
    echo "You can now run: /opt/pqc-chat/bin/pqc-enhanced-gui"
else
    echo "Build failed!"
    exit 1
fi
