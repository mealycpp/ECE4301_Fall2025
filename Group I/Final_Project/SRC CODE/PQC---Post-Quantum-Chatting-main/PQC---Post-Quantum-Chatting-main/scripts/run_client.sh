#!/bin/bash
# Run PQC Chat Client GUI
# Simple script to start the client for development/testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Build if needed
if [ ! -f "target/release/pqc-enhanced-gui" ]; then
    echo "Building PQC Chat Enhanced GUI..."
    cargo build --release --bin pqc-enhanced-gui --features gui
fi

echo "Starting PQC Chat Enhanced Client..."
./target/release/pqc-enhanced-gui "$@"
