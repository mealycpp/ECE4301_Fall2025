#!/bin/bash
# Generate TLS certificates for PQC Chat
# This script generates self-signed certificates for development/testing

set -e

OUTPUT_DIR="${1:-.}"

echo "Generating TLS certificates in $OUTPUT_DIR..."

# Generate CA certificate (optional, for mutual TLS)
echo "Generating CA certificate..."
openssl req -x509 -newkey rsa:4096 \
    -keyout "$OUTPUT_DIR/ca.key" \
    -out "$OUTPUT_DIR/ca.crt" \
    -days 3650 -nodes \
    -subj "/CN=PQC Chat CA/O=PQC Chat/C=US"

# Generate server certificate
echo "Generating server certificate..."
openssl req -newkey rsa:4096 \
    -keyout "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.csr" \
    -nodes \
    -subj "/CN=pqc-chat-server/O=PQC Chat/C=US"

openssl x509 -req \
    -in "$OUTPUT_DIR/server.csr" \
    -CA "$OUTPUT_DIR/ca.crt" \
    -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/server.crt" \
    -days 365

# Generate client certificate (for mutual TLS)
echo "Generating client certificate..."
openssl req -newkey rsa:4096 \
    -keyout "$OUTPUT_DIR/client.key" \
    -out "$OUTPUT_DIR/client.csr" \
    -nodes \
    -subj "/CN=pqc-chat-client/O=PQC Chat/C=US"

openssl x509 -req \
    -in "$OUTPUT_DIR/client.csr" \
    -CA "$OUTPUT_DIR/ca.crt" \
    -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/client.crt" \
    -days 365

# Clean up CSR files
rm -f "$OUTPUT_DIR"/*.csr

echo ""
echo "Certificates generated:"
echo "  CA Certificate:     $OUTPUT_DIR/ca.crt"
echo "  CA Key:             $OUTPUT_DIR/ca.key"
echo "  Server Certificate: $OUTPUT_DIR/server.crt"
echo "  Server Key:         $OUTPUT_DIR/server.key"
echo "  Client Certificate: $OUTPUT_DIR/client.crt"
echo "  Client Key:         $OUTPUT_DIR/client.key"
echo ""
echo "For production, replace these with certificates from a real CA."
