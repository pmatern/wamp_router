#!/bin/bash
# Generate self-signed TLS certificate for local testing
# DO NOT use these certificates in production!

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/test_certs"

echo "Generating test TLS certificates..."
echo "Output directory: $CERT_DIR"

# Create certificate directory
mkdir -p "$CERT_DIR"

# Generate private key (2048-bit RSA)
echo "  1. Generating private key..."
openssl genrsa -out "$CERT_DIR/key.pem" 2048 2>/dev/null

# Generate self-signed certificate (valid for 365 days)
echo "  2. Generating self-signed certificate..."
openssl req -new -x509 \
    -key "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=WAMP Router Development/CN=localhost" \
    2>/dev/null

echo ""
echo "✓ Test certificates generated successfully!"
echo ""
echo "Files created:"
echo "  Certificate: $CERT_DIR/cert.pem"
echo "  Private key: $CERT_DIR/key.pem"
echo ""
echo "To use these certificates, update your config file:"
echo ""
echo "  [server.tls]"
echo "  cert = \"$CERT_DIR/cert.pem\""
echo "  key = \"$CERT_DIR/key.pem\""
echo ""
echo "⚠️  WARNING: These are self-signed certificates for TESTING ONLY!"
echo "   Do NOT use in production environments."
echo ""
