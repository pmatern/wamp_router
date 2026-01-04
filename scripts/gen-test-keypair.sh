#!/bin/bash
# Generate Ed25519 key pair for testing WAMP-Cryptosign authentication

set -e

# Create output directory
mkdir -p test_auth

echo "Generating Ed25519 key pair..."

# Generate private key
openssl genpkey -algorithm ED25519 -out test_auth/private.pem

# Extract public key
openssl pkey -in test_auth/private.pem -pubout -out test_auth/public.pem

echo ""
echo "Keys generated successfully:"
echo "  Private key: test_auth/private.pem"
echo "  Public key: test_auth/public.pem"
echo ""

# Extract and display public key in hex format
echo "Public key (hex format for config.toml):"
openssl pkey -in test_auth/public.pem -pubin -text -noout | \
    grep -A 3 "pub:" | \
    tail -n 3 | \
    tr -d ' :\n'

echo ""
echo ""
echo "Add this to your config.toml [auth.keys] section:"
AUTHID="testuser"
PUBKEY_HEX=$(openssl pkey -in test_auth/public.pem -pubin -text -noout | \
    grep -A 3 "pub:" | \
    tail -n 3 | \
    tr -d ' :\n')

echo "\"${AUTHID}\" = \"${PUBKEY_HEX}\""
echo ""
