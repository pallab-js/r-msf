#!/usr/bin/env bash
set -euo pipefail

# ── RCF Binary Signing Script ──────────────────────────────────────────────────
# Signs a release binary with an Ed25519 key for integrity verification.
#
# Usage:
#   ./scripts/sign-release.sh <binary-path> [private-key-path]
#
# If no private key is given, looks for:
#   - $RCF_SIGN_KEY (env var)
#   - ~/.rcf/signing-key.pem (default path)
#
# Output: <binary-path>.sig (64-byte Ed25519 signature)

if [ $# -lt 1 ]; then
    echo "Usage: $0 <binary-path> [private-key-path]"
    exit 1
fi

BINARY="$1"
SIG_FILE="${BINARY}.sig"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found: $BINARY"
    exit 1
fi

# Locate private key
PRIV_KEY=""
if [ $# -ge 2 ]; then
    PRIV_KEY="$2"
elif [ -n "${RCF_SIGN_KEY:-}" ]; then
    PRIV_KEY="$RCF_SIGN_KEY"
elif [ -f "$HOME/.rcf/signing-key.pem" ]; then
    PRIV_KEY="$HOME/.rcf/signing-key.pem"
else
    echo "Error: No signing key found."
    echo "Generate one with:"
    echo "  mkdir -p ~/.rcf"
    echo "  openssl genpkey -algorithm ed25519 -out ~/.rcf/signing-key.pem"
    echo "  openssl pkey -in ~/.rcf/signing-key.pem -pubout -out ~/.rcf/signing-pubkey.pem"
    echo ""
    echo "Then set RCF_PUBKEY env var at build time using the hex-encoded public key."
    exit 1
fi

echo "Signing $BINARY with $PRIV_KEY ..."

# Generate a temporary Python script for signing since we need pure Ed25519
# This avoids requiring a Rust tool just for signing
python3 -c "
import hashlib
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError:
    print('Installing cryptography...', file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cryptography'])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

with open('$PRIV_KEY', 'rb') as f:
    key_data = f.read()

try:
    key = load_pem_private_key(key_data, password=None)
except (ValueError, TypeError):
    # Try as raw key data
    key = Ed25519PrivateKey.from_private_bytes(key_data)

with open('$BINARY', 'rb') as f:
    binary_data = f.read()

hash_val = hashlib.sha256(binary_data).digest()
signature = key.sign(hash_val)

with open('$SIG_FILE', 'wb') as f:
    f.write(signature)

print(f'Signed: $SIG_FILE ({len(signature)} bytes)')

# Also output the public key hex for embedding
pubkey = key.public_key()
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
pubkey_bytes = pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
print(f'Public key hex (set RCF_PUBKEY={pubkey_bytes.hex()})')
" || {
    echo "Error: Signing failed. Install cryptography: pip install cryptography"
    exit 1
}

echo "Done. Binary signed at $SIG_FILE"
