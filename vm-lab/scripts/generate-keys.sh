#!/bin/bash
# ==============================================================================
# Generate Keys for VM Lab
# ==============================================================================
# This script generates:
# - RSA key pair for LTI 1.3 JWT signing
# - ED25519 SSH key for VM access
# - Random secrets for LTI 1.1 consumers
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_DIR/lti/keys"

echo "======================================"
echo "Generating keys for VM Lab"
echo "======================================"

# Create keys directory
mkdir -p "$KEYS_DIR"

# ------------------------------------------------------------------------------
# Generate LTI 1.3 RSA Key Pair
# ------------------------------------------------------------------------------
echo ""
echo "Generating LTI 1.3 RSA key pair..."

if [ -f "$KEYS_DIR/private.pem" ]; then
    echo "  WARNING: private.pem already exists, skipping..."
else
    openssl genrsa -out "$KEYS_DIR/private.pem" 2048
    openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"
    chmod 600 "$KEYS_DIR/private.pem"
    chmod 644 "$KEYS_DIR/public.pem"
    echo "  Created: $KEYS_DIR/private.pem"
    echo "  Created: $KEYS_DIR/public.pem"
fi

# ------------------------------------------------------------------------------
# Generate SSH Key for VM Access
# ------------------------------------------------------------------------------
echo ""
echo "Generating SSH key for VM access..."

if [ -f "$KEYS_DIR/id_ed25519" ]; then
    echo "  WARNING: id_ed25519 already exists, skipping..."
else
    ssh-keygen -t ed25519 -f "$KEYS_DIR/id_ed25519" -N "" -C "vm-lab-orchestrator"
    chmod 600 "$KEYS_DIR/id_ed25519"
    chmod 644 "$KEYS_DIR/id_ed25519.pub"
    echo "  Created: $KEYS_DIR/id_ed25519"
    echo "  Created: $KEYS_DIR/id_ed25519.pub"
fi

# ------------------------------------------------------------------------------
# Generate Secrets for .env
# ------------------------------------------------------------------------------
echo ""
echo "Generating secrets for .env file..."
echo ""
echo "Add these to your .env file:"
echo "======================================"
echo ""
echo "# Session secret"
echo "SESSION_SECRET=$(openssl rand -hex 32)"
echo ""
echo "# Database passwords"
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)"
echo "LTI_DB_PASS=$(openssl rand -hex 16)"
echo "LAB_DB_PASS=$(openssl rand -hex 16)"
echo ""
echo "# LTI 1.1 Consumer Secrets"
echo "LTI11_CANVAS_SECRET=$(openssl rand -hex 32)"
echo "LTI11_BLACKBOARD_SECRET=$(openssl rand -hex 32)"
echo "LTI11_MOODLE_SECRET=$(openssl rand -hex 32)"
echo "LTI11_BRIGHTSPACE_SECRET=$(openssl rand -hex 32)"
echo ""
echo "======================================"

# ------------------------------------------------------------------------------
# Print SSH Public Key for VM Setup
# ------------------------------------------------------------------------------
echo ""
echo "SSH Public Key (add to VM base image):"
echo "======================================"
cat "$KEYS_DIR/id_ed25519.pub"
echo ""
echo "======================================"
echo ""
echo "Add this key to /home/student/.ssh/authorized_keys in your base QCOW2 image"
echo ""
