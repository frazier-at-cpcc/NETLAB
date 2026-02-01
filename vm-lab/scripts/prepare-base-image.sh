#!/bin/bash
# ==============================================================================
# Prepare Base QCOW2 Image for VM Lab
# ==============================================================================
# This script helps prepare your Red Hat Academy QCOW2 image for use as a
# template. Run these commands INSIDE the VM before shutting it down.
# ==============================================================================

set -e

echo "======================================"
echo "Red Hat Academy VM - Template Preparation"
echo "======================================"
echo ""
echo "Run this script INSIDE your base VM before converting to template."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# ------------------------------------------------------------------------------
# Create student user
# ------------------------------------------------------------------------------
echo "Step 1: Creating student user..."

if id "student" &>/dev/null; then
    echo "  User 'student' already exists"
else
    useradd -m -s /bin/bash student
    echo "  Created user 'student'"
fi

# Create .ssh directory
mkdir -p /home/student/.ssh
chmod 700 /home/student/.ssh

echo ""
echo "Step 2: Add SSH public key"
echo "Paste the SSH public key from the orchestrator (id_ed25519.pub):"
echo "(Press Enter twice when done)"
echo ""

# Read public key
KEY=""
while IFS= read -r line; do
    [ -z "$line" ] && break
    KEY="$line"
done

if [ -n "$KEY" ]; then
    echo "$KEY" >> /home/student/.ssh/authorized_keys
    chmod 600 /home/student/.ssh/authorized_keys
    chown -R student:student /home/student/.ssh
    echo "  Added SSH key to authorized_keys"
else
    echo "  WARNING: No key provided, skipping..."
fi

# ------------------------------------------------------------------------------
# Configure sudo
# ------------------------------------------------------------------------------
echo ""
echo "Step 3: Configuring passwordless sudo..."

echo "student ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/student
chmod 440 /etc/sudoers.d/student
echo "  Configured passwordless sudo for student"

# ------------------------------------------------------------------------------
# Configure SSH
# ------------------------------------------------------------------------------
echo ""
echo "Step 4: Configuring SSH..."

# Ensure SSH is enabled
systemctl enable sshd

# Optional: Speed up SSH connections by disabling DNS lookup
if ! grep -q "UseDNS no" /etc/ssh/sshd_config; then
    echo "UseDNS no" >> /etc/ssh/sshd_config
fi

echo "  SSH configured and enabled"

# ------------------------------------------------------------------------------
# Clean up for template
# ------------------------------------------------------------------------------
echo ""
echo "Step 5: Cleaning up for template use..."

# Remove SSH host keys (will be regenerated on first boot)
rm -f /etc/ssh/ssh_host_*
echo "  Removed SSH host keys"

# Clear machine-id (will be regenerated on first boot)
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
echo "  Cleared machine-id"

# Clear logs
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
journalctl --vacuum-time=1s 2>/dev/null || true
echo "  Cleared logs"

# Clear bash history
cat /dev/null > /root/.bash_history
cat /dev/null > /home/student/.bash_history 2>/dev/null || true
echo "  Cleared bash history"

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*
echo "  Cleared temporary files"

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
echo ""
echo "======================================"
echo "Template preparation complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Power off this VM: shutdown -h now"
echo "2. Copy the QCOW2 file to your template location"
echo "3. Set it as read-only: chmod 444 /path/to/template.qcow2"
echo ""
echo "The orchestrator will create thin clones from this template."
echo ""

read -p "Shut down now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    shutdown -h now
fi
