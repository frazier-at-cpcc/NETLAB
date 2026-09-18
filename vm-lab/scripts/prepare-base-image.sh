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
# Configure browser RDP access (optional guest-console capability)
# ------------------------------------------------------------------------------
echo ""
echo "Step 5: Installing browser RDP support..."

# System mode, not the per-user headless session.
#
# The headless path configures cleanly and never opens the port. It needs
# gnome-headless-session@<user>.service, a static system unit that runs
# /usr/libexec/gdm-headless-login-session, which forks and exits; systemd reads
# that exit as a failure and gives up after five restarts. Verified on RHEL 10.0
# on 2026-09-18. System mode serves the login screen and needs no pre-existing
# user session.
#
# RDP_USER is the GNOME Remote Desktop credential name, not a system account.
# Do not set it to an account whose password another part of the stack depends
# on: SSH_USER and SSH_PASSWORD authenticate the ttyd terminal path, and
# changing that account's password to serve the desktop breaks the terminal.

RDP_USER="${RDP_USER:-student}"
GRD_CERT_DIR=/var/lib/gnome-remote-desktop

if ! command -v dnf >/dev/null 2>&1; then
    echo "  WARNING: dnf is unavailable; install gnome-remote-desktop manually"
elif [ -z "${RDP_PASSWORD:-}" ]; then
    echo "  Set RDP_PASSWORD to configure browser RDP before templating"
else
    dnf install -y gnome-remote-desktop freerdp
    systemctl enable gdm 2>/dev/null || true
    echo "  Installed GNOME Remote Desktop and FreeRDP tooling"

    install -d -m 700 -o gnome-remote-desktop -g gnome-remote-desktop "$GRD_CERT_DIR"
    if [ ! -s "$GRD_CERT_DIR/rdp-tls.crt" ]; then
        runuser -u gnome-remote-desktop -- \
            winpr-makecert -silent -rdp -path "$GRD_CERT_DIR" rdp-tls
    fi

    grdctl --system rdp set-tls-key  "$GRD_CERT_DIR/rdp-tls.key"
    grdctl --system rdp set-tls-cert "$GRD_CERT_DIR/rdp-tls.crt"
    # Without this the server accepts the connection and then logs
    # "Credentials are not set, denying client", which reads as a network
    # fault from the client side.
    grdctl --system rdp set-credentials "$RDP_USER" "$RDP_PASSWORD"
    grdctl --system rdp enable
    systemctl enable --now gnome-remote-desktop.service

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=3389/tcp >/dev/null
        firewall-cmd --reload >/dev/null
    fi

    if ss -lnt 2>/dev/null | grep -q ':3389'; then
        echo "  Browser RDP listening on 3389 as credential '$RDP_USER'"
    else
        echo "  WARNING: RDP configured but nothing is listening on 3389"
        systemctl is-active gnome-remote-desktop.service || true
    fi

    echo "  For pre-RHEL 10 images, xrdp/xorgxrdp remains a supported fallback"
fi

# ------------------------------------------------------------------------------
# Clean up for template
# ------------------------------------------------------------------------------
echo ""
echo "Step 6: Cleaning up for template use..."

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
