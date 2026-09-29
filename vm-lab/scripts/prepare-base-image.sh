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

# Screen sharing of a logged-in session, not system mode and not headless.
#
# All three of GNOME Remote Desktop's modes configure without complaint and
# only one of them serves a desktop to Guacamole. The reason is worth recording
# because every failure reads as a network fault.
#
# System mode hands the connection over to GDM using an RDP Server Redirection
# PDU. A native FreeRDP client obeys it and reconnects; guacd does not
# implement server redirection, so it fails on the deactivation that precedes
# the redirect, the daemon logs "Aborting handover, removing remote client",
# and the client is cancelled with ERRINFO_CB_CONNECTION_CANCELLED. The
# student sees a black screen that closes after about thirty seconds. Confirmed
# with and without an emulated GPU.
#
# Headless mode adds a fresh virtual monitor beside the console one. It
# connects, but the student lands on an empty second screen while the panel and
# every window stay on the first.
#
# Session sharing has no redirection and no extra monitor: the daemon serves
# the session that is already running, which is the one the student wants.
#
# It needs a logged-in session, so GDM autologs RDP_DESKTOP_USER in, and it
# stores its credentials in the Secret Service, which is where the last trap
# is. Under autologin no password is ever typed, so the login keyring cannot be
# unlocked, "grdctl rdp set-credentials" fails with "Cannot create an item in a
# locked collection", and the daemon binds the port and then refuses every
# client because its credentials are empty. Writing an empty-password keyring
# ahead of first login avoids the prompt entirely.
#
# That keyring is plaintext on disk, so nothing else may be stored in it. The
# only secret it holds is RDP_PASSWORD, which already reaches this script in
# the clear, is scoped to one disposable lab VM, and is never a system account
# password. Do not reuse this pattern on a host that keeps real secrets.
#
# Two accounts are in play and they are not interchangeable:
#   RDP_DESKTOP_USER is a real system account whose GNOME session the student
#   sees. It defaults to SSH_USER because that account already owns the console
#   on the lab image.
#   RDP_USER is GNOME Remote Desktop's own credential name, checked by the
#   daemon and unrelated to PAM. It need not name any account. Do not set it to
#   an account whose password another part of the stack depends on: SSH_USER
#   and SSH_PASSWORD authenticate the ttyd terminal path.
#
# Verified end to end on RHEL 10 with gnome-remote-desktop 47.3, GNOME Shell
# 47.4 and guacd 1.6.0 on 2026-09-29: full desktop, live repaint, keyboard and
# pointer.

RDP_USER="${RDP_USER:-student}"
RDP_DESKTOP_USER="${RDP_DESKTOP_USER:-${SSH_USER:-student}}"

if ! command -v dnf >/dev/null 2>&1; then
    echo "  WARNING: dnf is unavailable; install gnome-remote-desktop manually"
elif [ -z "${RDP_PASSWORD:-}" ]; then
    echo "  Set RDP_PASSWORD to configure browser RDP before templating"
elif ! id "$RDP_DESKTOP_USER" >/dev/null 2>&1; then
    echo "  WARNING: RDP_DESKTOP_USER '$RDP_DESKTOP_USER' does not exist; skipping browser RDP"
else
    dnf install -y gnome-remote-desktop gdm gnome-keyring freerdp
    echo "  Installed GNOME Remote Desktop and FreeRDP tooling"

    RDP_UID="$(id -u "$RDP_DESKTOP_USER")"
    RDP_HOME="$(getent passwd "$RDP_DESKTOP_USER" | cut -d: -f6)"
    GRD_USER_DIR="$RDP_HOME/.local/share/gnome-remote-desktop"
    KEYRING_DIR="$RDP_HOME/.local/share/keyrings"

    # The system daemon would otherwise hold 3389 and win the bind.
    grdctl --system rdp disable 2>/dev/null || true
    systemctl disable --now gnome-remote-desktop.service 2>/dev/null || true

    python3 - "$RDP_DESKTOP_USER" <<'PYEOF'
import configparser
import sys

user = sys.argv[1]
path = "/etc/gdm/custom.conf"
conf = configparser.ConfigParser()
conf.optionxform = str
conf.read(path)
if not conf.has_section("daemon"):
    conf.add_section("daemon")
conf.set("daemon", "AutomaticLoginEnable", "True")
conf.set("daemon", "AutomaticLogin", user)
with open(path, "w") as handle:
    conf.write(handle)
PYEOF
    echo "  GDM will log in '$RDP_DESKTOP_USER' automatically"

    # An empty-password login keyring, written before first login so the
    # session never has to prompt for one it cannot answer.
    install -d -o "$RDP_DESKTOP_USER" -g "$RDP_DESKTOP_USER" -m 700 "$KEYRING_DIR"
    cat > "$KEYRING_DIR/login.keyring" <<'EOF'
[keyring]
display-name=login
ctime=0
mtime=0
lock-on-idle=false
lock-after=false
EOF
    printf 'login' > "$KEYRING_DIR/default"
    chown "$RDP_DESKTOP_USER:$RDP_DESKTOP_USER" "$KEYRING_DIR/login.keyring" "$KEYRING_DIR/default"
    chmod 600 "$KEYRING_DIR/login.keyring" "$KEYRING_DIR/default"

    install -d -o "$RDP_DESKTOP_USER" -g "$RDP_DESKTOP_USER" -m 700 "$GRD_USER_DIR"
    if [ ! -s "$GRD_USER_DIR/rdp-tls.crt" ]; then
        openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
            -subj "/CN=$(hostname -s)" \
            -out "$GRD_USER_DIR/rdp-tls.crt" \
            -keyout "$GRD_USER_DIR/rdp-tls.key" 2>/dev/null
        chown "$RDP_DESKTOP_USER:$RDP_DESKTOP_USER" "$GRD_USER_DIR/rdp-tls.crt" "$GRD_USER_DIR/rdp-tls.key"
        chmod 600 "$GRD_USER_DIR/rdp-tls.key"
    fi

    # The session has to exist before grdctl can be told anything: the
    # user-mode daemon is reached over that session's bus.
    loginctl enable-linger "$RDP_DESKTOP_USER"
    systemctl enable gdm
    systemctl restart gdm

    for _ in $(seq 1 45); do
        [ -S "/run/user/$RDP_UID/bus" ] && break
        sleep 2
    done
    if [ ! -S "/run/user/$RDP_UID/bus" ]; then
        echo "  WARNING: no session bus for '$RDP_DESKTOP_USER'; browser RDP not configured"
    else
        runuser -l "$RDP_DESKTOP_USER" -c "
            export XDG_RUNTIME_DIR=/run/user/$RDP_UID
            export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$RDP_UID/bus
            grdctl rdp set-tls-cert '$GRD_USER_DIR/rdp-tls.crt'
            grdctl rdp set-tls-key  '$GRD_USER_DIR/rdp-tls.key'
            grdctl rdp set-credentials '$RDP_USER' '$RDP_PASSWORD'
            grdctl rdp enable
            systemctl --user enable --now gnome-remote-desktop.service
        "
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=3389/tcp >/dev/null
        firewall-cmd --reload >/dev/null
    fi

    sleep 5
    STORED="$(runuser -l "$RDP_DESKTOP_USER" -c "
        export XDG_RUNTIME_DIR=/run/user/$RDP_UID
        export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$RDP_UID/bus
        grdctl status" 2>/dev/null | grep -c 'Username: (hidden)')"
    if ss -lnt 2>/dev/null | grep -q ':3389' && [ "$STORED" = "1" ]; then
        echo "  Browser RDP listening on 3389, sharing the desktop of '$RDP_DESKTOP_USER'"
    elif ss -lnt 2>/dev/null | grep -q ':3389'; then
        # Binding the port proves nothing on its own. A daemon whose
        # credentials failed to store listens and then refuses every client.
        echo "  WARNING: RDP is listening but stored no credentials; every client will be refused"
    else
        echo "  WARNING: RDP configured but nothing is listening on 3389"
        loginctl list-sessions --no-legend || true
    fi
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
