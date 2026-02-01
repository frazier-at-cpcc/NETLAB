#!/bin/bash
# ==============================================================================
# Setup Libvirt Network for VM Lab
# ==============================================================================
# Creates the 'lab-net' network for student VMs
# ==============================================================================

set -e

NETWORK_NAME="lab-net"
BRIDGE_NAME="virbr1"
NETWORK_ADDR="10.10.10.0"
NETMASK="255.255.255.0"
DHCP_START="10.10.10.11"
DHCP_END="10.10.10.254"

echo "======================================"
echo "Setting up libvirt network: $NETWORK_NAME"
echo "======================================"

# Check if network already exists
if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    echo "Network '$NETWORK_NAME' already exists."
    echo ""
    virsh net-info "$NETWORK_NAME"
    echo ""
    read -p "Do you want to recreate it? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Destroying existing network..."
        virsh net-destroy "$NETWORK_NAME" 2>/dev/null || true
        virsh net-undefine "$NETWORK_NAME"
    else
        echo "Keeping existing network."
        exit 0
    fi
fi

# Create network XML
NETWORK_XML=$(cat <<EOF
<network>
  <name>$NETWORK_NAME</name>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='$BRIDGE_NAME' stp='on' delay='0'/>
  <ip address='10.10.10.1' netmask='$NETMASK'>
    <dhcp>
      <range start='$DHCP_START' end='$DHCP_END'/>
    </dhcp>
  </ip>
</network>
EOF
)

# Create and start the network
echo "Creating network..."
echo "$NETWORK_XML" | virsh net-define /dev/stdin

echo "Starting network..."
virsh net-start "$NETWORK_NAME"

echo "Setting network to autostart..."
virsh net-autostart "$NETWORK_NAME"

echo ""
echo "======================================"
echo "Network created successfully!"
echo "======================================"
echo ""
virsh net-info "$NETWORK_NAME"
echo ""
echo "DHCP Range: $DHCP_START - $DHCP_END"
echo "Gateway: 10.10.10.1"
echo ""
