#!/bin/bash
# Reset Proxmox network to use DHCP with error handling and validation

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Exiting."
  exit 1
fi

# Prompt for network interface
read -p "Enter the network interface to use (e.g., enp3s0): " IFACE
if [ -z "$IFACE" ]; then
  echo "No interface entered. Exiting."
  exit 1
fi

# Validate interface exists
if ! ip link show dev "$IFACE" >/dev/null 2>&1; then
  echo "Interface $IFACE does not exist. Exiting."
  exit 1
fi

# Warn if bridges are detected (common in Proxmox)
if grep -q "vmbr" /etc/network/interfaces; then
  echo "WARNING: Bridge (e.g., vmbr0) detected in /etc/network/interfaces."
  echo "This script will remove bridges, which may break VM networking."
  read -p "Continue (y/n)? " CONFIRM
  if [ "$CONFIRM" != "y" ]; then
    echo "Aborting."
    exit 1
  fi
fi

# Backup current configuration
BACKUP="/etc/network/interfaces.bak.$(date +%s)"
echo "Backing up current network config to $BACKUP"
if ! cp /etc/network/interfaces "$BACKUP"; then
  echo "Failed to create backup. Exiting."
  exit 1
fi

# Reset network configuration
echo "Restoring network config to default with DHCP"
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $IFACE
iface $IFACE inet dhcp
EOF

if [ $? -ne 0 ]; then
  echo "Failed to write /etc/network/interfaces. Exiting."
  exit 1
fi

# Flush existing IPs and routes
echo "Flushing existing IPs and routes"
if ! ip addr flush dev "$IFACE"; then
  echo "Warning: Failed to flush IP addresses."
fi
if ! ip route flush dev "$IFACE"; then
  echo "Warning: Failed to flush routes."
fi

# Restart networking
echo "Restarting networking"
ifdown "$IFACE" >/dev/null 2>&1
if ! ifup "$IFACE"; then
  echo "Failed to bring up $IFACE. Check DHCP server or configuration."
  exit 1
fi

# Show assigned IP
echo "Assigned IP address:"
ip addr show dev "$IFACE" | grep "inet "

# Test internet connectivity
echo "Testing internet connectivity"
if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
  echo "Internet OK"
else
  echo "No internet! Check DHCP server, gateway, or firewall."
fi
