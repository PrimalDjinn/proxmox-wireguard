#!/bin/bash
# Run as root on the Proxmox host

set -e

### 1️⃣ CREATE NETWORK BRIDGES ###

echo "[+] Backing up /etc/network/interfaces"
cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%F-%H-%M)

echo "[+] Adding vmbr10 (Dev Network) and vmbr20 (Staging Network)"
cat <<EOF >>/etc/network/interfaces

# === Dev Network ===
auto vmbr10
iface vmbr10 inet static
    address 10.10.10.1/24
    bridge_ports none
    bridge_stp off
    bridge_fd 0

# === Staging Network ===
auto vmbr20
iface vmbr20 inet static
    address 10.20.20.1/24
    bridge_ports none
    bridge_stp off
    bridge_fd 0
EOF

echo "[+] Reloading network..."
ifdown vmbr10 2>/dev/null || true
ifdown vmbr20 2>/dev/null || true
ifup vmbr10
ifup vmbr20

### 2️⃣ ENABLE IP FORWARDING ###

echo "[+] Enabling IP forwarding"
sed -i 's/^#*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

### 3️⃣ FIREWALL RULES ###

echo "[+] Setting up firewall rules"

# Get the main network interface (usually vmbr0 or similar)
MAIN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "[+] Detected main interface: $MAIN_INTERFACE"

# Flush existing FORWARD and NAT rules (optional, comment out if you have custom rules)
iptables -F FORWARD
iptables -t nat -F POSTROUTING

# === NAT RULES FOR INTERNET ACCESS ===
# Enable NAT for Dev network (vmbr10) to access internet
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $MAIN_INTERFACE -j MASQUERADE

# Enable NAT for Staging network (vmbr20) to access internet
iptables -t nat -A POSTROUTING -s 10.20.20.0/24 -o $MAIN_INTERFACE -j MASQUERADE

# === FORWARD RULES ===
# Allow internet access from both networks
iptables -A FORWARD -i vmbr10 -o $MAIN_INTERFACE -j ACCEPT
iptables -A FORWARD -i vmbr20 -o $MAIN_INTERFACE -j ACCEPT

# Allow return traffic for established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Dev (vmbr10) -> Staging (vmbr20) only on specific ports (NestJS 3000, DB 3306)
iptables -A FORWARD -i vmbr10 -o vmbr20 -p tcp -m multiport --dports 3000,3306 -j ACCEPT

# Drop all other traffic between Dev and Staging
iptables -A FORWARD -i vmbr10 -o vmbr20 -j DROP
iptables -A FORWARD -i vmbr20 -o vmbr10 -j DROP

# Save iptables rules
echo "[+] Saving iptables rules"
apt-get update -y && apt-get install -y iptables-persistent
apt-get install netfilter-persistent -y
netfilter-persistent save

### 4️⃣ DNS CONFIGURATION ###

echo "[+] Setting up DNS forwarding"
# Install dnsmasq for DNS forwarding (optional but recommended)
apt-get install -y dnsmasq

# Configure dnsmasq for the custom networks
cat <<EOF >/etc/dnsmasq.d/proxmox-networks.conf
# DNS for Dev Network
interface=vmbr10
dhcp-range=vmbr10,10.10.10.100,10.10.10.200,24h
dhcp-option=vmbr10,3,10.10.10.1
dhcp-option=vmbr10,6,8.8.8.8,8.8.4.4

# DNS for Staging Network  
interface=vmbr20
dhcp-range=vmbr20,10.20.20.100,10.20.20.200,24h
dhcp-option=vmbr20,3,10.20.20.1
dhcp-option=vmbr20,6,8.8.8.8,8.8.4.4
EOF

systemctl restart dnsmasq
systemctl enable dnsmasq

### 5️⃣ STATIC IP HINTS ###

echo "[+] Network configuration complete!"
echo ""
echo "=== NETWORK DETAILS ==="
echo "Dev Network (vmbr10):"
echo "  - Network: 10.10.10.0/24"
echo "  - Gateway: 10.10.10.1"
echo "  - DNS: 8.8.8.8, 8.8.4.4"
echo "  - DHCP Range: 10.10.10.100-200 (optional)"
echo "  - Static IPs: Use 10.10.10.2-99 for manual assignment"
echo ""
echo "Staging Network (vmbr20):"
echo "  - Network: 10.20.20.0/24"
echo "  - Gateway: 10.20.20.1"
echo "  - DNS: 8.8.8.8, 8.8.4.4"
echo "  - DHCP Range: 10.20.20.100-200 (optional)"
echo "  - Static IPs: Use 10.20.20.2-99 for manual assignment"
echo ""
echo "=== LXC CONFIGURATION ==="
echo "For static IP configuration in LXCs, edit /etc/network/interfaces:"
echo ""
echo "# Example for Dev LXC (10.10.10.50):"
echo "auto eth0"
echo "iface eth0 inet static"
echo "    address 10.10.10.50/24"
echo "    gateway 10.10.10.1"
echo "    dns-nameservers 8.8.8.8 8.8.4.4"
echo ""
echo "# Example for Staging LXC (10.20.20.10):"
echo "auto eth0"
echo "iface eth0 inet static"
echo "    address 10.20.20.10/24"
echo "    gateway 10.20.20.1"
echo "    dns-nameservers 8.8.8.8 8.8.4.4"

### 6️⃣ ISOLATION BEST PRACTICES ###

echo ""
echo "[+] Enabling Proxmox firewall globally"
pve-firewall start
systemctl enable pve-firewall --now

echo ""
echo "[+] Done! Your Proxmox is now configured with:"
echo "    ✅ vmbr10 (Dev Network: 10.10.10.0/24) with internet access"
echo "    ✅ vmbr20 (Staging Network: 10.20.20.0/24) with internet access"
echo "    ✅ Controlled routing between networks (Dev can access Staging ports 3000,3306)"
echo "    ✅ NAT rules for internet connectivity"
echo "    ✅ Optional DHCP service via dnsmasq"
echo ""
echo "🔍 To test internet connectivity from an LXC:"
echo "    ping 8.8.8.8"
echo "    curl -I https://google.com"
