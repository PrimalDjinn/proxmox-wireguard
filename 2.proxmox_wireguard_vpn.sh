#!/bin/bash
# proxmox_wireguard_vpn.sh
# WireGuard VPN setup for Proxmox with LXC subnet access
set -euo pipefail

WG_IF="wg0"
WG_PORT=${WG_PORT:-51820}
WG_DIR="/etc/wireguard"
DNS=${DNS:-"1.1.1.1"}

# Your LXC subnets
LXC_SUBNETS=("10.10.10.0/24" "20.20.20.0/24")

# === UTILS ===
validate_ip() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        echo "Invalid IP: $1"
        exit 1
    }
}

get_used_subnets() {
    echo "[*] Scanning used subnets..."
    used_ips=$(ip -o addr show | awk '{print $4}' | grep -E '^[0-9]+\.')

    # Add LXC IPs
    for ctid in $(pct list | awk 'NR>1 {print $1}' 2>/dev/null || true); do
        ips=$(pct exec $ctid -- ip -o -4 addr show 2>/dev/null | awk '{print $4}' || true)
        used_ips="$used_ips"$'\n'"$ips"
    done

    # Convert to /24 subnets and unique sort
    echo "$used_ips" | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u
}

find_free_subnet() {
    used=$(get_used_subnets)
    for n in {100..250}; do
        candidate="10.${n}.${n}.0/24"
        if ! grep -q "$candidate" <<<"$used" && [[ "$candidate" != "10.10.10.0/24" ]] && [[ "$candidate" != "10.20.20.0/24" ]]; then
            echo "$candidate"
            return
        fi
    done
    echo "Error: No free subnet found" >&2
    exit 1
}

# === MAIN ===
echo "=== Proxmox WireGuard VPN Setup for LXC Access ==="

echo "[+] Installing WireGuard if missing..."
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables-persistent curl

mkdir -p $WG_DIR && cd $WG_DIR

# === SERVER KEYS ===
if [ ! -s server_private.key ] || [ ! -s server_public.key ]; then
    echo "[+] Generating server keys..."
    wg genkey | tee server_private.key | wg pubkey >server_public.key
    chmod 600 server_private.key
fi

SERVER_PRIV=$(cat server_private.key)
SERVER_PUB=$(cat server_public.key)

# === DETECT PUBLIC IP ===
if [[ -z "${PUBLIC_IP:-}" ]]; then
    echo "[+] Detecting public IP..."
    PUBLIC_IP=$(curl -s https://api.ipify.org || wget -qO- https://api.ipify.org || echo "")
fi
if [[ -z "$PUBLIC_IP" ]]; then
    echo "[!] Could not auto-detect public IP."
    read -p "Enter public IP manually: " PUBLIC_IP
fi
echo "[*] Public IP: $PUBLIC_IP"

# === VPN NETWORK (avoid conflicts with LXC subnets) ===
VPN_NET=$(find_free_subnet)
WG_SERVER_IP=$(echo "$VPN_NET" | sed 's/0\/24/1/')

read -p "Use detected free VPN subnet [$VPN_NET]: " custom_net
VPN_NET=${custom_net:-$VPN_NET}
WG_SERVER_IP=$(echo "$VPN_NET" | sed 's/0\/24/1/')

echo "[+] Using VPN network: $VPN_NET (Server IP: $WG_SERVER_IP)"

# === INTERFACE DETECTION ===
EXT_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
echo "[*] External interface detected: $EXT_IF"

# === CREATE WG CONFIG ===

touch $WG_IF-client-rules
touch $WG_IF-client-data
chmod +x $WG_IF-client-rules
cat >$WG_IF.conf <<EOF
[Interface]
Address = $WG_SERVER_IP/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s 10.100.100.0/24 -o vmbr0 -j MASQUERADE
PostUp = /etc/wireguard/wg0-client-rules
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.100.100.0/24 -o vmbr0 -j MASQUERADE
EOF

chmod +x $WG_IF.conf

echo "[+] Enabling IP forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf

systemctl enable wg-quick@$WG_IF
systemctl restart wg-quick@$WG_IF || {
    echo "[!] Failed to start WireGuard. Check wg0.conf."
    systemctl status wg-quick@$WG_IF
    exit 1
}

# Allow WireGuard port through firewall
iptables -C INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT
iptables-save >/etc/iptables/rules.v4

echo "[✓] WireGuard VPN server ready!"
echo ""
echo "=== SERVER INFO ==="
echo "Server Public Key: $SERVER_PUB"
echo "Server VPN IP: $WG_SERVER_IP"
echo "VPN Subnet: $VPN_NET"
echo "Public IP: $PUBLIC_IP"
echo "UDP Port: $WG_PORT"
echo ""
echo "=== ACCESSIBLE NETWORKS ==="
echo "Dev Network: 10.10.10.0/24 (gateway: 10.10.10.1)"
echo "Staging Network: 10.20.20.0/24 (gateway: 10.20.20.1)"
echo ""

# chmod +x add_client.sh

echo ""
echo "=== CLIENT SETUP ==="
echo "1. Create a client config:"
echo "   ./add_client.sh myclient"
echo ""
echo "=== TEST ACCESS ==="
echo "Once connected via VPN, you should be able to access:"
echo "- Dev LXCs: ping 10.10.10.x"
echo "- Staging LXCs: ping 10.20.20.x"
echo "- SSH to LXCs: ssh user@10.10.10.x"
