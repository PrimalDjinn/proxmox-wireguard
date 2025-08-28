#!/bin/bash
# proxmox_wireguard_vpn.sh
# WireGuard VPN setup for Proxmox with LXC subnet access + hardened client generator
set -euo pipefail

WG_IF="wg0"
WG_PORT=${WG_PORT:-51820}
WG_DIR="/etc/wireguard"
DNS=${DNS:-"1.1.1.1"}

# Your LXC subnets (destinations VPN clients can reach)
LXC_SUBNETS=("10.10.10.0/24" "10.20.20.0/24")

# === UTILS ===
validate_ip() {
  [[ ${1:-} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

get_used_subnets() {
  echo "[*] Scanning used subnets..."
  used_ips=$(ip -o addr show | awk '{print $4}' | grep -E '^[0-9]+\.') || true

  # Add LXC IPs
  for ctid in $(pct list 2>/dev/null | awk 'NR>1 {print $1}' || true); do
    ips=$(pct exec "$ctid" -- ip -o -4 addr show 2>/dev/null | awk '{print $4}' || true)
    used_ips="$used_ips"$'\n'"$ips"
  done

  # Convert to /24 subnets and unique sort
  echo "$used_ips" | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u
}

find_free_subnet() {
  used=$(get_used_subnets)
  for n in {100..250}; do
    candidate="10.${n}.${n}.0/24"
    if ! grep -qE "^${candidate}\$" <<<"$used" \
       && [[ ! " ${LXC_SUBNETS[*]} " =~ " ${candidate} " ]]; then
      echo "$candidate"
      return
    fi
  done
  echo "Error: No free /24 subnet found in 10.0.0.0/8" >&2
  exit 1
}

cidr_mask_bits() {
  # Expects CIDR like 10.1.2.0/24 -> prints 24
  echo "$1" | awk -F/ '{print $2}'
}

cidr_network() {
  # Expects CIDR like 10.1.2.0/24 -> prints 10.1.2.0
  echo "$1" | awk -F/ '{print $1}'
}

network_first_three() {
  # For /24 only: 10.1.2.0 -> 10.1.2
  echo "$1" | awk -F. '{print $1"."$2"."$3}'
}

# === MAIN ===
echo "=== Proxmox WireGuard VPN Setup for LXC Access (hardened) ==="

echo "[+] Installing WireGuard if missing..."
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables-persistent curl

mkdir -p "$WG_DIR" && cd "$WG_DIR"

# === SERVER KEYS ===
if [ ! -s server_private.key ] || [ ! -s server_public.key ]; then
  echo "[+] Generating server keys..."
  wg genkey | tee server_private.key | wg pubkey > server_public.key
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
  read -rp "Enter public IP manually: " PUBLIC_IP
fi
echo "[*] Public IP: $PUBLIC_IP"

# === VPN NETWORK (avoid conflicts with LXC subnets) ===
VPN_CIDR=$(find_free_subnet)          # e.g. 10.x.x.0/24
VPN_NET=$(cidr_network "$VPN_CIDR")   # e.g. 10.x.x.0
MASK_BITS=$(cidr_mask_bits "$VPN_CIDR") # 24
VPN_FIRST3=$(network_first_three "$VPN_NET")
WG_SERVER_IP="${VPN_FIRST3}.1"        # Reserve .1 for server

read -rp "Use detected free VPN subnet [$VPN_CIDR]: " custom_net
if [[ -n "${custom_net:-}" ]]; then
  VPN_CIDR="$custom_net"
  VPN_NET=$(cidr_network "$VPN_CIDR")
  MASK_BITS=$(cidr_mask_bits "$VPN_CIDR")
  if [[ "$MASK_BITS" != "24" ]]; then
    echo "For now this script expects a /24 (got /$MASK_BITS). Aborting to avoid misconfig."
    exit 1
  fi
  VPN_FIRST3=$(network_first_three "$VPN_NET")
  WG_SERVER_IP="${VPN_FIRST3}.1"
fi

echo "[+] Using VPN network: $VPN_CIDR (Server IP: $WG_SERVER_IP/$MASK_BITS)"

# === INTERFACE DETECTION ===
EXT_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
echo "[*] External interface detected: $EXT_IF"

# === CREATE WG CONFIG ===
cat > "$WG_IF.conf" <<EOF
[Interface]
Address = ${WG_SERVER_IP}/${MASK_BITS}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}

# Forward rules for VPN access to LXC subnets
PostUp   = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -j ACCEPT
PostUp   = iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %i -j ACCEPT

# Allow VPN clients to access LXC networks (no NAT needed internally)
$(for s in "${LXC_SUBNETS[@]}"; do
  echo "PostUp   = iptables -C FORWARD -s ${VPN_CIDR} -d ${s} -j ACCEPT 2>/dev/null || iptables -A FORWARD -s ${VPN_CIDR} -d ${s} -j ACCEPT"
done)

# Allow return traffic from LXC networks to VPN
$(for s in "${LXC_SUBNETS[@]}"; do
  echo "PostUp   = iptables -C FORWARD -s ${s} -d ${VPN_CIDR} -j ACCEPT 2>/dev/null || iptables -A FORWARD -s ${s} -d ${VPN_CIDR} -j ACCEPT"
done)

# Optional: NAT for VPN internet access (comment out if not needed)
PostUp   = iptables -t nat -C POSTROUTING -s ${VPN_CIDR} -o ${EXT_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${VPN_CIDR} -o ${EXT_IF} -j MASQUERADE

# Cleanup rules
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
$(for s in "${LXC_SUBNETS[@]}"; do
  echo "PostDown = iptables -D FORWARD -s ${VPN_CIDR} -d ${s} -j ACCEPT 2>/dev/null || true"
done)
$(for s in "${LXC_SUBNETS[@]}"; do
  echo "PostDown = iptables -D FORWARD -s ${s} -d ${VPN_CIDR} -j ACCEPT 2>/dev/null || true"
done)
PostDown = iptables -t nat -D POSTROUTING -s ${VPN_CIDR} -o ${EXT_IF} -j MASQUERADE 2>/dev/null || true
EOF

chmod 600 "$WG_IF.conf"

echo "[+] Enabling IP forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

systemctl enable "wg-quick@${WG_IF}"
systemctl restart "wg-quick@${WG_IF}" || {
  echo "[!] Failed to start WireGuard. Check ${WG_IF}.conf."
  systemctl status "wg-quick@${WG_IF}" || true
  exit 1
}

# Allow WireGuard port through firewall
iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT
iptables-save > /etc/iptables/rules.v4

echo "[✓] WireGuard VPN server ready!"
echo ""
echo "=== SERVER INFO ==="
echo "Server Public Key: $SERVER_PUB"
echo "Server VPN IP: $WG_SERVER_IP/$MASK_BITS"
echo "VPN Subnet: $VPN_CIDR"
echo "Public IP: $PUBLIC_IP"
echo "UDP Port: $WG_PORT"
echo ""
echo "=== ACCESSIBLE NETWORKS ==="
for s in "${LXC_SUBNETS[@]}"; do echo "- $s"; done
echo ""

# === CLIENT CONFIG GENERATOR (HARDENED) ===
echo "[+] Creating client config generator..."

# Build a comma-separated list of LXC subnets for client AllowedIPs
LXC_ALLOWED_CSV="$(IFS=, ; echo "${LXC_SUBNETS[*]}")"

cat > add_client.sh <<'EOS'
#!/bin/bash
# Usage: ./add_client.sh <client_name> [--extra "cidr1,cidr2,..."]
# Hardened: reserves .1 for server, finds next free IP, validates, and keeps server AllowedIPs to client's /32 only.
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <client_name> [--extra \"cidr1,cidr2,...\"]"
  exit 1
fi

CLIENT_NAME="$1"; shift || true
EXTRA_ALLOWED=""
while [[ "${1:-}" == "--extra" ]]; do
  shift
  EXTRA_ALLOWED="${1:-}"; shift || true
done

WG_DIR="/etc/wireguard"
WG_IF="wg0"
cd "$WG_DIR"

# Read server config details
SERVER_PUB=$(cat server_public.key)
SERVER_ADDR_CIDR=$(awk -F'=' '/^Address/ {gsub(/ /,"",$2); print $2; exit}' "$WG_IF.conf")
SERVER_ADDR="${SERVER_ADDR_CIDR%/*}"
MASK_BITS="${SERVER_ADDR_CIDR#*/}"

if [[ "$MASK_BITS" != "24" ]]; then
  echo "This generator expects server /24 (got /$MASK_BITS). Aborting to avoid mis-assignments."
  exit 1
fi

VPN_FIRST3=$(echo "$SERVER_ADDR" | awk -F. '{print $1"."$2"."$3}')
VPN_NET="${VPN_FIRST3}.0/${MASK_BITS}"
SERVER_VPN_IP="${VPN_FIRST3}.1"
WG_PORT=$(awk -F'=' '/^ListenPort/ {gsub(/ /,"",$2); print $2; exit}' "$WG_IF.conf")

# Determine public IP to embed into endpoint
PUBLIC_IP="$(curl -s https://api.ipify.org || echo "")"
if [[ -z "$PUBLIC_IP" ]]; then
  echo "⚠️  Could not auto-detect public IP. The client file will contain PUBLIC_IP_PLACEHOLDER."
  PUBLIC_IP="PUBLIC_IP_PLACEHOLDER"
fi

# Safety: Do not overwrite existing client file
if [[ -e "${CLIENT_NAME}.conf" ]]; then
  echo "❌ ${CLIENT_NAME}.conf already exists. Choose a different client name or remove the file."
  exit 1
fi

# Collect used IPs from existing configs and from live wg (if any)
declare -A USED
# From files
for f in *.conf; do
  [[ -f "$f" ]] || continue
  ip=$(awk -F'=' '/^\[Interface\]/{f=1} f&&/^Address/ {gsub(/ /,"",$2); print $2; exit}' "$f" | cut -d'/' -f1)
  [[ -n "$ip" ]] && USED["$ip"]=1
done
# From live wg
if command -v wg >/dev/null 2>&1; then
  wg show "$WG_IF" allowed-ips 2>/dev/null | awk '{print $3}' | tr ',' '\n' | while read -r cidr; do
    [[ -n "$cidr" ]] || continue
    ip="${cidr%/*}"
    USED["$ip"]=1
  done
fi
# Always mark server .1 as used
USED["$SERVER_VPN_IP"]=1

# Find next free IP (.2 -> .254)
NEXT=2
ALLOC_IP=""
while (( NEXT <= 254 )); do
  candidate="${VPN_FIRST3}.${NEXT}"
  if [[ -z "${USED[$candidate]:-}" ]]; then
    ALLOC_IP="$candidate"
    break
  fi
  ((NEXT++))
done

if [[ -z "$ALLOC_IP" ]]; then
  echo "❌ No available IPs left in ${VPN_FIRST3}.0/24"
  exit 1
fi

if [[ "$ALLOC_IP" == "$SERVER_VPN_IP" ]]; then
  echo "❌ Refusing to assign server IP ($ALLOC_IP) to client."
  exit 1
fi

# Generate client keys
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Build AllowedIPs (destinations) = LXC subnets + VPN subnet + optional extras
# LXC_ALLOWED_CSV is substituted by the parent script at generation time.
LXC_ALLOWED_CSV="__LXC_ALLOWED_CSV__"
DEST_ALLOWED="$LXC_ALLOWED_CSV,${VPN_FIRST3}.0/${MASK_BITS}"
if [[ -n "$EXTRA_ALLOWED" ]]; then
  # Clean spaces
  EXTRA_ALLOWED=$(echo "$EXTRA_ALLOWED" | sed 's/ //g')
  if [[ -n "$EXTRA_ALLOWED" ]]; then
    DEST_ALLOWED="${DEST_ALLOWED},${EXTRA_ALLOWED}"
  fi
fi

# Create client config
cat > "${CLIENT_NAME}.conf" <<EOC
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${ALLOC_IP}/${MASK_BITS}
DNS = ${DNS:-1.1.1.1}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${PUBLIC_IP}:${WG_PORT}
AllowedIPs = ${DEST_ALLOWED}
PersistentKeepalive = 25
EOC

# Add client to server config: only allow source from the client's single VPN IP (/32)
wg set "$WG_IF" peer "$CLIENT_PUB" allowed-ips "${ALLOC_IP}/32"
wg-quick save "$WG_IF"

echo "[✓] Client '${CLIENT_NAME}' created!"
echo "Config file: ${CLIENT_NAME}.conf"
echo "Client IP: ${ALLOC_IP}/${MASK_BITS}"
echo "Dest AllowedIPs: ${DEST_ALLOWED}"
if [[ "$PUBLIC_IP" == "PUBLIC_IP_PLACEHOLDER" ]]; then
  echo "⚠️  Replace PUBLIC_IP_PLACEHOLDER with your actual public IP."
fi

# Optional QR Code
if command -v qrencode >/dev/null 2>&1; then
  qrencode -t ansiutf8 < "${CLIENT_NAME}.conf"
fi
EOS

# Substitute variables into the generated add_client.sh
# 1) Inject DNS default
sed -i "s|\${DNS:-1.1.1.1}|${DNS}|g" add_client.sh
# 2) Inject LXC AllowedIPs CSV
sed -i "s|__LXC_ALLOWED_CSV__|${LXC_ALLOWED_CSV}|g" add_client.sh
chmod +x add_client.sh

echo ""
echo "=== CLIENT SETUP ==="
echo "1) Create a client config:"
echo "   cd ${WG_DIR} && ./add_client.sh myclient"
echo "   (Optionally add extra allowed destinations) e.g.:"
echo "   ./add_client.sh myclient --extra \"10.30.30.0/24,192.168.1.0/24\""
echo ""
echo "2) Copy the generated .conf to your device and import it."
echo "3) Connect and test access to: ${LXC_SUBNETS[*]} and ${VPN_CIDR}"
