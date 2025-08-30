#!/bin/bash
# Usage: ./add_client.sh <client_name>

if [ -z "$1" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME="$1"
WG_DIR="/etc/wireguard"
WG_IF="wg0"
CLIENT_RULES_FILE="/etc/wireguard/wg0-client-rules"
DATA_FILE="/etc/wireguard/wg0-client-data"

cd $WG_DIR || exit

# Initialize files if they don't exist
touch "$CLIENT_RULES_FILE"
touch "$DATA_FILE"

# Read server config
SERVER_PUB=$(cat server_public.key)
VPN_NET=$(grep "Address" $WG_IF.conf | cut -d'=' -f2 | xargs | cut -d'/' -f1 | cut -d'.' -f1-3)
SERVER_IP=$(grep "Address" $WG_IF.conf | cut -d'=' -f2 | xargs)
WG_PORT=$(grep "ListenPort" $WG_IF.conf | cut -d'=' -f2 | xargs)

# Get server public IP with dynamic default
PUBLIC_IP_DEFAULT=$(curl -4 -s ifconfig.co || echo "")
echo "Enter the server's public IP address (default: ${PUBLIC_IP_DEFAULT:-None}):"
read -p "Server IP: " PUBLIC_IP
PUBLIC_IP=${PUBLIC_IP:-$PUBLIC_IP_DEFAULT}

# Validate IP format
if ! [[ $PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address format"
    exit 1
fi

# Find next available client IP
NEXT_IP=2
# Create an array of used IPs from client configs only
USED_IPS=()
for conf in *.conf; do
    # Skip server configuration file
    if [[ "$conf" == "$WG_IF.conf" ]]; then
        continue
    fi
    # Extract IP from client configs
    ip=$(grep -oP 'Address\s*=\s*\K[0-9.]+' "$conf" 2>/dev/null)
    if [[ -n "$ip" ]]; then
        USED_IPS+=("$ip")
    fi
done

# Find next available IP
while :; do
    CLIENT_IP="${VPN_NET}.${NEXT_IP}"
    # Check if IP is in use
    if ! printf '%s\n' "${USED_IPS[@]}" | grep -q "^${CLIENT_IP}$"; then
        # Additional check to ensure IP isn't in server config
        if ! grep -q "${CLIENT_IP}" "$WG_IF.conf"; then
            break
        fi
    fi

    NEXT_IP=$((NEXT_IP + 1))
    if [ $NEXT_IP -gt 254 ]; then
        echo "Error: No available IPs"
        exit 1
    fi
done

CLIENT_IP="${VPN_NET}.${NEXT_IP}"

# Prompt for allowed IPs
echo ""
echo "Enter allowed networks/IPs (comma separated) for this client:"
echo "Examples:"
echo "  - Single VM: 10.10.10.123/32"
echo "  - Multiple VMs: 10.10.10.123/32,10.20.20.45/32"
echo "  - Entire network: 10.10.10.0/24"
echo ""
read -p "AllowedIPs: " ALLOWED_IPS

# Validate input
if [ -z "$ALLOWED_IPS" ]; then
    echo "Error: AllowedIPs cannot be empty"
    exit 1
fi

# Generate client keys
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Create client config
cat >"${CLIENT_NAME}.conf" <<EOC
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_IP/24

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $PUBLIC_IP:$WG_PORT
AllowedIPs = ${ALLOWED_IPS// /}
PersistentKeepalive = 25
EOC

# Add client to server config
wg set $WG_IF peer "$CLIENT_PUB" allowed-ips "$CLIENT_IP/32"
wg-quick save $WG_IF

# Add firewall rules and save to data file
IFS=',' read -ra IPS <<<"${ALLOWED_IPS// /}"
