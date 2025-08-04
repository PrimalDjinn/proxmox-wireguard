#!/bin/bash
# Usage: ./remove_client.sh <client_name>

if [ -z "$1" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME="$1"
WG_DIR="/etc/wireguard"
WG_IF="wg0"

cd $WG_DIR

# Check if client config exists
if [ ! -f "${CLIENT_NAME}.conf" ]; then
    echo "Error: Client '$CLIENT_NAME' not found"
    echo "Available clients:"
    ls -1 *.conf 2>/dev/null | grep -v "$WG_IF.conf" | sed 's/.conf$//' || echo "  No clients found"
    exit 1
fi

# Extract client's public key from config
CLIENT_PUB=$(grep -A 10 "\[Peer\]" "${CLIENT_NAME}.conf" | grep "PublicKey" | cut -d'=' -f2 | xargs)

if [ -z "$CLIENT_PUB" ]; then
    # If no public key in client config, extract from private key
    CLIENT_PRIV=$(grep "PrivateKey" "${CLIENT_NAME}.conf" | cut -d'=' -f2 | xargs)
    if [ ! -z "$CLIENT_PRIV" ]; then
        CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    fi
fi

# Get client IP for confirmation
CLIENT_IP=$(grep "Address" "${CLIENT_NAME}.conf" | cut -d'=' -f2 | xargs | cut -d'/' -f1)

# Show client info and confirm removal
echo "Client information:"
echo "  Name: $CLIENT_NAME"
echo "  IP: $CLIENT_IP"
echo "  Public Key: ${CLIENT_PUB:-'Not found'}"
echo ""
read -p "Are you sure you want to remove this client? (y/N): " confirm

if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Operation cancelled"
    exit 0
fi

# Remove client from server's active configuration
if [ ! -z "$CLIENT_PUB" ]; then
    echo "Removing client from active WireGuard interface..."
    wg set $WG_IF peer "$CLIENT_PUB" remove 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[✓] Client removed from active interface"
    else
        echo "[!] Warning: Could not remove from active interface (client may not be connected)"
    fi
else
    echo "[!] Warning: Could not find client's public key, skipping active interface removal"
fi

# Remove client from server config file and save
echo "Updating server configuration..."
if [ ! -z "$CLIENT_PUB" ]; then
    # Create a temporary file without the client's peer section
    awk -v pubkey="$CLIENT_PUB" '
    BEGIN { skip = 0 }
    /^\[Peer\]/ { 
        peer_section = ""
        while ((getline line) > 0 && line !~ /^\[/) {
            peer_section = peer_section line "\n"
            if (line ~ /^PublicKey/ && line ~ pubkey) {
                skip = 1
                break
            }
        }
        if (!skip) {
            print "[Peer]"
            printf "%s", peer_section
            if (line ~ /^\[/) print line
        } else {
            skip = 0
            if (line ~ /^\[/) print line
        }
        next
    }
    { print }
    ' "$WG_IF.conf" >"${WG_IF}.conf.tmp"

    # Replace original config with cleaned version
    mv "${WG_IF}.conf.tmp" "$WG_IF.conf"
    echo "[✓] Server configuration updated"
else
    echo "[!] Warning: Could not update server config (public key not found)"
fi

# Save the current WireGuard configuration
wg-quick save $WG_IF 2>/dev/null

# Remove client config file
rm -f "${CLIENT_NAME}.conf"
echo "[✓] Client configuration file removed"

echo ""
echo "[✓] Client '$CLIENT_NAME' has been completely removed!"
echo ""

# Show remaining clients
echo "Remaining clients:"
remaining_clients=$(ls -1 *.conf 2>/dev/null | grep -v "$WG_IF.conf" | sed 's/.conf$//')
if [ -z "$remaining_clients" ]; then
    echo "  No clients remaining"
else
    echo "$remaining_clients" | sed 's/^/  /'
fi
