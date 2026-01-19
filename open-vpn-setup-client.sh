#!/bin/bash

# Usage: sudo ./create-client.sh clientname
# Fully automated, includes tls-auth HMAC key

set -euo pipefail

CLIENT_NAME="${1:-}"
if [[ -z "$CLIENT_NAME" ]]; then
    echo "Error: No client name specified."
    echo "Usage: $0 clientname"
    exit 1
fi

# Paths
EASYRSA_DIR="/etc/openvpn/easy-rsa"
EASYRSA_PKI="$EASYRSA_DIR/pki"
OUTPUT_DIR="/etc/openvpn/client-configs"
SERVER_IP="148.113.201.198"   # Update to your public IP
SERVER_PORT="12321"
TA_KEY="$EASYRSA_DIR/ta.key"

# Check required files exist
for f in "$EASYRSA_PKI/ca.crt" "$TA_KEY"; do
    if [[ ! -f "$f" ]]; then
        echo "Error: Required file $f is missing."
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

cd "$EASYRSA_DIR"

# Generate client key/csr if not exists
if [[ ! -f "$EASYRSA_PKI/private/$CLIENT_NAME.key" ]]; then
    echo "Generating key for client $CLIENT_NAME..."
    ./easyrsa gen-req "$CLIENT_NAME" nopass
fi

# Sign client cert if not exists
if [[ ! -f "$EASYRSA_PKI/issued/$CLIENT_NAME.crt" ]]; then
    echo "Signing client certificate for $CLIENT_NAME..."
    ./easyrsa sign-req client "$CLIENT_NAME"
fi

# Paths for certs/keys
CA_CERT="$EASYRSA_PKI/ca.crt"
CLIENT_CERT="$EASYRSA_PKI/issued/$CLIENT_NAME.crt"
CLIENT_KEY="$EASYRSA_PKI/private/$CLIENT_NAME.key"

# Generate .ovpn config with embedded certs and ta.key
OVPN_FILE="$OUTPUT_DIR/$CLIENT_NAME.ovpn"

cat > "$OVPN_FILE" <<EOF
client
dev tun
proto udp
remote $SERVER_IP $SERVER_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
key-direction 1

<ca>
$(cat "$CA_CERT")
</ca>

<cert>
$(awk '/BEGIN/,/END/' "$CLIENT_CERT")
</cert>

<key>
$(cat "$CLIENT_KEY")
</key>

<tls-auth>
$(cat "$TA_KEY")
</tls-auth>
EOF

echo "✅ Client config created at: $OVPN_FILE"

