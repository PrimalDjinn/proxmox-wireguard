#!/bin/bash

# Usage: sudo ./remove-client.sh clientname
# Fully removes an OpenVPN client

set -euo pipefail

CLIENT_NAME="${1:-}"
if [[ -z "$CLIENT_NAME" ]]; then
    echo "Error: No client name specified."
    echo "Usage: $0 clientname"
    exit 1
fi

EASYRSA_DIR="/etc/openvpn/easy-rsa"
EASYRSA_PKI="$EASYRSA_DIR/pki"
CLIENT_OVPN="/etc/openvpn/client-configs/$CLIENT_NAME.ovpn"

cd "$EASYRSA_DIR"

# Check if client cert exists
if [[ ! -f "$EASYRSA_PKI/issued/$CLIENT_NAME.crt" ]]; then
    echo "Client $CLIENT_NAME does not exist. Nothing to revoke."
else
    echo "Revoking client certificate for $CLIENT_NAME..."
    # Revoke the certificate
    ./easyrsa --batch revoke "$CLIENT_NAME"

    # Generate updated CRL
    ./easyrsa gen-crl

    # Move the CRL to OpenVPN directory
    cp "$EASYRSA_PKI/crl.pem" /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    echo "Certificate revoked and CRL updated."
fi

# Remove client keys and certificates
for f in "$EASYRSA_PKI/issued/$CLIENT_NAME.crt" "$EASYRSA_PKI/private/$CLIENT_NAME.key" \
         "$EASYRSA_PKI/reqs/$CLIENT_NAME.req"; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        echo "Deleted $f"
    fi
done

# Remove the client .ovpn config
if [[ -f "$CLIENT_OVPN" ]]; then
    rm -f "$CLIENT_OVPN"
    echo "Deleted $CLIENT_OVPN"
fi

echo "✅ Client $CLIENT_NAME successfully removed."

