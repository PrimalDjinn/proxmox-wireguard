#!/bin/bash

# Usage: sudo ./install-openvpn.s
# Fully automated OpenVPN setup on a fresh Debian server

set -euo pipefail

echo "🔹 Starting OpenVPN setup..."

# --- 1️⃣ Install required packages ---
echo "Installing OpenVPN, EasyRSA, and ufw..."
apt update
apt install -y openvpn easy-rsa ufw

# --- 2️⃣ Set up EasyRSA PKI ---
EASYRSA_DIR="/etc/openvpn/easy-rsa"
mkdir -p "$EASYRSA_DIR"
cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
chmod -R 700 "$EASYRSA_DIR"

cd "$EASYRSA_DIR"

# Initialize PKI
echo "Initializing PKI..."
./easyrsa init-pki

# Build CA (non-interactive)
echo "Building CA..."
./easyrsa --batch build-ca nopass

# Generate server certificate and key
echo "Generating server certificate..."
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generate Diffie-Hellman parameters
echo "Generating DH parameters..."
./easyrsa gen-dh

# Generate HMAC key for TLS authentication
openvpn --genkey --secret ta.key

# --- 3️⃣ Create server config ---
SERVER_CONF_DIR="/etc/openvpn/server"
mkdir -p "$SERVER_CONF_DIR"
chmod 700 "$SERVER_CONF_DIR"

cat > "$SERVER_CONF_DIR/server.conf" <<EOF
port 12321
proto udp
dev tun
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/server.crt
key $EASYRSA_DIR/pki/private/server.key
dh $EASYRSA_DIR/pki/dh.pem
tls-auth $EASYRSA_DIR/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
status /run/openvpn-server/status-server.log
verb 3
EOF

# --- 4️⃣ Ensure runtime directory exists ---
mkdir -p /run/openvpn-server
chown nobody:nogroup /run/openvpn-server

# --- 5️⃣ Enable IP forwarding ---
echo "Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1

# --- 6️⃣ Set up UFW rules (optional but recommended) ---
echo "Configuring firewall rules..."
ufw allow 12321/udp
ufw allow OpenSSH
ufw --force enable

# --- 7️⃣ Enable and start OpenVPN ---
echo "Enabling and starting OpenVPN..."
systemctl enable openvpn-server@server
systemctl start openvpn-server@server

# --- 8️⃣ Create client-configs directory ---
CLIENT_CONFIG_DIR="/etc/openvpn/client-configs"
mkdir -p "$CLIENT_CONFIG_DIR"
chmod 700 "$CLIENT_CONFIG_DIR"

echo "✅ OpenVPN setup complete!"
echo "Server running on UDP port 12321"
echo "Client configs should be placed in $CLIENT_CONFIG_DIR"
echo "Use your create-client.sh script to generate clients"


#!/bin/bash

# --- Ensure IP forwarding ---
if [[ "$(sysctl -n net.ipv4.ip_forward)" -ne 1 ]]; then
    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || \
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi

# --- Determine OpenVPN subnet and public interface ---
OVPN_SUBNET="10.8.0.0/24"
PUB_IF="ens3"  # replace with your public interface if different

# --- Add NAT rule if absent ---
if ! iptables -t nat -C POSTROUTING -s "$OVPN_SUBNET" -o "$PUB_IF" -j MASQUERADE &>/dev/null; then
    echo "Adding NAT (MASQUERADE) rule for OpenVPN subnet..."
    iptables -t nat -A POSTROUTING -s "$OVPN_SUBNET" -o "$PUB_IF" -j MASQUERADE
fi

# --- Forward traffic from tun0 to public interface ---
if ! iptables -C FORWARD -i tun0 -o "$PUB_IF" -j ACCEPT &>/dev/null; then
    echo "Allowing forwarding from tun0 to $PUB_IF..."
    iptables -A FORWARD -i tun0 -o "$PUB_IF" -j ACCEPT
fi

# --- Forward return traffic ---
if ! iptables -C FORWARD -i "$PUB_IF" -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT &>/dev/null; then
    echo "Allowing return traffic from $PUB_IF to tun0..."
    iptables -A FORWARD -i "$PUB_IF" -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# --- Ensure VPN port is allowed ---
VPN_PORT=12321
if ! iptables -C INPUT -p udp --dport "$VPN_PORT" -j ACCEPT &>/dev/null; then
    echo "Allowing UDP port $VPN_PORT through firewall..."
    iptables -A INPUT -p udp --dport "$VPN_PORT" -j ACCEPT
fi

echo "✅ NAT and forwarding rules are in place."

