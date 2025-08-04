#!/bin/bash
# Removes all WireGuard clients (peers) from wg0.conf and live interface

WG_IF="wg0"
WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/$WG_IF.conf"

if [ ! -f "$WG_CONF" ]; then
    echo "[!] WireGuard config $WG_CONF not found."
    exit 1
fi

echo "=== Removing all clients from $WG_CONF ==="

# Backup existing config
cp "$WG_CONF" "$WG_CONF.bak.$(date +%s)"
echo "[*] Backup saved to $WG_CONF.bak.$(date +%s)"

# Extract all public keys (peers)
peers=$(grep -A1 "^\[Peer\]" "$WG_CONF" | grep PublicKey | awk '{print $3}')

if [ -z "$peers" ]; then
    echo "[*] No clients found in config."
else
    echo "[*] Found peers:"
    echo "$peers"
    for pk in $peers; do
        echo "[-] Removing peer $pk"
        wg set $WG_IF peer $pk remove 2>/dev/null || true
    done
fi

# Remove all [Peer] blocks from config
tmp=$(mktemp)
awk '
    BEGIN { skip=0 }
    /^\[Peer\]/ { skip=1 }
    skip && NF==0 { skip=0; next }
    !skip
' "$WG_CONF" > "$tmp"
mv "$tmp" "$WG_CONF"

chmod 600 "$WG_CONF"
wg syncconf $WG_IF <(wg-quick strip $WG_IF)

echo "[✓] All clients removed. Only server [Interface] remains."
