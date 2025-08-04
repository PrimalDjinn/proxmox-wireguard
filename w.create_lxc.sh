#!/bin/bash
set -e

# Function to validate IP address
validate_ip() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<<"$ip"
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        stat=0
    fi
    return $stat
}

echo "=== Proxmox LXC Container Creator ==="

# Check if running on Proxmox
if ! command -v pct &>/dev/null; then
    echo "Error: pct command not found. Is Proxmox VE installed?"
    exit 1
fi

# Auto-detect next CTID
NEXTID=$(pct list | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort -n | tail -1)
CTID=$((${NEXTID:-100} + 1))
echo "[+] Using container ID: $CTID"

# Detect storage
echo "[+] Detecting storages..."
mapfile -t STORAGES < <(pvesm status | awk 'NR>1 {print $1}')
if [ ${#STORAGES[@]} -eq 0 ]; then
    echo "Error: No storages found!"
    echo "Debug: Running 'pvesm status' to check available storages..."
    pvesm status
    exit 1
fi
for i in "${!STORAGES[@]}"; do
    echo "  $((i + 1))) ${STORAGES[$i]}"
done
read -p "Select storage [1-${#STORAGES[@]}]: " SIDX
if [[ ! "$SIDX" =~ ^[0-9]+$ ]] || [ "$SIDX" -lt 1 ] || [ "$SIDX" -gt ${#STORAGES[@]} ]; then
    echo "Error: Invalid storage selection!"
    exit 1
fi
STORAGE=${STORAGES[$((SIDX - 1))]}

# Detect bridges
echo "[+] Detecting Proxmox bridges..."
mapfile -t BRIDGES < <(ip link show | grep -oP 'vmbr[0-9]+' | sort -u)
if [ ${#BRIDGES[@]} -eq 0 ]; then
    echo "Error: No network bridges found!"
    exit 1
fi
for i in "${!BRIDGES[@]}"; do
    IP=$(ip -4 addr show "${BRIDGES[$i]}" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1 || echo "No IP")
    echo "  $((i + 1))) ${BRIDGES[$i]} ($IP)"
done
read -p "Select network [1-${#BRIDGES[@]}]: " BIDX
if [[ ! "$BIDX" =~ ^[0-9]+$ ]] || [ "$BIDX" -lt 1 ] || [ "$BIDX" -gt ${#BRIDGES[@]} ]; then
    echo "Error: Invalid bridge selection!"
    exit 1
fi
BRIDGE=${BRIDGES[$((BIDX - 1))]}

# Detect available templates
echo "[+] Detecting available LXC templates..."
echo "Updating template list..."
pveam update >/dev/null 2>&1 || true

mapfile -t TEMPLATES < <(pveam available | grep -E "(ubuntu|debian).*standard" | awk '{print $2 " " $3}')
if [ ${#TEMPLATES[@]} -eq 0 ]; then
    echo "Error: No Ubuntu/Debian templates available!"
    echo "You may need to download a template first with: pveam download local <template>"
    exit 1
fi

echo "Available templates:"
for i in "${!TEMPLATES[@]}"; do
    echo "  $((i + 1))) ${TEMPLATES[$i]}"
done
read -p "Select template [1-${#TEMPLATES[@]}]: " TIDX
if [[ ! "$TIDX" =~ ^[0-9]+$ ]] || [ "$TIDX" -lt 1 ] || [ "$TIDX" -gt ${#TEMPLATES[@]} ]; then
    echo "Error: Invalid template selection!"
    exit 1
fi
TEMPLATE=$(echo "${TEMPLATES[$((TIDX - 1))]}" | awk '{print $1}')

# Check if template is downloaded
if ! pveam list local | grep -q "$TEMPLATE"; then
    echo "[+] Downloading template $TEMPLATE..."
    pveam download local "$TEMPLATE"
fi

read -p "Container name: " NAME
if [[ -z "$NAME" || ! "$NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Invalid container name!"
    exit 1
fi

read -s -p "Root password: " ROOTPASS
echo
if [[ -z "$ROOTPASS" ]]; then
    echo "Error: Password cannot be empty!"
    exit 1
fi

read -p "Container IP (e.g. 192.168.1.100): " IPADDR
if ! validate_ip "$IPADDR"; then
    echo "Error: Invalid IP address format!"
    exit 1
fi

# Check for IP collision more precisely
if pct list | awk 'NR>1 {print $0}' | grep -qw "$IPADDR"; then
    echo "Error: IP address $IPADDR already in use!"
    exit 1
fi

# Auto-detect gateway from bridge IP
BRIDGE_IP=$(ip -4 addr show "$BRIDGE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [[ -n "$BRIDGE_IP" ]]; then
    GATEWAY="$BRIDGE_IP"
else
    read -p "Gateway IP (e.g. 192.168.1.1): " GATEWAY
    if ! validate_ip "$GATEWAY"; then
        echo "Error: Invalid gateway IP!"
        exit 1
    fi
fi

read -p "Number of CPU cores [blank=unlimited]: " CORES
if [[ -n "$CORES" && ! "$CORES" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid number of CPU cores!"
    exit 1
fi

read -p "Memory in MB [default=2048]: " MEMORY
MEMORY=${MEMORY:-2048}
if [[ ! "$MEMORY" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid memory amount!"
    exit 1
fi

echo "[+] Creating container $CTID ($NAME)"
CREATE_CMD="pct create $CTID local:vztmpl/$TEMPLATE \
    --hostname $NAME \
    --rootfs $STORAGE:8 \
    --memory $MEMORY \
    --swap 512 \
    --net0 name=eth0,bridge=$BRIDGE,gw=$GATEWAY,ip=$IPADDR/24,type=veth \
    --password $ROOTPASS \
    --unprivileged 1 \
    --features nesting=1 \
    --onboot 0"

# Only add cores if specified
if [[ -n "$CORES" ]]; then
    CREATE_CMD="$CREATE_CMD --cores $CORES"
fi

eval "$CREATE_CMD"

echo "[+] Starting container..."
pct start "$CTID"

# Wait for container to be ready
echo "[+] Waiting for container to be ready..."
sleep 10

# Basic container setup
echo "[+] Configuring container..."
pct exec "$CTID" -- bash -c "
    # Update package list
    apt-get update -qq
    
    # Enable SSH root login
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart ssh || service ssh restart
    
    # Set timezone
    timedatectl set-timezone UTC || true
    
    echo 'Container setup completed'
"

echo ""
echo "[✓] LXC container created successfully!"
echo ""
echo "=== Container Details ==="
echo "Container ID: $CTID"
echo "Name: $NAME"
echo "IP: $IPADDR"
echo "Gateway: $GATEWAY"
echo "Memory: ${MEMORY}MB"
echo "Cores: ${CORES:-unlimited}"
echo "Storage: $STORAGE"
echo "Bridge: $BRIDGE"
echo ""
echo "=== Access Information ==="
echo "SSH: ssh root@$IPADDR"
echo "Proxmox console: pct enter $CTID"
echo ""
echo "[DONE] Container is ready for use!"
