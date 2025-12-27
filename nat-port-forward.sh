#!/usr/bin/env bash
set -e

### CONFIG DEFAULTS ###
DEFAULT_LXC_IP="10.10.10.4"
VM_SUBNET="10.10.10.0/24"

### COLORS ###
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

### UTILS ###
pause() { read -rp "Press Enter to continue..."; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${RESET}"
    exit 1
  fi
}

detect_iface() {
  ip route get 8.8.8.8 | awk '{print $5; exit}'
}

install_deps() {
  echo -e "${BLUE}[*] Installing dependencies...${RESET}"
  apt update -qq
  apt install -y iptables iptables-persistent net-tools >/dev/null
}

enable_forwarding() {
  if sysctl -n net.ipv4.ip_forward | grep -q 0; then
    echo -e "${YELLOW}[*] Enabling IP forwarding${RESET}"
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >/dev/null
  fi
}

setup_docker_compatibility() {
  echo -e "${BLUE}[*] Setting up Docker/nftables compatibility...${RESET}"
  
  # Allow VM subnet through Docker's FORWARD chain via DOCKER-USER
  iptables -C DOCKER-USER -s "$VM_SUBNET" -j ACCEPT 2>/dev/null ||
  iptables -I DOCKER-USER -s "$VM_SUBNET" -j ACCEPT
  
  iptables -C DOCKER-USER -d "$VM_SUBNET" -j ACCEPT 2>/dev/null ||
  iptables -I DOCKER-USER -d "$VM_SUBNET" -j ACCEPT
  
  echo -e "${GREEN}✔ Docker compatibility configured${RESET}"
}

prevent_hairpin_nat() {
  echo -e "${BLUE}[*] Preventing hairpin NAT (VMs connecting to themselves)...${RESET}"
  
  # Skip DNAT for traffic originating from the VM subnet
  iptables -t nat -C PREROUTING -s "$VM_SUBNET" -j ACCEPT 2>/dev/null ||
  iptables -t nat -I PREROUTING -s "$VM_SUBNET" -j ACCEPT
  
  echo -e "${GREEN}✔ Hairpin NAT prevention configured${RESET}"
}

show_networks() {
  echo -e "${BLUE}=== Network Interfaces ===${RESET}"
  ip -br addr
  echo
  echo -e "${BLUE}=== Routing Table ===${RESET}"
  ip route
}

show_forwards() {
  echo -e "${BLUE}=== Current Port Forwards (DNAT) ===${RESET}"
  iptables -t nat -L PREROUTING -n --line-numbers
  echo
  echo -e "${BLUE}=== Forward Chain ===${RESET}"
  iptables -L FORWARD -n --line-numbers
  echo
  echo -e "${BLUE}=== Docker User Chain ===${RESET}"
  iptables -L DOCKER-USER -n --line-numbers 2>/dev/null || echo "DOCKER-USER chain not found"
}

add_forward() {
  read -rp "Public port to expose: " PUB_PORT
  read -rp "LXC/VM IP [${DEFAULT_LXC_IP}]: " LXC_IP
  LXC_IP=${LXC_IP:-$DEFAULT_LXC_IP}
  read -rp "LXC/VM port [$PUB_PORT]: " LXC_PORT
  LXC_PORT=${LXC_PORT:-$PUB_PORT}
  
  IFACE=$(detect_iface)
  
  echo -e "${GREEN}[*] Forwarding ${IFACE}:${PUB_PORT} → ${LXC_IP}:${LXC_PORT}${RESET}"
  
  # DNAT (skip traffic from VM subnet - handled by PREROUTING rule)
  iptables -t nat -C PREROUTING -p tcp --dport "$PUB_PORT" -j DNAT --to "$LXC_IP:$LXC_PORT" 2>/dev/null ||
  iptables -t nat -A PREROUTING -p tcp --dport "$PUB_PORT" -j DNAT --to "$LXC_IP:$LXC_PORT"
  
  # FORWARD allow (these are now redundant with DOCKER-USER rules but kept for non-Docker setups)
  iptables -C FORWARD -p tcp -d "$LXC_IP" --dport "$LXC_PORT" -j ACCEPT 2>/dev/null ||
  iptables -A FORWARD -p tcp -d "$LXC_IP" --dport "$LXC_PORT" -j ACCEPT
  
  iptables -C FORWARD -p tcp -s "$LXC_IP" --sport "$LXC_PORT" -j ACCEPT 2>/dev/null ||
  iptables -A FORWARD -p tcp -s "$LXC_IP" --sport "$LXC_PORT" -j ACCEPT
  
  # MASQUERADE
  iptables -t nat -C POSTROUTING -s "$LXC_IP" -o "$IFACE" -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -s "$LXC_IP" -o "$IFACE" -j MASQUERADE
  
  netfilter-persistent save >/dev/null
  echo -e "${GREEN}✔ Port forwarded successfully${RESET}"
}

remove_forward() {
  show_forwards
  echo
  read -rp "Enter PREROUTING rule number to delete: " RULE
  iptables -t nat -D PREROUTING "$RULE"
  netfilter-persistent save >/dev/null
  echo -e "${GREEN}✔ Rule removed${RESET}"
}

full_initialize() {
  echo -e "${BLUE}=== Full Initialization ===${RESET}"
  install_deps
  enable_forwarding
  setup_docker_compatibility
  prevent_hairpin_nat
  
  # Ensure MASQUERADE for VM subnet
  IFACE=$(detect_iface)
  iptables -t nat -C POSTROUTING -s "$VM_SUBNET" -o "$IFACE" -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -s "$VM_SUBNET" -o "$IFACE" -j MASQUERADE
  
  netfilter-persistent save >/dev/null
  echo -e "${GREEN}✔ Initialization complete${RESET}"
}

wizard() {
  while true; do
    clear
    echo -e "${BLUE}=== Proxmox LXC/VM Port Forward Wizard ===${RESET}"
    echo "1) Install & initialize (first run)"
    echo "2) Show networks"
    echo "3) Show current forwards"
    echo "4) Add port forward"
    echo "5) Remove port forward"
    echo "6) Fix Docker/nftables compatibility (if apt update fails)"
    echo "7) Exit"
    echo
    read -rp "Choose an option: " CHOICE
    case "$CHOICE" in
      1)
        full_initialize
        pause
        ;;
      2)
        show_networks
        pause
        ;;
      3)
        show_forwards
        pause
        ;;
      4)
        add_forward
        pause
        ;;
      5)
        remove_forward
        pause
        ;;
      6)
        setup_docker_compatibility
        prevent_hairpin_nat
        netfilter-persistent save >/dev/null
        echo -e "${GREEN}✔ Compatibility fixes applied${RESET}"
        pause
        ;;
      7)
        exit 0
        ;;
      *)
        echo -e "${RED}Invalid option${RESET}"
        pause
        ;;
    esac
  done
}

require_root
wizard
