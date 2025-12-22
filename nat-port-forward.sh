#!/usr/bin/env bash
set -e

### CONFIG DEFAULTS ###
DEFAULT_LXC_IP="10.10.10.4"

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
}

add_forward() {
  read -rp "Public port to expose: " PUB_PORT
  read -rp "LXC IP [${DEFAULT_LXC_IP}]: " LXC_IP
  LXC_IP=${LXC_IP:-$DEFAULT_LXC_IP}
  read -rp "LXC port [$PUB_PORT]: " LXC_PORT
  LXC_PORT=${LXC_PORT:-$PUB_PORT}

  IFACE=$(detect_iface)

  echo -e "${GREEN}[*] Forwarding ${IFACE}:${PUB_PORT} → ${LXC_IP}:${LXC_PORT}${RESET}"

  # DNAT
  iptables -t nat -C PREROUTING -p tcp --dport "$PUB_PORT" -j DNAT --to "$LXC_IP:$LXC_PORT" 2>/dev/null ||
  iptables -t nat -A PREROUTING -p tcp --dport "$PUB_PORT" -j DNAT --to "$LXC_IP:$LXC_PORT"

  # FORWARD allow
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

wizard() {
  while true; do
    clear
    echo -e "${BLUE}=== Proxmox LXC Port Forward Wizard ===${RESET}"
    echo "1) Install & initialize (first run)"
    echo "2) Show networks"
    echo "3) Show current forwards"
    echo "4) Add port forward"
    echo "5) Remove port forward"
    echo "6) Exit"
    echo
    read -rp "Choose an option: " CHOICE

    case "$CHOICE" in
      1)
        install_deps
        enable_forwarding
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
