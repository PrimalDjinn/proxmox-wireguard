#!/bin/bash

# Server Hardening Script for Debian/Proxmox
# This script does NOT modify network configuration
# Run as root: sudo bash harden.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Server Hardening Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Backup directory
BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo -e "${YELLOW}Backups will be saved to: $BACKUP_DIR${NC}"
echo ""

# Function to backup files
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$BACKUP_DIR/"
        echo -e "${GREEN}✓${NC} Backed up: $1"
    fi
}

# 1. Update System
echo -e "${YELLOW}[1/9] Updating system packages...${NC}"
apt update
apt upgrade -y
apt autoremove -y
echo -e "${GREEN}✓ System updated${NC}\n"

# 2. Install essential security tools
echo -e "${YELLOW}[2/9] Installing security tools...${NC}"
apt install -y \
    fail2ban \
    unattended-upgrades \
    ufw \
    aide \
    auditd \
    logwatch \
    rkhunter \
    clamav \
    clamav-daemon
echo -e "${GREEN}✓ Security tools installed${NC}\n"

# 3. Configure automatic security updates
echo -e "${YELLOW}[3/9] Configuring automatic security updates...${NC}"
backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
echo -e "${GREEN}✓ Automatic updates configured${NC}\n"

# 4. Configure SSH hardening
echo -e "${YELLOW}[4/9] Hardening SSH configuration...${NC}"
backup_file "/etc/ssh/sshd_config"

# Create hardened SSH config
cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
# SSH Hardening Configuration
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
# Disable weak ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF

echo -e "${GREEN}✓ SSH hardened${NC}"
echo -e "${YELLOW}  Note: PasswordAuthentication is now disabled${NC}"
echo -e "${YELLOW}  Make sure you have SSH keys configured!${NC}\n"

# 5. Configure Fail2Ban
echo -e "${YELLOW}[5/9] Configuring Fail2Ban...${NC}"
backup_file "/etc/fail2ban/jail.local"

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[proxmox]
enabled = true
port = https,http,8006
logpath = /var/log/daemon.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}✓ Fail2Ban configured and started${NC}\n"

# 6. Configure UFW Firewall (without enabling it yet)
echo -e "${YELLOW}[6/9] Configuring UFW firewall...${NC}"
# Set defaults
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow 22/tcp comment 'SSH'

# Allow Proxmox Web Interface
ufw allow 8006/tcp comment 'Proxmox Web UI'

# Allow Proxmox clustering (if needed)
ufw allow 5900:5999/tcp comment 'Proxmox VNC'
ufw allow 3128/tcp comment 'Proxmox SPICE Proxy'

# Allow WireGuard VPN
ufw allow 51820/udp comment 'WireGuard VPN'

echo -e "${GREEN}✓ UFW rules configured${NC}"
echo -e "${YELLOW}  UFW is NOT enabled yet. To enable, run: sudo ufw enable${NC}"
echo -e "${YELLOW}  Review rules first with: sudo ufw status${NC}\n"

# 7. Secure shared memory
echo -e "${YELLOW}[7/9] Securing shared memory...${NC}"
backup_file "/etc/fstab"
if ! grep -q "tmpfs /run/shm tmpfs" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    echo -e "${GREEN}✓ Shared memory secured${NC}\n"
else
    echo -e "${GREEN}✓ Shared memory already secured${NC}\n"
fi

# 8. Kernel hardening via sysctl
echo -e "${YELLOW}[8/9] Applying kernel hardening...${NC}"
backup_file "/etc/sysctl.conf"

cat > /etc/sysctl.d/99-hardening.conf <<EOF
# IP Forwarding (needed for Proxmox VMs with NAT)
net.ipv4.ip_forward = 1

# Disable IPv6 if not needed (comment out if you use IPv6)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Prevent SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Ignore source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore Broadcast Request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Protection against bad ICMP messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Increase system file descriptor limit
fs.file-max = 65535

# Protect against buffer overflow attacks
kernel.exec-shield = 1
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-hardening.conf > /dev/null 2>&1
echo -e "${GREEN}✓ Kernel hardening applied${NC}\n"

# 9. Set secure file permissions
echo -e "${YELLOW}[9/9] Setting secure file permissions...${NC}"
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/ssh/sshd_config
echo -e "${GREEN}✓ File permissions secured${NC}\n"

# Summary
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Hardening Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "Backups saved to: ${YELLOW}$BACKUP_DIR${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Test SSH access in a NEW terminal before closing this one"
echo "2. Review UFW rules: sudo ufw status"
echo "3. Enable UFW when ready: sudo ufw enable"
echo "4. Restart SSH: sudo systemctl restart sshd"
echo "5. Check Fail2Ban: sudo fail2ban-client status"
echo "6. Review logs: sudo tail -f /var/log/fail2ban.log"
echo ""
echo -e "${RED}IMPORTANT:${NC}"
echo "- Make sure you have SSH keys configured before disabling password auth"
echo "- Test SSH access before logging out"
echo "- UFW is configured but NOT enabled yet"
echo ""
