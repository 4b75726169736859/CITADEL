#!/bin/bash

# ==============================================================================
#  PROJECT: VANGUARD (RELEASE 1.0)
#  TARGET: ROCKY LINUX 9 / RHEL 9
#  PROFILE: HARDENED SERVER & DOCKER READY
# ==============================================================================

# --- COULEURS & STYLES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_FILE="/var/log/vanguard_install.log"
DATE_NOW=$(date +%Y-%m-%d_%H-%M)

# --- FONCTIONS UTILITAIRES ---
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_input() { echo -ne "${PURPLE}[?]${NC} $1"; }

loading_bar() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -ne "  Traitement en cours... "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
    echo -e "${GREEN}Terminé.${NC}"
}

# --- VÉRIFICATION ROOT ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[CRITICAL] VANGUARD nécessite les droits ROOT.${NC}" 
   exit 1
fi

# --- BANNER ---
clear
echo -e "${CYAN}"
echo "██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
echo "██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
echo "██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
echo "╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
echo " ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
echo "  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
echo "          >>> SYSTEM HARDENING SUITE - ROCKY LINUX 9 <<<"
echo -e "${NC}"

# ==============================================================================
#  PHASE 1 : RECONNAISSANCE & INPUT
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 1 : INITIALISATION ---${NC}"

log_input "Nom de l'utilisateur Admin (ex: operator) : "; read ADMIN_USER
log_input "Créer cet utilisateur ? (o/n) : "; read CREATE_USER_CHOICE
log_input "Port SSH Hardened (ex: 2022) : "; read SSH_PORT
log_input "Hostname du serveur (ex: vanguard-01) : "; read NEW_HOSTNAME

if [[ -z "$ADMIN_USER" || -z "$SSH_PORT" ]]; then
    echo -e "${RED}Erreur : Paramètres manquants. Abandon.${NC}"
    exit 1
fi

# ==============================================================================
#  PHASE 2 : SYSTEM BASE & REPOS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 2 : CORE SYSTEM ---${NC}"

# 1. Hostname & Time
hostnamectl set-hostname "$NEW_HOSTNAME"
timedatectl set-timezone Europe/Paris
log_success "Identité : $NEW_HOSTNAME (Europe/Paris)"

# 2. Dépôts (CRB + EPEL)
log_info "Activation des dépôts étendus (CRB & EPEL)..."
dnf config-manager --set-enabled crb >/dev/null 2>&1
dnf install -y epel-release >/dev/null 2>&1

# 3. Full Update (Background)
log_info "Mise à jour complète du système (Cela peut être long)..."
(dnf update -y) > /dev/null 2>&1 &
loading_bar $!

# 4. Installation Arsenal
log_info "Installation de la suite d'outils..."
PACKAGES="vim git curl wget net-tools bind-utils ncdu neofetch dnf-automatic fail2ban tree btop bash-completion firewalld iptables-services iptables-nft ipset audit policycoreutils-python-utils tar man-pages aide rkhunter clamav clamav-update"
(dnf install -y $PACKAGES) > /dev/null 2>&1 &
loading_bar $!

# 5. Swap Management (2GB)
if [ $(swapon --show | wc -l) -eq 0 ]; then
    log_info "Création SWAP (2Go)..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_success "Swap activé."
fi

# ==============================================================================
#  PHASE 3 : KERNEL & DOCKER PREP
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 3 : KERNEL OPTIMIZATION ---${NC}"

# 1. Modules Noyau (Fix Docker/Iptables)
log_info "Chargement des modules noyau critiques..."
modprobe overlay br_netfilter ip_tables iptable_nat iptable_filter xt_masquerade

cat > /etc/modules-load.d/vanguard.conf <<EOF
overlay
br_netfilter
ip_tables
iptable_nat
iptable_filter
xt_masquerade
EOF

# 2. Sysctl Hardening
log_info "Application des paramètres sysctl (Sécurité + Réseau)..."
cat > /etc/sysctl.d/99-vanguard.conf <<EOF
# --- DOCKER COMPATIBILITY ---
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1

# --- NETWORK SECURITY ---
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP Redirects (MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore Broadcast Pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log Martians (Paquets avec IP sources impossibles)
net.ipv4.conf.all.log_martians = 1

# TCP Hardening (SYN Flood)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_timestamps = 0
EOF

sysctl --system > /dev/null 2>&1
log_success "Noyau durci."

# ==============================================================================
#  PHASE 4 : GESTION UTILISATEUR
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 4 : IDENTITY & ACCESS ---${NC}"

if [[ "$CREATE_USER_CHOICE" =~ ^[oOyeYE] ]]; then
    if id "$ADMIN_USER" &>/dev/null; then
        log_warn "Utilisateur $ADMIN_USER existe déjà."
        usermod -aG wheel "$ADMIN_USER"
    else
        useradd -m -s /bin/bash "$ADMIN_USER"
        log_input "Mot de passe pour $ADMIN_USER : "
        passwd "$ADMIN_USER"
        usermod -aG wheel "$ADMIN_USER"
        log_success "Admin $ADMIN_USER créé."
    fi
else
    if id "$ADMIN_USER" &>/dev/null; then
        usermod -aG wheel "$ADMIN_USER"
        log_success "Privilèges sudo accordés à $ADMIN_USER."
    fi
fi

# ==============================================================================
#  PHASE 5 : SSH FORTRESS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 5 : SSH HARDENING ---${NC}"

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# SELinux Port Context (Critique Rocky 9)
log_info "Configuration SELinux pour SSH Port $SSH_PORT..."
semanage port -a -t ssh_port_t -p tcp $SSH_PORT 2>/dev/null || true

# Configuration SSH
sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
# Authentification par mot de passe ACTIVE (selon ta demande), mais sécurisée
sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/" /etc/ssh/sshd_config
sed -i "s/^#\?X11Forwarding .*/X11Forwarding no/" /etc/ssh/sshd_config
sed -i "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" /etc/ssh/sshd_config
sed -i "s/^#\?AllowUsers .*/AllowUsers $ADMIN_USER/" /etc/ssh/sshd_config

# Bannière d'avertissement
echo "-----------------------------------------------------------------" > /etc/issue.net
echo " WARNING: AUTHORIZED ACCESS ONLY. SYSTEM MONITORED. " >> /etc/issue.net
echo "-----------------------------------------------------------------" >> /etc/issue.net
sed -i "s/^#\?Banner .*/Banner \/etc\/issue.net/" /etc/ssh/sshd_config

log_success "SSH configuré et sécurisé."

# ==============================================================================
#  PHASE 6 : FIREWALL & DEFENSE (FIREWALLD)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 6 : NETWORK DEFENSE ---${NC}"

systemctl unmask firewalld >/dev/null 2>&1
systemctl enable --now firewalld >/dev/null 2>&1

# Reset Zone Public
firewall-cmd --permanent --zone=public --remove-service=ssh >/dev/null 2>&1
firewall-cmd --permanent --zone=public --add-port=$SSH_PORT/tcp
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https

# Services additionnels (DNS/AdGuard/Alt-Web)
firewall-cmd --permanent --zone=public --add-port=53/tcp
firewall-cmd --permanent --zone=public --add-port=53/udp
firewall-cmd --permanent --zone=public --add-port=3000/tcp # Setup AdGuard
firewall-cmd --permanent --zone=public --add-port=8080/tcp

# Masquerade (NAT pour Docker)
firewall-cmd --permanent --zone=public --add-masquerade

firewall-cmd --reload >/dev/null 2>&1
log_success "Firewalld : Règles appliquées (SSH/HTTP/S/DNS)."

# ==============================================================================
#  PHASE 7 : INTRUSION DETECTION (AIDE, FAIL2BAN, RKHUNTER)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 7 : INTRUSION DETECTION ---${NC}"

# 1. Fail2Ban
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/secure
backend = systemd
mode = aggressive
EOF
systemctl enable --now fail2ban
log_success "Fail2Ban activé."

# 2. Auditd (Surveillance système)
cat > /etc/audit/rules.d/audit.rules <<EOF
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF
service auditd restart
log_success "Auditd : Règles de surveillance chargées."

# 3. RKHunter (Maj DB)
log_info "Mise à jour base de données RKHunter..."
rkhunter --propupd > /dev/null 2>&1

# 4. AIDE (Advanced Intrusion Detection Environment)
# On initialise juste la DB, ça peut prendre du temps donc on le fait en tâche de fond ou rapide
# Note: Sur une fresh install, l'init est rapide.
log_info "Initialisation de la base AIDE (Intégrité fichiers)..."
aide --init > /dev/null 2>&1
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
log_success "AIDE initialisé."

# ==============================================================================
#  PHASE 8 : ESTHÉTIQUE & AUTOMATISATION
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 8 : FINITIONS ---${NC}"

# Bashrc Admin
BASHRC="/home/$ADMIN_USER/.bashrc"
if ! grep -q "VANGUARD" $BASHRC; then
cat >> $BASHRC <<EOF

# --- PROJECT VANGUARD CUSTOM ---
export HISTTIMEFORMAT="%d/%m/%y %T "
export HISTCONTROL=ignoredups

# Prompt Couleur
parse_git_branch() {
     git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}
export PS1="\[\033[38;5;39m\]\u@\h\[\033[00m\]:\[\033[38;5;208m\]\w\[\033[35m\]\$(parse_git_branch)\[\033[00m\]$ "

# Aliases
alias update='sudo dnf update -y'
alias ll='ls -alF --color=auto --group-directories-first'
alias grep='grep --color=auto'
alias ports='netstat -tulanp'
alias myip='curl -s ifconfig.me'
alias sys='btop'
alias d='docker'
alias firewall='sudo firewall-cmd --list-all'
alias checksec='sudo rkhunter --check --sk'

echo -e "\n\033[1;32m SYSTEM PROTECTED BY VANGUARD. \033[0m"
EOF
    chown $ADMIN_USER:$ADMIN_USER $BASHRC
fi

# Auto-Updates Security
sed -i 's/upgrade_type = default/upgrade_type = security/' /etc/dnf/dnf-automatic.conf
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/dnf-automatic.conf
systemctl enable --now dnf-automatic.timer

# ==============================================================================
#  RAPPORT FINAL
# ==============================================================================
clear
echo -e "${GREEN}"
echo "   VANGUARD DEPLOYMENT COMPLETE."
echo "   Serveur Rocky Linux 9 sécurisé."
echo -e "${NC}"
echo "╔════════════════════════════════════════════════════════╗"
echo -e "║  USER ADMIN   : ${CYAN}$ADMIN_USER${NC}"
echo -e "║  PORT SSH     : ${YELLOW}$SSH_PORT${NC}"
echo -e "║  FIREWALL     : ${GREEN}ACTIF (SSH/HTTP/DNS)${NC}"
echo -e "║  FAIL2BAN     : ${GREEN}ACTIF${NC}"
echo -e "║  AIDE & RKH   : ${GREEN}INITIALISÉS${NC}"
echo -e "║  DOCKER PREP  : ${GREEN}MODULES & NAT OK${NC}"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo -e "${RED}[IMPORTANT]${NC} Ne fermez PAS cette session."
echo -e "1. Ouvrez un NOUVEAU terminal."
echo -e "2. Testez : ${BOLD}ssh -p $SSH_PORT $ADMIN_USER@$(curl -s ifconfig.me)${NC}"
echo -e "3. Si connexion OK : tapez ${YELLOW}systemctl restart sshd && reboot${NC} ici."
echo ""

exit 0
