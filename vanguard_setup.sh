#!/bin/bash

# ==============================================================================
#  PROJECT: CITADEL (GENERAL HARDENING)
#  TARGET: ROCKY LINUX 9 / RHEL 9
#  PROFILE: BASE SECURE SERVER (NO DOCKER PRE-INSTALL)
# ==============================================================================

# --- COULEURS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_FILE="/var/log/citadel_install.log"

# --- FONCTIONS ---
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_input() { echo -ne "${PURPLE}[?]${NC} $1"; }

loading_bar() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -ne "  Traitement... "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
    echo -e "${GREEN}Fait.${NC}"
}

# --- CHECK ROOT ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[CRITICAL] Doit être lancé en ROOT.${NC}" 
   exit 1
fi

clear
echo -e "${CYAN}"
echo "   ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗     "
echo "  ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║     "
echo "  ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║     "
echo "  ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║     "
echo "  ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗"
echo "   ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝"
echo "      >>> UNIVERSAL HARDENING - ROCKY LINUX 9 <<<"
echo -e "${NC}"

# ==============================================================================
#  PHASE 1 : LOGIQUE UTILISATEUR & INPUTS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 1 : CONFIGURATION ---${NC}"

# 1. Gestion Utilisateur (Logique demandée)
log_input "Voulez-vous créer un NOUVEL utilisateur admin ? (o/n) : "
read CREATE_USER_CHOICE

if [[ "$CREATE_USER_CHOICE" =~ ^[oOyeYE] ]]; then
    log_input "Entrez le nom du NOUVEL utilisateur (ex: admin) : "
    read ADMIN_USER
    DO_CREATE=true
else
    log_input "Entrez le nom de l'utilisateur admin EXISTANT : "
    read ADMIN_USER
    DO_CREATE=false
    
    # Vérification simple
    if ! id "$ADMIN_USER" &>/dev/null; then
        echo -e "${RED}Erreur : L'utilisateur $ADMIN_USER n'existe pas.${NC}"
        exit 1
    fi
fi

# 2. Port SSH
log_input "Port SSH personnalisé (Recommandé > 1024, ex: 2022) : "
read SSH_PORT

# 3. Hostname
log_input "Hostname de la machine (ex: srv-rocky-01) : "
read NEW_HOSTNAME

if [[ -z "$ADMIN_USER" || -z "$SSH_PORT" ]]; then
    echo -e "${RED}Erreur: Données manquantes.${NC}"
    exit 1
fi

# ==============================================================================
#  PHASE 2 : SYSTÈME & DÉPÔTS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 2 : BASE SYSTÈME ---${NC}"

# Hostname & Time
hostnamectl set-hostname "$NEW_HOSTNAME"
timedatectl set-timezone Europe/Paris
log_success "Identité définie : $NEW_HOSTNAME"

# Dépôts (CRB + EPEL sont indispensables pour les outils de sécurité)
log_info "Activation des dépôts CRB & EPEL..."
dnf config-manager --set-enabled crb >/dev/null 2>&1
dnf install -y epel-release >/dev/null 2>&1

# Full Update
log_info "Mise à jour système complète..."
(dnf update -y) > /dev/null 2>&1 &
loading_bar $!

# Installation Outils Admin (Sans Docker)
log_info "Installation de l'arsenal d'administration..."
# Note : firewalld, ipset, audit sont critiques pour la sécurité
PKGS="vim git curl wget net-tools bind-utils ncdu neofetch dnf-automatic fail2ban tree btop bash-completion firewalld iptables-services iptables-nft ipset audit policycoreutils-python-utils tar man-pages aide rkhunter"
(dnf install -y $PKGS) > /dev/null 2>&1 &
loading_bar $!

# Swap (Sécurité Anti-Crash RAM)
if [ $(swapon --show | wc -l) -eq 0 ]; then
    log_info "Génération Swap (2Go)..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_success "Swap activé."
fi

# ==============================================================================
#  PHASE 3 : OPTIMISATION NOYAU (PREP UNIVERSELLE)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 3 : HARDENING KERNEL ---${NC}"

# On charge quand même les modules réseaux avancés.
# Pourquoi ? Si tu installes un VPN, un Firewall complexe ou Docker dans 6 mois,
# tu n'auras pas d'erreur. Ça ne consomme rien et ça rend la machine "Ready".
log_info "Préparation des modules réseaux (Bridge/Filter)..."
modprobe overlay br_netfilter ip_tables iptable_nat iptable_filter xt_masquerade

cat > /etc/modules-load.d/citadel.conf <<EOF
overlay
br_netfilter
ip_tables
iptable_nat
iptable_filter
xt_masquerade
EOF

# Hardening Sysctl (Sécurité Réseau Générale)
log_info "Verrouillage de la stack TCP/IP..."
cat > /etc/sysctl.d/99-citadel.conf <<EOF
# --- GENERAL SECURITY ---
# Protection IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP Redirects (Protection MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore Broadcast Pings (Protection Smurf)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log Martians (Paquets suspects)
net.ipv4.conf.all.log_martians = 1

# Protection SYN Flood (Anti-DDoS basique)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# --- COMPATIBILITY PREP ---
# Permet le forwarding si besoin futur (VPN/Container)
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sysctl --system > /dev/null 2>&1
log_success "Noyau durci."

# ==============================================================================
#  PHASE 4 : GESTION UTILISATEUR
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 4 : ACCÈS ---${NC}"

if [ "$DO_CREATE" = true ]; then
    if id "$ADMIN_USER" &>/dev/null; then
        log_warn "L'utilisateur $ADMIN_USER existe déjà (ignoré)."
        usermod -aG wheel "$ADMIN_USER"
    else
        useradd -m -s /bin/bash "$ADMIN_USER"
        log_input "Définissez le mot de passe pour $ADMIN_USER : "
        passwd "$ADMIN_USER"
        usermod -aG wheel "$ADMIN_USER"
        log_success "Utilisateur $ADMIN_USER créé."
    fi
else
    usermod -aG wheel "$ADMIN_USER"
    log_success "Privilèges sudo vérifiés pour $ADMIN_USER."
fi

# ==============================================================================
#  PHASE 5 : SSH FORTRESS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 5 : SÉCURISATION SSH ---${NC}"

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# SELinux (Critique Rocky 9)
log_info "Ajustement SELinux pour port $SSH_PORT..."
semanage port -a -t ssh_port_t -p tcp $SSH_PORT 2>/dev/null || true

# Config SSH
sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config
sed -i "s/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/" /etc/ssh/sshd_config
sed -i "s/^#\?X11Forwarding .*/X11Forwarding no/" /etc/ssh/sshd_config
sed -i "s/^#\?MaxAuthTries .*/MaxAuthTries 3/" /etc/ssh/sshd_config
sed -i "s/^#\?AllowUsers .*/AllowUsers $ADMIN_USER/" /etc/ssh/sshd_config

# Banner
echo "-----------------------------------------------------------------" > /etc/issue.net
echo " WARNING: AUTHORIZED ACCESS ONLY. SYSTEM MONITORED. " >> /etc/issue.net
echo "-----------------------------------------------------------------" >> /etc/issue.net
sed -i "s/^#\?Banner .*/Banner \/etc\/issue.net/" /etc/ssh/sshd_config

log_success "SSH sécurisé (Port $SSH_PORT)."

# ==============================================================================
#  PHASE 6 : FIREWALL & INTRUSION (GENERIC)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 6 : DÉFENSE RÉSEAU ---${NC}"

# Firewalld
systemctl unmask firewalld >/dev/null 2>&1
systemctl enable --now firewalld >/dev/null 2>&1

# Configuration de base : On ferme tout, on ouvre SSH
firewall-cmd --permanent --zone=public --remove-service=ssh >/dev/null 2>&1
firewall-cmd --permanent --zone=public --remove-service=cockpit >/dev/null 2>&1
firewall-cmd --permanent --zone=public --add-port=$SSH_PORT/tcp

# On active le Masquerade par défaut.
# C'est une bonne pratique "Générale" sur un VPS : ça permet à n'importe quel 
# service interne (VPN, Docker futur, Podman) d'accéder au net sans config complexe.
firewall-cmd --permanent --zone=public --add-masquerade

firewall-cmd --reload >/dev/null 2>&1
log_success "Firewall actif (Port $SSH_PORT ouvert, le reste fermé)."

# Fail2Ban
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
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
log_success "Fail2Ban actif."

# Auditd (Surveillance)
cat > /etc/audit/rules.d/citadel.rules <<EOF
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF
service auditd restart >/dev/null 2>&1
log_success "Auditd actif."

# RKHunter Update
rkhunter --propupd >/dev/null 2>&1

# ==============================================================================
#  PHASE 7 : FINITIONS & UX
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 7 : FINITIONS ---${NC}"

# .bashrc pour l'admin
BASHRC="/home/$ADMIN_USER/.bashrc"
if ! grep -q "CITADEL" $BASHRC; then
cat >> $BASHRC <<EOF

# --- PROJECT CITADEL ---
export HISTTIMEFORMAT="%d/%m/%y %T "
export HISTCONTROL=ignoredups

# Prompt
export PS1="\[\033[38;5;39m\]\u@\h\[\033[00m\]:\[\033[38;5;208m\]\w\[\033[00m\]$ "

# Aliases
alias update='sudo dnf update -y'
alias ll='ls -alF --color=auto --group-directories-first'
alias grep='grep --color=auto'
alias ports='netstat -tulanp'
alias myip='curl -s ifconfig.me'
alias sys='btop'
alias firewall='sudo firewall-cmd --list-all'
alias checksec='sudo rkhunter --check --sk'

echo -e "\n\033[1;32m CITADEL SECURE SHELL. \033[0m"
EOF
    chown $ADMIN_USER:$ADMIN_USER $BASHRC
fi

# Mises à jour auto (Security only)
sed -i 's/upgrade_type = default/upgrade_type = security/' /etc/dnf/dnf-automatic.conf
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/dnf-automatic.conf
systemctl enable --now dnf-automatic.timer

# ==============================================================================
#  RAPPORT FINAL
# ==============================================================================
clear
echo -e "${GREEN}"
echo "   CITADEL DEPLOYMENT COMPLETE."
echo "   Serveur sécurisé (General Purpose)."
echo -e "${NC}"
echo "╔════════════════════════════════════════════════════════╗"
echo -e "║  USER ADMIN   : ${CYAN}$ADMIN_USER${NC}"
echo -e "║  PORT SSH     : ${YELLOW}$SSH_PORT${NC}"
echo -e "║  FIREWALL     : ${GREEN}ACTIF (Port SSH Uniquement)${NC}"
echo -e "║  FAIL2BAN     : ${GREEN}ACTIF${NC}"
echo -e "║  AIDE & RKH   : ${GREEN}INSTALLÉS${NC}"
echo -e "║  DOCKER       : ${YELLOW}NON INSTALLÉ (Mais Kernel Prêt)${NC}"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo -e "${RED}[IMPORTANT]${NC} Ne fermez PAS cette session."
echo -e "1. Ouvrez un NOUVEAU terminal."
echo -e "2. Testez : ${BOLD}ssh -p $SSH_PORT $ADMIN_USER@$(curl -s ifconfig.me)${NC}"
echo -e "3. Si connexion OK : tapez ${YELLOW}systemctl restart sshd && reboot${NC} ici."
echo ""

exit 0
