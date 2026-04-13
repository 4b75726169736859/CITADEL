#!/bin/bash

# ==============================================================================
#  PROJECT: CITADEL (GENERAL HARDENING) - v2.0
#  TARGET: ROCKY LINUX 9 / RHEL 9
#  PROFILE: BASE SECURE SERVER (NO DOCKER PRE-INSTALL)
#  AUTHOR: 4b75726169736859
#  CHANGELOG v2.0:
#    - Validation des inputs (port SSH, username)
#    - Vérification sshd -t avant restart
#    - SELinux forcé en Enforcing
#    - Sysctl: ASLR, core dumps, hardlinks/symlinks, dmesg/kptr restrict
#    - SSH: clé publique only, ClientAlive, LoginGraceTime, PrintMotd
#    - MOTD dynamique post-auth (compatible SFTP/SCP)
#    - Auditd: sudoers, execve root, crontabs
#    - AIDE initialisé + cron hebdo
#    - Lynis installé
#    - Firewall: zone drop par défaut + rate-limit SSH
#    - Mode dry-run (--dry-run)
#    - Idempotence améliorée
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
DRY_RUN=false

# --- MODE DRY RUN ---
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo -e "${YELLOW}[DRY-RUN] Mode simulation activé. Aucune modification ne sera appliquée.${NC}"
fi

# Wrapper : exécute la commande sauf en dry-run
run() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "  ${YELLOW}[DRY-RUN]${NC} Commande ignorée : $*"
    else
        eval "$@"
    fi
}

# --- FONCTIONS ---
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"    | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"     | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"  | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"    | tee -a "$LOG_FILE"; }
log_input()   { echo -ne "${PURPLE}[?]${NC} $1"; }

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
echo "      >>> UNIVERSAL HARDENING v2.0 - ROCKY LINUX 9 <<<"
echo "                   >>> BY 4b75726169736859 <<<"
echo -e "${NC}"

# ==============================================================================
#  PHASE 1 : LOGIQUE UTILISATEUR & INPUTS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 1 : CONFIGURATION ---${NC}"

# 1. Gestion Utilisateur
log_input "Voulez-vous créer un NOUVEL utilisateur admin ? (o/n) : "
read CREATE_USER_CHOICE

if [[ "$CREATE_USER_CHOICE" =~ ^[oOyY] ]]; then
    log_input "Entrez le nom du NOUVEL utilisateur (ex: admin) : "
    read ADMIN_USER
    DO_CREATE=true
else
    log_input "Entrez le nom de l'utilisateur admin EXISTANT : "
    read ADMIN_USER
    DO_CREATE=false

    if ! id "$ADMIN_USER" &>/dev/null; then
        log_error "L'utilisateur $ADMIN_USER n'existe pas."
        exit 1
    fi
fi

# Validation username
if [[ ! "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    log_error "Nom d'utilisateur invalide : '$ADMIN_USER'. Utilisez uniquement a-z, 0-9, _ ou -"
    exit 1
fi

# 2. Port SSH avec validation stricte
while true; do
    log_input "Port SSH personnalisé (1025-65535, ex: 2022) : "
    read SSH_PORT
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -gt 1024 ] && [ "$SSH_PORT" -le 65535 ]; then
        break
    else
        log_warn "Port invalide. Entrez un nombre entre 1025 et 65535."
    fi
done

# 3. Clé SSH publique
log_input "Collez votre clé SSH publique (laisser vide pour garder auth mot de passe) : "
read SSH_PUBKEY

# 4. Hostname
log_input "Hostname de la machine (ex: srv-rocky-01) : "
read NEW_HOSTNAME

if [[ -z "$ADMIN_USER" || -z "$SSH_PORT" ]]; then
    log_error "Données manquantes."
    exit 1
fi

# ==============================================================================
#  PHASE 2 : SYSTÈME & DÉPÔTS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 2 : BASE SYSTÈME ---${NC}"

run hostnamectl set-hostname "$NEW_HOSTNAME"
run timedatectl set-timezone Europe/Paris
log_success "Identité définie : $NEW_HOSTNAME (Europe/Paris)"

log_info "Activation des dépôts CRB & EPEL..."
run "dnf config-manager --set-enabled crb >/dev/null 2>&1"
run "dnf install -y epel-release >/dev/null 2>&1"

log_info "Mise à jour système complète (Patience)..."
(run "dnf update -y >/dev/null 2>&1") &
loading_bar $!

# Lynis ajouté pour les audits ponctuels de conformité
log_info "Installation de l'arsenal d'administration..."
PKGS="vim git curl wget net-tools bind-utils ncdu neofetch dnf-automatic fail2ban tree btop bash-completion firewalld iptables-services iptables-nft ipset audit policycoreutils-python-utils tar man-pages aide rkhunter lynis"
(run "dnf install -y $PKGS >/dev/null 2>&1") &
loading_bar $!

# Swap
if [ $(swapon --show | wc -l) -eq 0 ]; then
    log_info "Génération Swap (2Go)..."
    run "fallocate -l 2G /swapfile"
    run "chmod 600 /swapfile"
    run "mkswap /swapfile > /dev/null"
    run "swapon /swapfile"
    run "echo '/swapfile none swap sw 0 0' >> /etc/fstab"
    log_success "Swap activé."
fi

# ==============================================================================
#  PHASE 3 : HARDENING KERNEL (ÉTENDU)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 3 : HARDENING KERNEL ---${NC}"

log_info "Préparation des modules réseaux..."
run "modprobe overlay br_netfilter ip_tables iptable_nat iptable_filter xt_masquerade"

run "cat > /etc/modules-load.d/citadel.conf <<EOF
overlay
br_netfilter
ip_tables
iptable_nat
iptable_filter
xt_masquerade
EOF"

log_info "Verrouillage de la stack TCP/IP + durcissement noyau..."
run "cat > /etc/sysctl.d/99-citadel.conf <<'EOF'
# ============================================================
# PROJECT CITADEL v2.0 — SYSCTL HARDENING
# ============================================================

# --- RESEAU : ANTI-SPOOFING / MITM / FLOOD ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# --- COMPATIBILITE (VPN/Container futur) ---
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1

# --- MEMOIRE / EXPLOIT MITIGATION ---
# ASLR au maximum (randomisation des adresses mémoire)
kernel.randomize_va_space = 2

# Désactiver les core dumps (évite les fuites mémoire/secrets)
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Restreindre l'accès au kernel log (dmesg) aux root uniquement
kernel.dmesg_restrict = 1

# Masquer les pointeurs mémoire kernel dans /proc (anti-exploitation)
kernel.kptr_restrict = 2

# Protéger contre les attaques par hardlinks/symlinks (privilege escalation)
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF"

run "sysctl --system > /dev/null 2>&1"
log_success "Noyau durci (ASLR, core dumps, kptr, hardlinks)."

# ==============================================================================
#  PHASE 4 : SELINUX — ENFORCING OBLIGATOIRE
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 4 : SELINUX ---${NC}"

SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
if [ "$SELINUX_STATUS" != "Enforcing" ]; then
    log_warn "SELinux n'est pas en mode Enforcing (état : $SELINUX_STATUS). Correction..."
    run "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
    log_warn "SELinux sera en Enforcing après le prochain reboot."
else
    log_success "SELinux déjà en mode Enforcing."
fi

# ==============================================================================
#  PHASE 5 : GESTION UTILISATEUR
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 5 : ACCÈS ---${NC}"

if [ "$DO_CREATE" = true ]; then
    if id "$ADMIN_USER" &>/dev/null; then
        log_warn "L'utilisateur $ADMIN_USER existe déjà (ignoré)."
        run "usermod -aG wheel $ADMIN_USER"
    else
        run "useradd -m -s /bin/bash $ADMIN_USER"
        echo -e "${YELLOW}>>> Définissez le mot de passe pour $ADMIN_USER :${NC}"
        [ "$DRY_RUN" = false ] && passwd "$ADMIN_USER"
        run "usermod -aG wheel $ADMIN_USER"
        log_success "Utilisateur $ADMIN_USER créé."
    fi
else
    run "usermod -aG wheel $ADMIN_USER"
    log_success "Privilèges sudo vérifiés pour $ADMIN_USER."
fi

# Déploiement clé SSH publique
if [[ -n "$SSH_PUBKEY" ]]; then
    SSH_DIR="/home/$ADMIN_USER/.ssh"
    run "mkdir -p $SSH_DIR"
    run "echo '$SSH_PUBKEY' >> $SSH_DIR/authorized_keys"
    run "chmod 700 $SSH_DIR"
    run "chmod 600 $SSH_DIR/authorized_keys"
    run "chown -R $ADMIN_USER:$ADMIN_USER $SSH_DIR"
    log_success "Clé SSH publique déployée pour $ADMIN_USER."
fi

# ==============================================================================
#  PHASE 6 : SSH FORTRESS
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 6 : SÉCURISATION SSH ---${NC}"

run "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak"

log_info "Ajustement SELinux pour port $SSH_PORT..."
run "semanage port -a -t ssh_port_t -p tcp $SSH_PORT 2>/dev/null || true"

# Détermination du mode d'auth SSH
if [[ -n "$SSH_PUBKEY" ]]; then
    PUBKEY_AUTH="yes"
    PASSWD_AUTH="no"
    log_info "Clé publique fournie → Auth par mot de passe DÉSACTIVÉE."
else
    PUBKEY_AUTH="yes"
    PASSWD_AUTH="yes"
    log_warn "Pas de clé publique → Auth par mot de passe maintenue (pensez à la désactiver plus tard)."
fi

run "sed -i 's/^#\?Port .*/Port $SSH_PORT/'                             /etc/ssh/sshd_config"
run "sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/'             /etc/ssh/sshd_config"
run "sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication $PASSWD_AUTH/' /etc/ssh/sshd_config"
run "sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication $PUBKEY_AUTH/'     /etc/ssh/sshd_config"
run "sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/'   /etc/ssh/sshd_config"
run "sed -i 's/^#\?X11Forwarding .*/X11Forwarding no/'                 /etc/ssh/sshd_config"
run "sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/'                    /etc/ssh/sshd_config"
run "sed -i 's/^#\?AllowUsers .*/AllowUsers $ADMIN_USER/'              /etc/ssh/sshd_config"
run "sed -i 's/^#\?PrintMotd .*/PrintMotd yes/'                        /etc/ssh/sshd_config"
run "sed -i 's/^#\?PrintLastLog .*/PrintLastLog yes/'                  /etc/ssh/sshd_config"

# Timeout sessions inactives (kick après 5 min d'inactivité)
if ! grep -q "ClientAliveInterval" /etc/ssh/sshd_config; then
    run "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config"
    run "echo 'ClientAliveCountMax 2'   >> /etc/ssh/sshd_config"
fi

# Réduire la fenêtre d'auth à 30s
if ! grep -q "LoginGraceTime" /etc/ssh/sshd_config; then
    run "echo 'LoginGraceTime 30' >> /etc/ssh/sshd_config"
fi

# Auth par clé uniquement si clé fournie
if [[ -n "$SSH_PUBKEY" ]]; then
    if ! grep -q "AuthenticationMethods" /etc/ssh/sshd_config; then
        run "echo 'AuthenticationMethods publickey' >> /etc/ssh/sshd_config"
    fi
fi

# MOTD dynamique post-auth (compatible SFTP/SCP — s'affiche APRÈS l'auth)
run "cat > /etc/motd <<'EOF'
-----------------------------------------------------------------
 WARNING: AUTHORIZED ACCESS ONLY. SYSTEM MONITORED BY CITADEL.
-----------------------------------------------------------------
EOF"

# Script MOTD dynamique dans profile.d (charge CPU, mémoire, dernière connexion)
run "cat > /etc/profile.d/citadel_motd.sh <<'MOTD'
#!/bin/bash
echo ""
echo -e \"\033[1;36m  [\$(hostname)] — \$(date '+%A %d %B %Y, %H:%M:%S')\033[0m\"
echo -e \"  Load     : \$(uptime | awk -F'load average:' '{print \$2}' | xargs)\"
echo -e \"  Mémoire  : \$(free -h | awk '/^Mem/{print \$3 \" / \" \$2}')\"
echo -e \"  Disque / : \$(df -h / | awk 'NR==2{print \$3 \" / \" \$2 \" (\" \$5 \" utilisé)\"}')\"
echo -e \"  Uptime   : \$(uptime -p)\"
echo ""
MOTD"
run "chmod +x /etc/profile.d/citadel_motd.sh"

# Validation config SSH avant d'aller plus loin
log_info "Validation de la configuration SSH..."
if [ "$DRY_RUN" = false ]; then
    if ! sshd -t; then
        log_error "La configuration sshd est INVALIDE. Restauration de la sauvegarde."
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        exit 1
    fi
    log_success "Configuration SSH valide."
fi

log_success "SSH sécurisé (Port $SSH_PORT, sessions timeout 10min)."

# ==============================================================================
#  PHASE 7 : FIREWALL & INTRUSION
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 7 : DÉFENSE RÉSEAU ---${NC}"

run "systemctl unmask firewalld >/dev/null 2>&1"
run "systemctl enable --now firewalld >/dev/null 2>&1"

# Zone drop = tout paquet non matché est silencieusement ignoré (pas de RST)
# Idéal contre le scanning et les sondes automatiques
run "firewall-cmd --permanent --set-default-zone=drop >/dev/null 2>&1"

# SSH autorisé sur la zone drop
run "firewall-cmd --permanent --zone=drop --remove-service=ssh >/dev/null 2>&1"
run "firewall-cmd --permanent --zone=drop --remove-service=cockpit >/dev/null 2>&1"
run "firewall-cmd --permanent --zone=drop --add-port=$SSH_PORT/tcp"

# Masquerade (compatibilité VPN/containers futur)
run "firewall-cmd --permanent --zone=drop --add-masquerade"

# Rate-limiting SSH directement au firewall (anti-brute force en amont de fail2ban)
# Limite : max 10 nouvelles connexions SSH / minute par IP
run "firewall-cmd --permanent --zone=drop --add-rich-rule='rule service name=\"ssh\" accept limit value=\"10/m\"' >/dev/null 2>&1 || \
     firewall-cmd --permanent --zone=drop --add-rich-rule='rule port port=\"$SSH_PORT\" protocol=\"tcp\" accept limit value=\"10/m\"' >/dev/null 2>&1"

run "firewall-cmd --reload >/dev/null 2>&1"
log_success "Firewall actif (zone DROP par défaut, port $SSH_PORT + rate-limit)."

# Fail2Ban
run "cat > /etc/fail2ban/jail.local <<EOF
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
EOF"
run "systemctl enable --now fail2ban"
log_success "Fail2Ban actif."

# ==============================================================================
#  PHASE 8 : AUDITD (ÉTENDU)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 8 : AUDIT & SURVEILLANCE ---${NC}"

run "cat > /etc/audit/rules.d/citadel.rules <<'EOF'
# Vider les règles existantes
-D
-b 8192
-f 1

# --- IDENTITÉ ---
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity

# --- SUDO & PRIVILEGES ---
-w /etc/sudoers    -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- SSH ---
-w /etc/ssh/sshd_config -p wa -k sshd_config

# --- CRONTABS (persistance malveillante) ---
-w /etc/cron.d/      -p wa -k cron
-w /etc/cron.daily/  -p wa -k cron
-w /etc/crontab      -p wa -k cron
-w /var/spool/cron   -p wa -k cron

# --- EXECUTIONS EN TANT QUE ROOT (détection lateral movement) ---
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
-a always,exit -F arch=b32 -F euid=0 -S execve -k root_exec
EOF"

run "service auditd restart >/dev/null 2>&1"
log_success "Auditd actif (sudoers, cron, root_exec, identity)."

# ==============================================================================
#  PHASE 9 : AIDE (INITIALISATION RÉELLE)
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 9 : AIDE (IDS Fichiers) ---${NC}"

# Vérification idempotente
if [ ! -f /var/lib/aide/aide.db.gz ]; then
    log_info "Initialisation de la base de référence AIDE (peut prendre quelques minutes)..."
    run "aide --init >/dev/null 2>&1"
    run "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    log_success "Base AIDE initialisée."
else
    log_warn "Base AIDE déjà existante (ignorée pour idempotence)."
fi

# Cron hebdomadaire : check AIDE chaque lundi à 3h du matin
if ! crontab -l 2>/dev/null | grep -q "aide --check"; then
    run "(crontab -l 2>/dev/null; echo '0 3 * * 1 /usr/sbin/aide --check >> /var/log/aide_check.log 2>&1') | crontab -"
    log_success "Cron AIDE hebdomadaire configuré (lundi 3h00)."
fi

# RKHunter
run "rkhunter --propupd >/dev/null 2>&1"
log_success "RKHunter mis à jour."

# ==============================================================================
#  PHASE 10 : FINITIONS & UX
# ==============================================================================
echo -e "\n${BOLD}--- PHASE 10 : FINITIONS ---${NC}"

BASHRC="/home/$ADMIN_USER/.bashrc"
if ! grep -q "CITADEL" $BASHRC 2>/dev/null; then
run "cat >> $BASHRC <<'EOF'

# --- PROJECT CITADEL v2.0 BY KURAISHY ---
export HISTTIMEFORMAT="%d/%m/%y %T "
export HISTCONTROL=ignoredups:erasedups
export HISTSIZE=10000
export HISTFILESIZE=20000

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
alias audit='sudo lynis audit system'
alias aidechk='sudo aide --check'
EOF"
    run "chown $ADMIN_USER:$ADMIN_USER $BASHRC"
fi

# Mises à jour auto (Security only)
run "sed -i 's/upgrade_type = default/upgrade_type = security/' /etc/dnf/dnf-automatic.conf"
run "sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/dnf-automatic.conf"
run "systemctl enable --now dnf-automatic.timer"

# ==============================================================================
#  RAPPORT FINAL
# ==============================================================================
clear
echo -e "${GREEN}"
echo "   CITADEL v2.0 DEPLOYMENT COMPLETE."
echo "   Serveur sécurisé (General Purpose)."
echo -e "${NC}"
echo "╔════════════════════════════════════════════════════════════╗"
echo -e "║  USER ADMIN    : ${CYAN}$ADMIN_USER${NC}"
echo -e "║  PORT SSH      : ${YELLOW}$SSH_PORT${NC}"
echo -e "║  AUTH SSH      : $([ -n "$SSH_PUBKEY" ] && echo "${GREEN}CLÉ PUBLIQUE UNIQUEMENT${NC}" || echo "${YELLOW}MOT DE PASSE (à migrer)${NC}")"
echo -e "║  FIREWALL      : ${GREEN}ACTIF (Zone DROP + Rate-Limit)${NC}"
echo -e "║  FAIL2BAN      : ${GREEN}ACTIF${NC}"
echo -e "║  SELINUX       : ${GREEN}ENFORCING (actif au prochain reboot si modifié)${NC}"
echo -e "║  AUDITD        : ${GREEN}ACTIF (sudoers, cron, root_exec)${NC}"
echo -e "║  AIDE          : ${GREEN}INITIALISÉ (check hebdo lundi 3h)${NC}"
echo -e "║  RKHUNTER      : ${GREEN}INSTALLÉ & MIS À JOUR${NC}"
echo -e "║  LYNIS         : ${GREEN}INSTALLÉ (alias: audit)${NC}"
echo -e "║  KERNEL        : ${GREEN}DURCI (ASLR, kptr, core dumps, hardlinks)${NC}"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${RED}[IMPORTANT]${NC} Ne fermez PAS cette session."
echo -e "1. Ouvrez un NOUVEAU terminal."
echo -e "2. Testez : ${BOLD}ssh -p $SSH_PORT $ADMIN_USER@$(curl -s ifconfig.me 2>/dev/null || echo '<votre-ip>')${NC}"
echo -e "3. Si connexion OK : tapez ${YELLOW}systemctl restart sshd && reboot${NC} ici."
echo ""
echo -e "${BLUE}[POST-INSTALL]${NC} Commandes utiles :"
echo -e "  ${CYAN}sudo lynis audit system${NC}      → Audit de conformité complet"
echo -e "  ${CYAN}sudo aide --check${NC}             → Vérifier l'intégrité des fichiers"
echo -e "  ${CYAN}sudo ausearch -k root_exec${NC}    → Voir les exécutions root"
echo -e "  ${CYAN}sudo fail2ban-client status sshd${NC} → Status Fail2Ban"
echo ""

exit 0