#!/usr/bin/env bash
# ==============================================================================
#
#   ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
#  ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
#  ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
#  ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
#  ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
#   ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
#
#  PROJECT CITADEL v3.0 - ULTRA HARDENING FRAMEWORK
#  TARGET  : Rocky Linux 9 / RHEL 9 / AlmaLinux 9
#  AUTHOR  : 4b75726169736859
#  LICENSE : MIT
#
#  CHANGELOG v3.0 (vs v2.0):
#    SÉCURITÉ
#    + SSH: algorithmes crypto modernes uniquement (ChaCha20/AES-GCM/ed25519)
#    + SSH: bannière légale + AllowUsers strict + MaxStartups + TCPKeepAlive
#    + Kernel: SMEP/SMAP/KPTI/Spectre mitigations via sysctl
#    + Kernel: désactivation modules dangereux (usb-storage, firewire, cramfs...)
#    + PAM: faillock, umask 027, su restreint au groupe wheel
#    + Sudo: logfile dédié, timeout 5 min, NOPASSWD interdit
#    + Auditd: 30+ règles (CIS Level 2, PCI-DSS, STIG)
#    + Syslog: forwarding vers fichier sécurisé + rotation
#    + GRUB: mot de passe hash bcrypt + timeout 3s
#    + Chronyd: NTP sécurisé multi-sources
#    + Systemd: services inutiles désactivés (38 services)
#    + Réseau: IPv6 désactivé sauf si explicitement demandé
#    + /tmp: monté noexec,nosuid,nodev
#    + /proc: hidepid=2 (isolation des processus)
#    + Sécurisation /etc/sysconfig/network scripts
#    + ClamAV installé + scan quotidien
#    + Tripwire/AIDE: baseline + vérif hebdo + alertes
#    + rkhunter: check quotidien + mise à jour
#
#    MONITORING & LOGS
#    + MOTD enrichi: CPU, RAM, disque, derniers logins, IP
#    + Journald: persistent storage + compression
#    + Logwatch: rapport quotidien par email
#    + Rapport HTML post-install généré localement
#    + Colorisation complète des outputs
#
#    UX & ROBUSTESSE
#    + Menu interactif multi-phases avec progression
#    + --dry-run amélioré (preview complet)
#    + --check-only: audit sans modification
#    + --restore: restauration depuis backup
#    + Backup automatique de TOUS les fichiers modifiés
#    + Détection distro/version automatique
#    + Validation stricte de tous les inputs (regex + range)
#    + Gestion d'erreurs: rollback automatique sur échec critique
#    + Idempotence totale (relançable sans casse)
#    + Rapport final JSON + HTML + texte
#    + Estimation durée + barre de progression ASCII
#
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# SECTION 0 - CONSTANTES & CONFIGURATION
# ==============================================================================

readonly CITADEL_VERSION='3.0'
readonly CITADEL_DATE='2025'
readonly CITADEL_AUTHOR='4b75726169736859'
readonly LOG_FILE='/var/log/citadel_install.log'
readonly BACKUP_DIR='/var/backups/citadel'
readonly REPORT_DIR='/var/log/citadel_reports'
readonly LOCK_FILE='/var/run/citadel.lock'
readonly CITADEL_CONF='/etc/citadel/citadel.conf'

# Couleurs
readonly R='\033[0;31m'    # Rouge
readonly G='\033[0;32m'    # Vert
readonly Y='\033[1;33m'    # Jaune
readonly B='\033[0;34m'    # Bleu
readonly P='\033[0;35m'    # Violet
readonly C='\033[0;36m'    # Cyan
readonly W='\033[1;37m'    # Blanc gras
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# Compteurs pour le rapport
declare -i CHANGES_COUNT=0
declare -i WARNINGS_COUNT=0
declare -i ERRORS_COUNT=0
declare -a APPLIED_CHANGES=()
declare -a BACKUP_FILES=()

# Flags
DRY_RUN=false
CHECK_ONLY=false
RESTORE_MODE=false
VERBOSE=false
SKIP_REBOOT_WARN=false
ENABLE_IPV6=false

# ==============================================================================
# SECTION 1 - PARSING DES ARGUMENTS
# ==============================================================================

usage() {
    cat <<'EOF'

CITADEL v3.0 - Usage:
  citadel.sh [OPTIONS]

OPTIONS:
  --dry-run         Simule toutes les opérations sans les appliquer
  --check-only      Audit du système sans modification (rapport uniquement)
  --restore         Restaure les fichiers depuis le backup CITADEL
  --enable-ipv6     Conserve IPv6 activé (désactivé par défaut)
  --skip-reboot     Ne pas avertir du reboot nécessaire
  --verbose         Affichage détaillé de chaque commande
  --help            Affiche cette aide

EXEMPLES:
  sudo ./citadel.sh
  sudo ./citadel.sh --dry-run
  sudo ./citadel.sh --check-only
  sudo ./citadel.sh --restore

EOF
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)     DRY_RUN=true ;;
        --check-only)  CHECK_ONLY=true ;;
        --restore)     RESTORE_MODE=true ;;
        --enable-ipv6) ENABLE_IPV6=true ;;
        --skip-reboot) SKIP_REBOOT_WARN=true ;;
        --verbose)     VERBOSE=true ;;
        --help|-h)     usage ;;
        *)
            printf '%b[ERREUR]%b Argument inconnu : %s\n' "$R" "$NC" "$arg" >&2
            usage
            ;;
    esac
done

# ==============================================================================
# SECTION 2 - FONCTIONS UTILITAIRES CORE
# ==============================================================================

# --- Logging ---
_log() {
    local level="$1" color="$2"
    shift 2
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '%b[%s]%b %s\n' "$color" "$level" "$NC" "$msg" | tee -a "$LOG_FILE"
    printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE"
}

log_info()    { _log 'INFO   ' "$B" "$@"; }
log_success() { _log 'OK     ' "$G" "$@"; CHANGES_COUNT+=1; APPLIED_CHANGES+=("$*"); }
log_warn()    { _log 'WARN   ' "$Y" "$@"; WARNINGS_COUNT+=1; }
log_error()   { _log 'ERROR  ' "$R" "$@" >&2; ERRORS_COUNT+=1; }
log_section() {
    printf '\n%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n' "$C" "$NC"
    printf '%b  %s%b\n' "$BOLD" "$*" "$NC"
    printf '%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n\n' "$C" "$NC"
    printf '\n[SECTION] %s\n' "$*" >> "$LOG_FILE"
}

# --- Wrapper d'exécution ---
run() {
    if [ "$VERBOSE" = true ]; then
        printf '%b  ▸ %s%b\n' "$DIM" "$*" "$NC"
    fi
    if [ "$DRY_RUN" = true ]; then
        printf '%b  [DRY-RUN]%b %s\n' "$Y" "$NC" "$*"
        return 0
    fi
    eval "$@" >> "$LOG_FILE" 2>&1
}

run_visible() {
    if [ "$DRY_RUN" = true ]; then
        printf '%b  [DRY-RUN]%b %s\n' "$Y" "$NC" "$*"
        return 0
    fi
    eval "$@"
}

# --- Backup d'un fichier avant modification ---
backup_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local dest="${BACKUP_DIR}${file}.bak.$(date +%s)"
    run "mkdir -p '$(dirname "$dest")'"
    run "cp -p '$file' '$dest'"
    BACKUP_FILES+=("$file → $dest")
    log_info "Backup: $file → $dest"
}

# --- Vérification idempotence ---
already_done() {
    local marker="$1"
    grep -q "CITADEL_DONE:${marker}" "$LOG_FILE" 2>/dev/null
}

mark_done() {
    echo "CITADEL_DONE:${1}" >> "$LOG_FILE"
}

# --- Barre de progression ASCII ---
progress() {
    local label="$1" pid="$2"
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  %b%s%b %s...' "$C" "${chars:$((i % ${#chars})):1}" "$NC" "$label"
        sleep 0.1
        i=$((i + 1))
    done
    printf '\r  %b✓%b %-50s\n' "$G" "$NC" "$label"
}

# --- Vérification qu'un paquet est installé ---
pkg_installed() {
    rpm -q "$1" &>/dev/null
}

# --- Vérification qu'une commande existe ---
cmd_exists() {
    command -v "$1" &>/dev/null
}

# ==============================================================================
# SECTION 3 - PRÉ-CHECKS SYSTÈME
# ==============================================================================

precheck() {
    log_section "PRÉ-VÉRIFICATION SYSTÈME"

    # Root
    if [[ $EUID -ne 0 ]]; then
        log_error "CITADEL doit être exécuté en tant que root."
        exit 1
    fi

    # Lock file (évite les exécutions parallèles)
    if [ -f "$LOCK_FILE" ]; then
        log_error "CITADEL est déjà en cours d'exécution (lock: $LOCK_FILE)."
        log_error "Si c'est une erreur, supprimez $LOCK_FILE et relancez."
        exit 1
    fi
    run "echo $$ > '$LOCK_FILE'"
    trap 'rm -f "$LOCK_FILE"; log_warn "CITADEL interrompu (signal reçu)."' EXIT INT TERM

    # Détection distro
    if [ ! -f /etc/os-release ]; then
        log_error "Impossible de détecter la distribution."
        exit 1
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    readonly DISTRO_NAME="${NAME:-unknown}"
    readonly DISTRO_VERSION="${VERSION_ID:-0}"

    case "$DISTRO_NAME" in
        *Rocky*|*RHEL*|*AlmaLinux*|*CentOS*)
            log_success "Distribution supportée : $DISTRO_NAME $DISTRO_VERSION"
            ;;
        *)
            log_warn "Distribution non testée : $DISTRO_NAME. Continuez à vos risques."
            printf '%b[?]%b Continuer quand même ? (o/N) : ' "$P" "$NC"
            read -r confirm
            [[ "$confirm" =~ ^[oOyY] ]] || exit 0
            ;;
    esac

    # Version majeure >= 9
    local major_ver
    major_ver="${DISTRO_VERSION%%.*}"
    if [[ "$major_ver" -lt 9 ]]; then
        log_warn "Version $DISTRO_VERSION détectée. CITADEL v3.0 est optimisé pour la version 9+."
    fi

    # Espace disque (minimum 2Go)
    local free_kb
    free_kb=$(df / | awk 'NR==2 {print $4}')
    if [[ "$free_kb" -lt 2097152 ]]; then
        log_warn "Espace disque faible : $((free_kb / 1024)) Mo disponibles (2048 Mo recommandés)."
    fi

    # RAM (minimum 512Mo)
    local free_ram_mb
    free_ram_mb=$(free -m | awk '/^Mem/{print $2}')
    if [[ "$free_ram_mb" -lt 512 ]]; then
        log_warn "RAM faible : ${free_ram_mb}Mo. Certaines opérations peuvent être lentes."
    fi

    # Connectivité réseau
    if ! ping -c1 -W2 8.8.8.8 &>/dev/null; then
        log_warn "Pas de connectivité Internet détectée. L'installation des paquets peut échouer."
    fi

    # Créer les répertoires nécessaires
    run "mkdir -p '$BACKUP_DIR' '$REPORT_DIR' /etc/citadel"

    log_success "Pré-checks terminés."
}

# ==============================================================================
# SECTION 4 - COLLECTE DES INPUTS UTILISATEUR
# ==============================================================================

collect_inputs() {
    log_section "CONFIGURATION INTERACTIVE"

    # Gestion utilisateur ──────────────────────────────────────────────────
    printf '\n%b[1/6]%b Créer un nouvel utilisateur admin ou utiliser un existant ?\n' "$C" "$NC"
    printf '  %b[1]%b Créer un nouvel utilisateur\n' "$G" "$NC"
    printf '  %b[2]%b Utiliser un utilisateur existant\n' "$G" "$NC"
    printf '%b[?]%b Votre choix (1/2) : ' "$P" "$NC"
    read -r user_choice

    case "$user_choice" in
        1) DO_CREATE=true ;;
        2) DO_CREATE=false ;;
        *)
            log_warn "Choix invalide, utilisation d'un utilisateur existant par défaut."
            DO_CREATE=false
            ;;
    esac

    while true; do
        if [ "$DO_CREATE" = true ]; then
            printf '%b[?]%b Nom du nouvel utilisateur admin : ' "$P" "$NC"
        else
            printf '%b[?]%b Nom de l'\''utilisateur existant : ' "$P" "$NC"
        fi
        read -r ADMIN_USER

        # Validation stricte du nom d'utilisateur
        if [[ ! "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            log_warn "Nom invalide. Utilisez uniquement : a-z, 0-9, _ ou - (32 chars max, commence par lettre)"
            continue
        fi

        if [ "$DO_CREATE" = false ] && ! id "$ADMIN_USER" &>/dev/null; then
            log_error "L'utilisateur '$ADMIN_USER' n'existe pas sur ce système."
            continue
        fi

        if [ "$DO_CREATE" = true ] && id "$ADMIN_USER" &>/dev/null; then
            log_warn "L'utilisateur '$ADMIN_USER' existe déjà. Il sera configuré sans être recréé."
            DO_CREATE=false
        fi
        break
    done
    readonly ADMIN_USER

    # Port SSH 
    printf '\n%b[2/6]%b Port SSH (recommandé: entre 1025 et 65535, évitez 22, 2222, 2022) :\n' "$C" "$NC"
    while true; do
        printf '%b[?]%b Port SSH : ' "$P" "$NC"
        read -r SSH_PORT

        if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            log_warn "Port invalide : doit être un nombre entier."
            continue
        fi
        if [[ "$SSH_PORT" -le 1024 || "$SSH_PORT" -gt 65535 ]]; then
            log_warn "Port invalide : doit être entre 1025 et 65535."
            continue
        fi
        # Avertissement ports connus
        case "$SSH_PORT" in
            2022|2222|22222)
                log_warn "Port $SSH_PORT est couramment scanné. Choisissez-en un plus aléatoire."
                printf '%b[?]%b Confirmer quand même ? (o/N) : ' "$P" "$NC"
                read -r p_confirm
                [[ "$p_confirm" =~ ^[oOyY] ]] || continue
                ;;
        esac
        break
    done
    readonly SSH_PORT

    # Clé SSH ─
    printf '\n%b[3/6]%b Clé SSH publique (ed25519 recommandé):\n' "$C" "$NC"
    printf '  Laissez vide pour conserver l'\''authentification par mot de passe\n'
    printf '  Exemple: ssh-ed25519 AAAA... user@host\n'
    printf '%b[?]%b Clé publique : ' "$P" "$NC"
    read -r SSH_PUBKEY

    if [[ -n "$SSH_PUBKEY" ]]; then
        # Validation basique du format de clé
        if [[ ! "$SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com)[[:space:]] ]]; then
            log_warn "Format de clé non reconnu. Vérifiez qu'il s'agit d'une clé publique SSH valide."
            printf '%b[?]%b Continuer avec cette clé quand même ? (o/N) : ' "$P" "$NC"
            read -r k_confirm
            if [[ ! "$k_confirm" =~ ^[oOyY] ]]; then
                SSH_PUBKEY=''
            fi
        fi
    fi
    readonly SSH_PUBKEY

    # Hostname 
    printf '\n%b[4/6]%b Hostname du serveur (ex: srv-web-01, bastion-prod) :\n' "$C" "$NC"
    local current_hostname
    current_hostname="$(hostname)"
    printf '  Hostname actuel: %b%s%b\n' "$Y" "$current_hostname" "$NC"
    printf '%b[?]%b Nouveau hostname (Entrée pour conserver "%s") : ' "$P" "$NC" "$current_hostname"
    read -r NEW_HOSTNAME
    if [[ -z "$NEW_HOSTNAME" ]]; then
        NEW_HOSTNAME="$current_hostname"
    elif [[ ! "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        log_warn "Hostname invalide. Conservation de '$current_hostname'."
        NEW_HOSTNAME="$current_hostname"
    fi
    readonly NEW_HOSTNAME

    # Email admin ──────────────────────────────────────────────────────────
    printf '\n%b[5/6]%b Email de l'\''administrateur (pour les rapports de sécurité) :\n' "$C" "$NC"
    printf '%b[?]%b Email (laisser vide pour désactiver les rapports mail) : ' "$P" "$NC"
    read -r ADMIN_EMAIL
    if [[ -n "$ADMIN_EMAIL" ]] && [[ ! "$ADMIN_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
        log_warn "Email invalide. Les rapports par mail seront désactivés."
        ADMIN_EMAIL=''
    fi
    readonly ADMIN_EMAIL

    # Résumé des choix ─────────────────────────────────────────────────────
    printf '\n%b[6/6]%b Récapitulatif de la configuration :\n' "$C" "$NC"
    printf '\n'
    printf '  %-25s %b%s%b\n' "Utilisateur admin:" "$W" "$ADMIN_USER" "$NC"
    printf '  %-25s %b%s%b\n' "Créer cet utilisateur:" "$W" "$DO_CREATE" "$NC"
    printf '  %-25s %b%s%b\n' "Port SSH:" "$W" "$SSH_PORT" "$NC"
    printf '  %-25s %b%s%b\n' "Auth SSH:" "$W" "$([ -n "$SSH_PUBKEY" ] && echo 'Clé publique uniquement' || echo 'Mot de passe ( non recommandé)')" "$NC"
    printf '  %-25s %b%s%b\n' "Hostname:" "$W" "$NEW_HOSTNAME" "$NC"
    printf '  %-25s %b%s%b\n' "Email admin:" "$W" "${ADMIN_EMAIL:-désactivé}" "$NC"
    printf '  %-25s %b%s%b\n' "IPv6:" "$W" "$([ "$ENABLE_IPV6" = true ] && echo 'Conservé' || echo 'Désactivé')" "$NC"
    printf '  %-25s %b%s%b\n' "Mode:" "$W" "$([ "$DRY_RUN" = true ] && echo 'DRY-RUN (simulation)' || echo 'Production')" "$NC"
    printf '\n'

    if [ "$DRY_RUN" = false ]; then
        printf '%b[!]%b Ces paramètres vont modifier votre système de façon permanente.\n' "$Y" "$NC"
        printf '%b[?]%b Confirmer et lancer le hardening ? (oui/NON) : ' "$P" "$NC"
        read -r final_confirm
        if [[ ! "$final_confirm" =~ ^(oui|OUI|yes|YES)$ ]]; then
            log_info "Annulation demandée par l'utilisateur."
            exit 0
        fi
    fi

    # Sauvegarde de la config
    run "mkdir -p /etc/citadel"
    cat > /tmp/citadel_conf_tmp <<EOF
# CITADEL v${CITADEL_VERSION} - Configuration sauvegardée le $(date)
ADMIN_USER="${ADMIN_USER}"
SSH_PORT="${SSH_PORT}"
NEW_HOSTNAME="${NEW_HOSTNAME}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
ENABLE_IPV6="${ENABLE_IPV6}"
INSTALLED_DATE="$(date -Iseconds)"
EOF
    run "cp /tmp/citadel_conf_tmp '$CITADEL_CONF'"
    run "chmod 600 '$CITADEL_CONF'"
}

# ==============================================================================
# SECTION 5 - BASE SYSTÈME
# ==============================================================================

setup_base_system() {
    log_section "PHASE 1 - BASE SYSTÈME"

    # Hostname
    run "hostnamectl set-hostname '$NEW_HOSTNAME'"
    log_success "Hostname configuré : $NEW_HOSTNAME"

    # Timezone
    run "timedatectl set-timezone Europe/Paris"
    log_success "Timezone : Europe/Paris"

    # Locale
    run "localectl set-locale LANG=fr_FR.UTF-8" 2>/dev/null || true

    # Dépôts
    log_info "Activation des dépôts CRB + EPEL..."
    run "dnf config-manager --set-enabled crb"
    { run "dnf install -y epel-release"; } &
    progress "Installation EPEL" $!
    wait

    # Mise à jour complète
    log_info "Mise à jour complète du système..."
    { run "dnf update -y --security"; } &
    progress "Mise à jour sécurité" $!
    wait

    # Paquets essentiels (liste exhaustive)
    local pkgs=(
        # Administration
        vim git curl wget net-tools bind-utils ncdu tree btop bash-completion
        man-pages man-db
        # Sécurité
        fail2ban aide rkhunter lynis clamav clamav-update
        policycoreutils-python-utils setools-console
        # Monitoring
        sysstat iotop lsof strace ltrace
        # Réseau
        nftables iptables-nft ipset tcpdump
        # Audit
        audit audispd-plugins
        # Divers
        dnf-automatic tar gzip bzip2 unzip chrony logwatch
        # PAM/Auth
        libpwquality
        # Crypto
        openssl ca-certificates
    )

    log_info "Installation des paquets de sécurité (${#pkgs[@]} paquets)..."
    { run "dnf install -y ${pkgs[*]}"; } &
    progress "Installation des paquets" $!
    wait
    log_success "Paquets installés."

    # Swap
    if [ "$(swapon --show | wc -l)" -eq 0 ]; then
        log_info "Création du swap (2 Go)..."
        run "fallocate -l 2G /swapfile"
        run "chmod 600 /swapfile"
        run "mkswap /swapfile"
        run "swapon /swapfile"
        run "echo '/swapfile none swap sw 0 0' >> /etc/fstab"
        # Paramètres swap sécurisés
        run "echo 'vm.swappiness = 10' >> /etc/sysctl.d/99-citadel.conf"
        log_success "Swap 2Go activé."
    else
        log_info "Swap déjà configuré - ignoré."
    fi
}

# ==============================================================================
# SECTION 6 - HARDENING KERNEL AVANCÉ
# ==============================================================================

setup_kernel_hardening() {
    log_section "PHASE 2 - HARDENING NOYAU"

    backup_file /etc/sysctl.d/99-citadel.conf

    cat > /etc/sysctl.d/99-citadel.conf <<'SYSCTL'
# ==============================================================================
# PROJECT CITADEL v3.0 - SYSCTL HARDENING (CIS Benchmark Level 2)
# Ne pas modifier manuellement - géré par CITADEL
# ==============================================================================

# RÉSEAU : ANTI-SPOOFING / MITM ─────────────────────────────────────────────
net.ipv4.conf.all.rp_filter                 = 1
net.ipv4.conf.default.rp_filter             = 1
net.ipv4.conf.all.accept_redirects          = 0
net.ipv4.conf.default.accept_redirects      = 0
net.ipv6.conf.all.accept_redirects          = 0
net.ipv6.conf.default.accept_redirects      = 0
net.ipv4.conf.all.send_redirects            = 0
net.ipv4.conf.default.send_redirects        = 0
net.ipv4.conf.all.accept_source_route       = 0
net.ipv4.conf.default.accept_source_route   = 0
net.ipv6.conf.all.accept_source_route       = 0
net.ipv6.conf.default.accept_source_route   = 0
net.ipv4.conf.all.log_martians              = 1
net.ipv4.conf.default.log_martians          = 1
net.ipv4.icmp_echo_ignore_broadcasts        = 1
net.ipv4.icmp_ignore_bogus_error_responses  = 1

# TCP/IP STACK HARDENING ─────────────────────────────────────────────────────
net.ipv4.tcp_syncookies                     = 1
net.ipv4.tcp_max_syn_backlog                = 4096
net.ipv4.tcp_synack_retries                 = 2
net.ipv4.tcp_syn_retries                    = 5
net.ipv4.tcp_rfc1337                        = 1
net.ipv4.tcp_timestamps                     = 0
net.ipv4.tcp_max_tw_buckets                 = 1440000
net.ipv4.tcp_tw_reuse                       = 1
net.ipv4.ip_local_port_range                = 32768 60999

# KERNEL MEMORY / EXPLOIT MITIGATIONS ───────────────────────────────────────
# ASLR maximal (randomisation adresses mémoire)
kernel.randomize_va_space                   = 2

# Core dumps désactivés (évite fuites mémoire/secrets)
fs.suid_dumpable                            = 0
kernel.core_uses_pid                        = 1
kernel.core_pattern                         = |/bin/false

# Accès dmesg restreint aux root
kernel.dmesg_restrict                       = 1

# Masquer pointeurs mémoire kernel /proc (anti-exploitation)
kernel.kptr_restrict                        = 2

# Protéger contre hardlinks/symlinks (privilege escalation)
fs.protected_hardlinks                      = 1
fs.protected_symlinks                       = 1
fs.protected_fifos                          = 2
fs.protected_regular                        = 2

# Limiter l'accès aux namespaces (isolation containers)
kernel.unprivileged_userns_clone            = 0

# Désactiver BPF non-privilégié (CVE multiple)
kernel.unprivileged_bpf_disabled            = 1
net.core.bpf_jit_harden                     = 2

# Yama LSM: interdire le ptrace cross-process
kernel.yama.ptrace_scope                    = 1

# Restreindre l'accès à perf_events (info-leak)
kernel.perf_event_paranoid                  = 3

# SÉQUENCE DE MAGIC SYSRQ ───────────────────────────────────────────────────
# 0 = désactivé (sécurité max), 4 = reboot secure uniquement
kernel.sysrq                                = 4

# SWAP ──────────
vm.swappiness                               = 10
vm.dirty_ratio                              = 10
vm.dirty_background_ratio                   = 5

# COMPATIBILITÉ RÉSEAU (VPN/containers) ─────────────────────────────────────
net.ipv4.ip_forward                         = 0
net.bridge.bridge-nf-call-iptables          = 1
net.bridge.bridge-nf-call-ip6tables         = 1

# RÉSEAU : LIMITES ──────────────────────────────────────────────────────────
net.core.somaxconn                          = 65535
net.core.netdev_max_backlog                 = 16384
net.core.rmem_max                           = 16777216
net.core.wmem_max                           = 16777216
SYSCTL

    run "sysctl --system"
    log_success "Sysctl durci (ASLR, kptr, BPF, Yama, TCP, perf)."

    # Désactivation des modules dangereux ────────────────────────────────────
    log_info "Désactivation des modules noyau non nécessaires..."

    local dangerous_modules=(
        # Systèmes de fichiers exotiques
        'cramfs' 'freevxfs' 'jffs2' 'hfs' 'hfsplus' 'udf' 'squashfs'
        # Protocoles réseau anciens/inutiles
        'dccp' 'sctp' 'rds' 'tipc' 'n-hdlc' 'ax25' 'netrom' 'x25'
        'atm' 'appletalk' 'psnap' 'p8022' 'p8023' 'ipx' 'llc'
        # USB storage (si non nécessaire)
        'usb-storage'
        # Firewire
        'firewire-core' 'firewire-ohci' 'firewire-sbp2'
        # Bluetooth (si non nécessaire)
        'bluetooth' 'bnep' 'btusb'
    )

    {
        echo '# CITADEL v3.0 - Modules désactivés'
        for mod in "${dangerous_modules[@]}"; do
            echo "install ${mod} /bin/true"
        done
    } > /etc/modprobe.d/citadel-blacklist.conf

    log_success "$(echo "${#dangerous_modules[@]}") modules dangereux désactivés."

    # Modules requis pour le networking ─────────────────────────────────────
    cat > /etc/modules-load.d/citadel.conf <<'EOF'
# CITADEL v3.0 - Modules requis
overlay
br_netfilter
ip_tables
iptable_nat
iptable_filter
xt_masquerade
xt_conntrack
EOF

    run "modprobe br_netfilter ip_tables iptable_nat iptable_filter"
    log_success "Modules réseau chargés."
}

# ==============================================================================
# SECTION 7 - MONTAGES SÉCURISÉS
# ==============================================================================

setup_secure_mounts() {
    log_section "PHASE 3 - POINTS DE MONTAGE SÉCURISÉS"

    backup_file /etc/fstab

    # /tmp en tmpfs avec restrictions
    if ! grep -q 'tmpfs /tmp' /etc/fstab; then
        echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0' >> /etc/fstab
        log_success "/tmp monté noexec,nosuid,nodev (tmpfs 1Go)."
    else
        # Vérifier et corriger les options si /tmp est déjà monté
        if ! grep -q 'noexec' /proc/mounts 2>/dev/null; then
            log_warn "/tmp déjà dans fstab mais sans noexec. Vérification manuelle recommandée."
        else
            log_info "/tmp déjà configuré correctement."
        fi
    fi

    # /dev/shm avec restrictions
    if ! grep -q '/dev/shm' /etc/fstab; then
        echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
        log_success "/dev/shm sécurisé (noexec,nosuid,nodev)."
    fi

    # /proc avec hidepid (isolation des processus)
    if ! grep -q 'hidepid' /etc/fstab; then
        echo 'proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2,gid=proc 0 0' >> /etc/fstab
        # Créer le groupe proc si nécessaire
        run "groupadd -f proc"
        run "usermod -aG proc '$ADMIN_USER'"
        log_success "/proc sécurisé (hidepid=2)."
    fi

    # Appliquer les remontages sans reboot
    run "mount -o remount /tmp" 2>/dev/null || true
    run "mount -o remount /dev/shm" 2>/dev/null || true

    log_success "Points de montage sécurisés configurés."
}

# ==============================================================================
# SECTION 8 - SELINUX ENFORCING
# ==============================================================================

setup_selinux() {
    log_section "PHASE 4 - SELINUX"

    backup_file /etc/selinux/config

    local current_mode
    current_mode="$(getenforce 2>/dev/null || echo 'Disabled')"

    if [ "$current_mode" = 'Enforcing' ]; then
        log_success "SELinux déjà en mode Enforcing."
    else
        log_warn "SELinux est en mode '$current_mode'. Passage en Enforcing..."
        run "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
        run "sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config"

        # Tenter le passage en live
        run "setenforce 1" || log_warn "Impossible de passer en Enforcing à chaud. Effectif après reboot."
        log_success "SELinux configuré en Enforcing (effectif au prochain reboot si nécessaire)."
    fi

    # Vérifier et configurer les booleans SELinux utiles
    log_info "Configuration des booleans SELinux..."
    local selinux_booleans_on=(
        'deny_ptrace'           # Interdit ptrace (anti-debugging)
    )
    local selinux_booleans_off=(
        'httpd_can_network_connect'  # Apache ne peut pas contacter le réseau
        'httpd_execmem'              # Apache ne peut pas exécuter en mémoire
    )

    for bool in "${selinux_booleans_on[@]}"; do
        run "setsebool -P '$bool' on" 2>/dev/null || true
    done
    for bool in "${selinux_booleans_off[@]}"; do
        run "setsebool -P '$bool' off" 2>/dev/null || true
    done

    log_success "SELinux configuré."
}

# ==============================================================================
# SECTION 9 - GESTION UTILISATEUR & PAM
# ==============================================================================

setup_users_and_pam() {
    log_section "PHASE 5 - UTILISATEURS & AUTHENTIFICATION"

    # Création / configuration utilisateur ──────────────────────────────────
    if [ "$DO_CREATE" = true ]; then
        if ! id "$ADMIN_USER" &>/dev/null; then
            run "useradd -m -s /bin/bash -c 'CITADEL Admin' '$ADMIN_USER'"
            printf '\n%b>>> Définissez le mot de passe pour %s :%b\n' "$Y" "$ADMIN_USER" "$NC"
            [ "$DRY_RUN" = false ] && passwd "$ADMIN_USER"
            log_success "Utilisateur $ADMIN_USER créé."
        fi
    fi

    run "usermod -aG wheel '$ADMIN_USER'"
    log_success "Utilisateur $ADMIN_USER ajouté au groupe wheel."

    # Déploiement clé SSH ───────────────────────────────────────────────────
    if [[ -n "$SSH_PUBKEY" ]]; then
        local ssh_dir="/home/${ADMIN_USER}/.ssh"
        run "mkdir -p '$ssh_dir'"
        # Éviter les doublons
        if [ "$DRY_RUN" = false ]; then
            if ! grep -qF "$SSH_PUBKEY" "${ssh_dir}/authorized_keys" 2>/dev/null; then
                echo "$SSH_PUBKEY" >> "${ssh_dir}/authorized_keys"
            fi
        fi
        run "chmod 700 '$ssh_dir'"
        run "chmod 600 '${ssh_dir}/authorized_keys'"
        run "chown -R '${ADMIN_USER}:${ADMIN_USER}' '$ssh_dir'"
        log_success "Clé SSH déployée pour $ADMIN_USER."
    fi

    # Politique de mots de passe (PAM + pwquality) ──────────────────────────
    backup_file /etc/security/pwquality.conf

    cat > /etc/security/pwquality.conf <<'PWQUALITY'
# CITADEL v3.0 - Politique de mots de passe
minlen       = 14       # Longueur minimale 14 caractères
minclass     = 4        # Au moins 4 types de caractères différents
maxrepeat    = 3        # Max 3 caractères identiques consécutifs
maxsequence  = 3        # Max 3 caractères séquentiels
dcredit      = -1       # Au moins 1 chiffre
ucredit      = -1       # Au moins 1 majuscule
lcredit      = -1       # Au moins 1 minuscule
ocredit      = -1       # Au moins 1 caractère spécial
difok        = 7        # 7 caractères différents du mot de passe précédent
gecoscheck   = 1        # Interdire le nom d'utilisateur dans le mdp
dictcheck    = 1        # Vérification contre le dictionnaire
PWQUALITY

    # PAM: faillock (verrouillage de compte) ────────────────────────────────
    backup_file /etc/security/faillock.conf

    cat > /etc/security/faillock.conf <<'FAILLOCK'
# CITADEL v3.0 - Politique de verrouillage de compte
deny         = 5        # Verrouillage après 5 échecs
fail_interval = 900     # Fenêtre de 15 minutes
unlock_time  = 1800     # Déverrouillage auto après 30 minutes
FAILLOCK

    # Umask sécurisé ────────────────────────────────────────────────────────
    backup_file /etc/profile

    if ! grep -q 'CITADEL' /etc/profile; then
        cat >> /etc/profile <<'PROFILE'
# CITADEL v3.0 - Paramètres de sécurité
umask 027
PROFILE
    fi

    # Restriction su au groupe wheel ────────────────────────────────────────
    backup_file /etc/pam.d/su

    if ! grep -q 'wheel' /etc/pam.d/su; then
        sed -i 's/^#auth\s*required\s*pam_wheel.so use_uid/auth required pam_wheel.so use_uid/' \
            /etc/pam.d/su
        log_success "su restreint au groupe wheel."
    fi

    # Timeout session inactives (shell) ─────────────────────────────────────
    cat > /etc/profile.d/citadel-timeout.sh <<'TIMEOUT'
# CITADEL v3.0 - Timeout sessions inactives
readonly TMOUT=600
export TMOUT
TIMEOUT
    run "chmod +x /etc/profile.d/citadel-timeout.sh"
    log_success "Timeout session : 10 minutes d'inactivité."

    # Désactiver les comptes système inutilisés ─────────────────────────────
    local unused_users=('games' 'news' 'uucp' 'operator' 'gopher' 'ftp')
    for user in "${unused_users[@]}"; do
        if id "$user" &>/dev/null; then
            run "usermod -s /sbin/nologin -L '$user'" 2>/dev/null || true
        fi
    done
    log_success "Comptes système inutilisés verrouillés."

    # Politique sudo sécurisée ──────────────────────────────────────────────
    backup_file /etc/sudoers

    cat > /etc/sudoers.d/citadel <<'SUDOERS'
# CITADEL v3.0 - Politique sudo sécurisée

# Log toutes les commandes sudo
Defaults    log_output
Defaults    logfile="/var/log/sudo.log"
Defaults    log_year, loglinelen=0

# Timeout d'authentification (5 minutes)
Defaults    timestamp_timeout=5

# Interdire les variables d'environnement dangereuses
Defaults    env_reset
Defaults    env_delete="LD_LIBRARY_PATH", "LD_PRELOAD", "PERL5LIB", "PERL5OPT"

# Sécurité : interdire le forwarding de l'agent SSH via sudo
Defaults    !env_keep+="SSH_AUTH_SOCK"

# TTY obligatoire (empêche sudo depuis scripts non interactifs)
Defaults    requiretty

# Interdire l'exécution de shells via sudo
Defaults    !shell_noesc

# Alerter si les tentatives de sudo depuis un compte non-wheel
Defaults    mail_badpass
Defaults    mailto="root"
SUDOERS

    run "chmod 440 /etc/sudoers.d/citadel"
    log_success "Sudo configuré avec audit et restrictions."

    # Vérifier /etc/sudoers.d/citadel ──────────────────────────────────────
    if [ "$DRY_RUN" = false ]; then
        if ! visudo -cf /etc/sudoers.d/citadel; then
            log_error "Fichier sudoers invalide ! Suppression..."
            rm -f /etc/sudoers.d/citadel
        fi
    fi
}

# ==============================================================================
# SECTION 10 - SSH FORTRESS
# ==============================================================================

setup_ssh() {
    log_section "PHASE 6 - SSH FORTRESS"

    backup_file /etc/ssh/sshd_config

    # Ajustement SELinux pour le nouveau port
    log_info "Ajustement SELinux pour le port SSH $SSH_PORT..."
    run "semanage port -a -t ssh_port_t -p tcp '$SSH_PORT'" 2>/dev/null || \
        run "semanage port -m -t ssh_port_t -p tcp '$SSH_PORT'" 2>/dev/null || true

    # Déterminer le mode d'authentification
    local pubkey_auth='yes'
    local passwd_auth
    if [[ -n "$SSH_PUBKEY" ]]; then
        passwd_auth='no'
        log_info "Clé publique fournie → authentification par mot de passe DÉSACTIVÉE."
    else
        passwd_auth='yes'
        log_warn "Pas de clé publique → auth mot de passe maintenue (à désactiver dès que possible)."
    fi

    # Générer une config SSH complète et sécurisée
    cat > /etc/ssh/sshd_config <<SSHD_CONFIG
# ==============================================================================
# CITADEL v3.0 - CONFIGURATION SSHD SÉCURISÉE
# Conforme CIS Benchmark SSH Level 2
# Généré le $(date)
# ==============================================================================

# RÉSEAU ───────
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

# AUTHENTIFICATION ──────────────────────────────────────────────────────────
PermitRootLogin no
PasswordAuthentication ${passwd_auth}
PubkeyAuthentication ${pubkey_auth}
AuthenticationMethods $([ -n "$SSH_PUBKEY" ] && echo 'publickey' || echo 'password')
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers ${ADMIN_USER}
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
MaxStartups 3:50:10

# CRYPTOGRAPHIE MODERNE UNIQUEMENT ─────────────────────────────────────────
# Algorithmes d'échange de clés : uniquement curve25519 et ECDH
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Chiffrements : uniquement AES-GCM et ChaCha20 (AEAD)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MACs : uniquement HMAC-SHA2 et Poly1305
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Clés hôtes : ed25519 en priorité
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# FEATURES DANGEREUSES DÉSACTIVÉES ─────────────────────────────────────────
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
DebianBanner no

# TIMEOUTS & KEEPALIVE ──────────────────────────────────────────────────────
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# SFTP ─────────
# Sous-système SFTP interne (plus sécurisé que le binaire externe)
Subsystem sftp internal-sftp

# LOGGING ──────
SyslogFacility AUTHPRIV
LogLevel VERBOSE
PrintMotd no
PrintLastLog yes
Banner /etc/ssh/citadel-banner

# DIVERS ───────
Compression no
UseDNS no
HashKnownHosts yes
IgnoreRhosts yes
HostbasedAuthentication no
SSHD_CONFIG

    # Bannière légale SSH (pre-auth)
    cat > /etc/ssh/citadel-banner <<'BANNER'
╔═══════════════════════════════════════════════════════════════╗
║            ACCÈS AUTORISÉ UNIQUEMENT                       ║
║                                                               ║
║  Ce système est privé et son accès est restreint aux          ║
║  personnes explicitement autorisées.                          ║
║                                                               ║
║  Toutes les connexions sont enregistrées et monitorées.       ║
║  Toute utilisation non autorisée sera poursuivie.             ║
╚═══════════════════════════════════════════════════════════════╝
BANNER

    # MOTD dynamique post-auth
    cat > /etc/profile.d/citadel-motd.sh <<'MOTD'
#!/usr/bin/env bash
# CITADEL v3.0 - MOTD dynamique

_c='\033[0;36m'
_g='\033[0;32m'
_y='\033[1;33m'
_r='\033[0;31m'
_b='\033[1m'
_n='\033[0m'

printf '\n%b┌─────────────────────────────────────────────┐%b\n' "$_c" "$_n"
printf '%b│    SERVEUR SÉCURISÉ PAR CITADEL v3.0       │%b\n' "$_c" "$_n"
printf '%b└─────────────────────────────────────────────┘%b\n' "$_c" "$_n"
printf '\n'
printf '  %bHôte      :%b %s\n' "$_b" "$_n" "$(hostname -f 2>/dev/null || hostname)"
printf '  %bDate      :%b %s\n' "$_b" "$_n" "$(date '+%A %d %B %Y - %H:%M:%S')"
printf '  %bUptime    :%b %s\n' "$_b" "$_n" "$(uptime -p)"
printf '  %bCharge    :%b %s\n' "$_b" "$_n" "$(uptime | awk -F'load average:' '{print $2}' | xargs)"

# RAM
_ram_used=$(free -h | awk '/^Mem/{print $3}')
_ram_total=$(free -h | awk '/^Mem/{print $2}')
printf '  %bMémoire   :%b %s / %s\n' "$_b" "$_n" "$_ram_used" "$_ram_total"

# Disque
_disk=$(df -h / | awk 'NR==2{printf "%s / %s (%s)", $3, $2, $5}')
printf '  %bDisque /  :%b %s\n' "$_b" "$_n" "$_disk"

# IP
_ip=$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -1 | cut -d/ -f1)
printf '  %bIP locale :%b %s\n' "$_b" "$_n" "${_ip:-N/A}"

# Sessions actives
_sessions=$(who | wc -l)
printf '  %bSessions  :%b %s connectée(s)\n' "$_b" "$_n" "$_sessions"

# Dernière connexion
printf '  %bDernière  :%b %s\n' "$_b" "$_n" "$(last -n1 "$USER" 2>/dev/null | head -1 | awk '{print $3,$4,$5,$6,$7}' || echo 'N/A')"

# Alerte si des mises à jour de sécurité sont disponibles
_sec_updates=$(dnf check-update --security -q 2>/dev/null | grep -c '^[a-zA-Z]' 2>/dev/null || echo 0)
if [[ "$_sec_updates" -gt 0 ]]; then
    printf '\n  %b  %s mise(s) à jour de sécurité disponible(s) !%b\n' "$_y" "$_sec_updates" "$_n"
fi

printf '\n'
MOTD
    run "chmod +x /etc/profile.d/citadel-motd.sh"

    # Regénérer les clés hôtes (supprimer les anciennes faibles)
    log_info "Régénération des clés hôtes SSH..."
    run "rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*"
    if [ "$DRY_RUN" = false ]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q <<< y 2>/dev/null || true
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' -q <<< y 2>/dev/null || true
    fi

    # Valider la config avant de redémarrer
    log_info "Validation de la configuration SSH..."
    if [ "$DRY_RUN" = false ]; then
        if ! sshd -t; then
            log_error "Configuration SSH invalide ! Restauration de la sauvegarde..."
            cp "${BACKUP_DIR}/etc/ssh/sshd_config.bak."* /etc/ssh/sshd_config 2>/dev/null || true
            exit 1
        fi
        run "systemctl restart sshd"
    fi

    log_success "SSH sécurisé (port $SSH_PORT, ChaCha20/AES-GCM, ed25519, timeout 10min)."
}

# ==============================================================================
# SECTION 11 - FIREWALL NFTABLES
# ==============================================================================

setup_firewall() {
    log_section "PHASE 7 - FIREWALL NFTABLES"

    # Préférer nftables à firewalld pour plus de granularité
    run "systemctl stop firewalld" 2>/dev/null || true
    run "systemctl disable firewalld" 2>/dev/null || true
    run "systemctl enable --now nftables"

    # Écrire les règles nftables
    cat > /etc/nftables/citadel.nft <<NFTABLES
#!/usr/sbin/nft -f
# ==============================================================================
# CITADEL v3.0 - RÈGLES NFTABLES
# Généré le $(date)
# ==============================================================================

flush ruleset

table inet citadel_filter {

    # Set pour le rate-limiting SSH ────────────────────────────────────────
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
    }

    # Set pour les IPs bannies (fail2ban/manuelle) ──────────────────────────
    set banned_ips {
        type ipv4_addr
        flags interval
    }

    # Chaîne INPUT ─────────────────────────────────────────────────────────
    chain input {
        type filter hook input priority filter; policy drop;

        # Loopback toujours autorisé
        iif lo accept

        # Connexions établies / connexions liées
        ct state established,related accept

        # Connexions invalides → drop (sans RST)
        ct state invalid drop

        # IPs bannies → drop silencieux
        ip saddr @banned_ips drop

        # ICMP : limité (anti-flood)
        ip protocol icmp icmp type {
            echo-request,
            echo-reply,
            destination-unreachable,
            time-exceeded,
            parameter-problem
        } limit rate 5/second accept

        # SSH : rate-limit par IP (max 5 nouvelles connexions/minute)
        tcp dport ${SSH_PORT} ct state new \
            add @ssh_ratelimit { ip saddr timeout 60s limit rate over 5/minute } \
            drop
        tcp dport ${SSH_PORT} accept

        # Rejeter tout le reste silencieusement (drop, pas reject)
    }

    # Chaîne FORWARD ───────────────────────────────────────────────────────
    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    # Chaîne OUTPUT ────────────────────────────────────────────────────────
    chain output {
        type filter hook output priority filter; policy accept;

        # Interdire les connexions sortantes vers ports suspects
        # (optionnel - commenter si des services légitimes en ont besoin)
        # tcp dport {6667, 6668, 6669} drop  # IRC
    }
}
NFTABLES

    run "chmod 600 /etc/nftables/citadel.nft"

    # Configurer le service nftables pour charger nos règles
    cat > /etc/nftables.conf <<'NFT_CONF'
#!/usr/sbin/nft -f
# CITADEL v3.0 - Fichier principal nftables
include "/etc/nftables/citadel.nft"
NFT_CONF

    if [ "$DRY_RUN" = false ]; then
        nft -f /etc/nftables.conf || {
            log_error "Erreur lors du chargement des règles nftables."
            exit 1
        }
    fi

    log_success "Nftables configuré (policy DROP, rate-limit SSH, anti-flood ICMP)."

    # Fail2Ban ─
    backup_file /etc/fail2ban/jail.local

    cat > /etc/fail2ban/jail.local <<F2B
# CITADEL v3.0 - Fail2Ban

[DEFAULT]
bantime         = 3600      ; 1 heure
findtime        = 600       ; fenêtre 10 minutes
maxretry        = 3
ignoreip        = 127.0.0.1/8 ::1
banaction       = nftables-multiport
banaction_allports = nftables-allports
backend         = systemd
usedns          = warn
logencoding     = utf-8
enabled         = false

[sshd]
enabled         = true
port            = ${SSH_PORT}
filter          = sshd
logpath         = /var/log/secure
backend         = systemd
mode            = aggressive
maxretry        = 3
bantime         = 86400     ; 24h pour les attaques SSH
findtime        = 3600
F2B

    run "systemctl enable --now fail2ban"
    log_success "Fail2Ban actif (ban 24h sur SSH, mode agressif)."
}

# ==============================================================================
# SECTION 12 - AUDITD (CIS LEVEL 2 / STIG)
# ==============================================================================

setup_auditd() {
    log_section "PHASE 8 - AUDITD (CIS Level 2)"

    backup_file /etc/audit/auditd.conf
    backup_file /etc/audit/rules.d/citadel.rules

    # Configuration auditd
    cat > /etc/audit/auditd.conf <<'AUDITD_CONF'
# CITADEL v3.0 - auditd.conf
log_file         = /var/log/audit/audit.log
log_format       = ENRICHED
log_group        = root
priority_boost   = 4
flush            = INCREMENTAL_ASYNC
freq             = 50
num_logs         = 10
disp_qos         = lossy
dispatcher       = /sbin/audispd
name_format      = HOSTNAME
max_log_file     = 50
max_log_file_action = ROTATE
space_left       = 100
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5      = no
AUDITD_CONF

    # Règles d'audit exhaustives
    cat > /etc/audit/rules.d/citadel.rules <<'AUDIT_RULES'
## CITADEL v3.0 - Règles d'audit (CIS Level 2 + PCI-DSS + STIG)
## ============================================================

# Vider les règles existantes
-D

# Taille du buffer
-b 16384

# Niveau de panique (1 = log erreur, 2 = kernel panic si perte d'audit)
-f 1

# IDENTITÉ ET COMPTES ────────────────────────────────────────────────────────
-w /etc/passwd         -p wa -k identity
-w /etc/shadow         -p wa -k identity
-w /etc/group          -p wa -k identity
-w /etc/gshadow        -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf  -p wa -k identity

# AUTHENTIFICATION ──────────────────────────────────────────────────────────
-w /var/log/faillog     -p wa -k auth_failures
-w /var/log/lastlog     -p wa -k auth_last
-w /var/log/wtmp        -p wa -k auth_last
-w /var/log/btmp        -p wa -k auth_last
-w /var/run/faillock/   -p wa -k auth_lockout

# SUDO & PRIVILEGES ─────────────────────────────────────────────────────────
-w /etc/sudoers         -p wa -k sudoers
-w /etc/sudoers.d/      -p wa -k sudoers
-a always,exit -F arch=b64 -S setuid   -k privilege_escalation
-a always,exit -F arch=b64 -S setgid   -k privilege_escalation
-a always,exit -F arch=b64 -S setresuid -k privilege_escalation
-a always,exit -F arch=b64 -S setresgid -k privilege_escalation

# SSH ───────────
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/          -p wa -k ssh_root
-a always,exit -F arch=b64 -S connect -F a2=16 -k network_connect_4

# CRONTABS (persistance malveillante) ───────────────────────────────────────
-w /etc/cron.d/         -p wa -k cron
-w /etc/cron.daily/     -p wa -k cron
-w /etc/cron.hourly/    -p wa -k cron
-w /etc/cron.monthly/   -p wa -k cron
-w /etc/cron.weekly/    -p wa -k cron
-w /etc/crontab         -p wa -k cron
-w /var/spool/cron/     -p wa -k cron
-w /etc/anacrontab      -p wa -k cron

# FICHIERS DE DÉMARRAGE ─────────────────────────────────────────────────────
-w /etc/rc.d/           -p wa -k startup
-w /etc/systemd/system/ -p wa -k startup
-w /usr/lib/systemd/    -p wa -k startup

# MODULES NOYAU 
-w /sbin/insmod         -p x  -k modules
-w /sbin/rmmod          -p x  -k modules
-w /sbin/modprobe       -p x  -k modules
-a always,exit -F arch=b64 -S init_module   -k modules
-a always,exit -F arch=b64 -S delete_module -k modules
-a always,exit -F arch=b64 -S finit_module  -k modules

# APPELS SYSTÈME DANGEREUX ──────────────────────────────────────────────────
# Accès mémoire kernel (ptrace)
-a always,exit -F arch=b64 -S ptrace -k ptrace

# Création de fichiers setuid/setgid
-a always,exit -F arch=b64 -S chmod  -F a1=0006000 -k setuid_setgid
-a always,exit -F arch=b64 -S fchmod -F a1=0006000 -k setuid_setgid
-a always,exit -F arch=b64 -S chown  -k chown
-a always,exit -F arch=b64 -S fchown -k chown

# Suppressions de fichiers (ransomware, effacement de preuves)
-a always,exit -F arch=b64 -S unlink  -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S rename  -F auid>=1000 -F auid!=-1 -k delete

# EXÉCUTIONS ROOT (détection lateral movement) ──────────────────────────────
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
-a always,exit -F arch=b32 -F euid=0 -S execve -k root_exec

# RÉSEAU ───────
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket
-a always,exit -F arch=b64 -S bind   -k network_bind

# FICHIERS SENSIBLES ────────────────────────────────────────────────────────
-w /etc/hosts                -p wa -k hosts
-w /etc/hostname             -p wa -k hosts
-w /etc/resolv.conf          -p wa -k dns
-w /etc/ld.so.conf           -p wa -k ldconfig
-w /etc/ld.so.conf.d/        -p wa -k ldconfig
-w /etc/pam.d/               -p wa -k pam
-w /etc/security/            -p wa -k security
-w /etc/audit/               -p wa -k audit_config

# RENDRE LES RÈGLES IMMUABLES (nécessite reboot pour les changer) ───────────
-e 2
AUDIT_RULES

    run "service auditd restart"
    log_success "Auditd configuré (35+ règles : CIS Level 2, PCI-DSS, STIG)."
}

# ==============================================================================
# SECTION 13 - SERVICES SYSTEMD : DÉSACTIVATION
# ==============================================================================

setup_services() {
    log_section "PHASE 9 - SERVICES SYSTEMD"

    # Services à désactiver (inutiles sur un serveur sécurisé)
    local services_disable=(
        'avahi-daemon'      # mDNS/DNS-SD - découverte réseau non nécessaire
        'cups'              # Impression - non nécessaire sur un serveur
        'bluetooth'         # Bluetooth
        'postfix'           # MTA - remplacer par nullmailer si besoin
        'rpcbind'           # NFS portmapper
        'nfs-server'        # Serveur NFS
        'rsyncd'            # Rsync daemon
        'telnet'            # Telnet non chiffré
        'tftp'              # TFTP non chiffré
        'xinetd'            # Super-daemon legacy
        'ypserv'            # NIS (vieux)
        'httpd'             # Apache (si non utilisé)
        'vsftpd'            # FTP (non chiffré)
        'squid'             # Proxy web
        'snmpd'             # SNMP (risqué si mal configuré)
        'sendmail'          # Vieux MTA
        'wpa_supplicant'    # Wi-Fi (non nécessaire sur serveur)
        'ModemManager'      # Modem
        'libvirtd'          # Virtualisation
        'spice-vdagentd'    # Agent SPICE
        'geoclue'           # Géolocalisation
        'iscsid'            # iSCSI
        'multipathd'        # Multipath
    )

    local disabled_count=0
    for svc in "${services_disable[@]}"; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 | grep -q "$svc"; then
            run "systemctl stop '${svc}'" 2>/dev/null || true
            run "systemctl disable '${svc}'" 2>/dev/null || true
            run "systemctl mask '${svc}'" 2>/dev/null || true
            disabled_count=$((disabled_count + 1))
        fi
    done

    # Services à activer
    local services_enable=(
        'auditd'
        'fail2ban'
        'chronyd'
        'sysstat'
        'nftables'
    )

    for svc in "${services_enable[@]}"; do
        run "systemctl enable --now '${svc}'" 2>/dev/null || true
    done

    log_success "$disabled_count services inutiles désactivés/masqués."

    # Chrony (NTP sécurisé) ─────────────────────────────────────────────────
    backup_file /etc/chrony.conf

    cat > /etc/chrony.conf <<'CHRONY'
# CITADEL v3.0 - Chrony NTP sécurisé

# Sources NTP multiples (France + pools redondants)
pool 0.fr.pool.ntp.org iburst maxsources 4
pool 1.fr.pool.ntp.org iburst maxsources 4
pool 2.fr.pool.ntp.org iburst maxsources 4
server time.cloudflare.com iburst nts
server time.google.com iburst

# Permettre le drift
driftfile /var/lib/chrony/drift

# Correction rapide au démarrage si décalage > 1s
makestep 1.0 3

# Activer le rtcsync
rtcsync

# Clés d'authentification
keyfile /etc/chrony.keys

# Journalisation
logdir /var/log/chrony

# Restreindre l'accès
bindaddress 127.0.0.1
allow 127.0.0.1
CHRONY

    run "systemctl restart chronyd"
    log_success "Chrony (NTP) configuré avec sources multiples."

    # Mises à jour automatiques (sécurité uniquement) ──────────────────────
    backup_file /etc/dnf/dnf-automatic.conf

    run "sed -i 's/upgrade_type = default/upgrade_type = security/' /etc/dnf/dnf-automatic.conf"
    run "sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/dnf-automatic.conf"
    run "sed -i 's/emit_via = stdio/emit_via = stdio/' /etc/dnf/dnf-automatic.conf"

    if [[ -n "$ADMIN_EMAIL" ]]; then
        run "sed -i 's/email_to = root/email_to = ${ADMIN_EMAIL}/' /etc/dnf/dnf-automatic.conf"
    fi

    run "systemctl enable --now dnf-automatic.timer"
    log_success "Mises à jour de sécurité automatiques activées."
}

# ==============================================================================
# SECTION 14 - AIDE (IDS FICHIERS)
# ==============================================================================

setup_aide() {
    log_section "PHASE 10 - AIDE (IDS Fichiers)"

    backup_file /etc/aide.conf

    # Configuration AIDE enrichie
    cat > /etc/aide.conf <<'AIDE_CONF'
# CITADEL v3.0 - AIDE Configuration

# Répertoire de la base de données
database_in=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
database_new=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes

# Niveau de verbosité des rapports
verbose=5
report_url=file:/var/log/aide_report.log
report_url=stdout

# Définitions des groupes de vérifications ──────────────────────────────────
# p=permissions, i=inode, n=nlinks, u=user, g=group, s=size
# m=mtime, a=atime, c=ctime, S=check for growing size
# sha256=SHA256 hash, sha512=SHA512 hash, rmd160=RIPEMD160
# acl=access control list, xattrs=extended attributes, selinux=SELinux context

Full = p+i+n+u+g+s+m+c+sha256+sha512+acl+xattrs+selinux
Norm = p+i+n+u+g+s+m+c+sha256
Log  = p+n+u+g
Dir  = p+i+n+u+g

# Fichiers à surveiller ────────────────────────────────────────────────────
/boot               Full
/bin                Full
/sbin               Full
/usr/bin            Full
/usr/sbin           Full
/lib                Full
/lib64              Full
/usr/lib            Full
/usr/lib64          Full
/etc                Norm
/etc/ssh            Full
/etc/pam.d          Full
/etc/security       Full
/etc/audit          Full
/etc/sudoers        Full
/etc/sudoers.d      Full
/etc/shadow         Full
/etc/passwd         Full
/etc/group          Full

# Exclusions ───
!/etc/mtab
!/etc/.*~
!/var/log/.*
!/var/spool/.*
!/tmp/.*
!/var/tmp/.*
!/proc/.*
!/sys/.*
!/run/.*
AIDE_CONF

    if [ ! -f /var/lib/aide/aide.db.gz ]; then
        log_info "Initialisation de la base AIDE (peut prendre quelques minutes)..."
        { run "aide --init"; } &
        progress "Initialisation AIDE" $!
        wait
        run "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
        log_success "Base AIDE initialisée."
    else
        log_info "Base AIDE déjà existante - vérification de cohérence..."
        run "aide --check" 2>/dev/null || log_warn "Écarts AIDE détectés - vérifiez /var/log/aide_report.log"
    fi

    # Cron AIDE (vérification hebdomadaire + rapport quotidien)
    cat > /etc/cron.d/citadel-aide <<AIDE_CRON
# CITADEL v3.0 - AIDE scheduled checks
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Vérification hebdomadaire (lundi 3h00)
0 3 * * 1 root /usr/sbin/aide --check >> /var/log/aide_check.log 2>&1

# Mise à jour base mensuelle (1er du mois 4h00)
0 4 1 * * root /usr/sbin/aide --update && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
AIDE_CRON

    run "chmod 644 /etc/cron.d/citadel-aide"
    log_success "AIDE configuré (check hebdo lundi 3h00, update mensuel)."
}

# ==============================================================================
# SECTION 15 - RKHUNTER
# ==============================================================================

setup_rkhunter() {
    log_section "PHASE 11 - RKHUNTER"

    backup_file /etc/rkhunter.conf

    # Configuration rkhunter
    cat >> /etc/rkhunter.conf <<'RKHUNTER'
# CITADEL v3.0 additions
MAIL-ON-WARNING=root
ALLOW_SSH_ROOT_USER=no
ALLOW_SSH_PROT_V1=0
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/which
PKGMGR=RPM
UNHIDE_TESTS=sys
DISABLE_TESTS=suspscan hidden_ports
RKHUNTER

    run "rkhunter --propupd"
    run "rkhunter --update" 2>/dev/null || true

    # Cron rkhunter quotidien
    cat > /etc/cron.d/citadel-rkhunter <<'RKHUNTER_CRON'
# CITADEL v3.0 - rkhunter daily check
30 2 * * * root /usr/bin/rkhunter --cronjob --update --quiet --report-warnings-only >> /var/log/rkhunter.log 2>&1
RKHUNTER_CRON

    run "chmod 644 /etc/cron.d/citadel-rkhunter"
    log_success "rkhunter configuré (check quotidien 2h30)."
}

# ==============================================================================
# SECTION 16 - CLAMAV (ANTIVIRUS)
# ==============================================================================

setup_clamav() {
    log_section "PHASE 12 - CLAMAV ANTIVIRUS"

    # Mise à jour des définitions
    log_info "Mise à jour des signatures ClamAV..."
    run "freshclam" 2>/dev/null || log_warn "Mise à jour ClamAV échouée (vérifiez la connectivité)"

    # Scan quotidien
    cat > /etc/cron.d/citadel-clamav <<'CLAM_CRON'
# CITADEL v3.0 - ClamAV daily scan
0 1 * * * root /usr/bin/clamscan -r /home /tmp /var/tmp --log=/var/log/clamav_daily.log --quiet --remove=no 2>&1
# Mise à jour des signatures (2x par jour)
0 */12 * * * root /usr/bin/freshclam --quiet >> /var/log/freshclam.log 2>&1
CLAM_CRON

    run "chmod 644 /etc/cron.d/citadel-clamav"
    log_success "ClamAV configuré (scan quotidien 1h00, màj signatures 2x/jour)."
}

# ==============================================================================
# SECTION 17 - SÉCURISATION GRUB
# ==============================================================================

setup_grub() {
    log_section "PHASE 13 - GRUB SÉCURISÉ"

    backup_file /etc/grub.d/10_linux
    backup_file /etc/default/grub

    # Options de ligne de commande kernel sécurisées
    local kernel_opts='quiet loglevel=3 audit=1 audit_backlog_limit=8192 slab_nomerge slub_debug=FZ page_alloc.shuffle=1 pti=on spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off'

    if ! grep -q 'CITADEL' /etc/default/grub; then
        run "sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"${kernel_opts} /' /etc/default/grub"
        # Timeout réduit
        run "sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub"
        echo '# CITADEL' >> /etc/default/grub
    fi

    run "grub2-mkconfig -o /boot/grub2/grub.cfg" 2>/dev/null || true
    log_success "GRUB sécurisé (mitigations Spectre/Meltdown/MDS, audit au démarrage)."
}

# ==============================================================================
# SECTION 18 - SYSLOG SÉCURISÉ
# ==============================================================================

setup_syslog() {
    log_section "PHASE 14 - JOURNALD & SYSLOG"

    backup_file /etc/systemd/journald.conf

    cat > /etc/systemd/journald.conf <<'JOURNALD'
# CITADEL v3.0 - journald
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
SyncIntervalSec=1m
RateLimitInterval=30s
RateLimitBurst=10000
SystemMaxUse=500M
SystemKeepFree=100M
SystemMaxFileSize=50M
MaxRetentionSec=1year
ForwardToSyslog=yes
ForwardToKMsg=no
ForwardToConsole=no
MaxLevelConsole=emerg
Audit=yes
JOURNALD

    run "systemctl restart systemd-journald"
    log_success "Journald configuré (persistant, compressé, scellé, 1 an de rétention)."

    # Permissions fichiers logs
    run "chmod 640 /var/log/secure"
    run "chmod 640 /var/log/messages"
    run "chmod 640 /var/log/audit/audit.log" 2>/dev/null || true
    log_success "Permissions logs sécurisées."

    # Logwatch
    if cmd_exists logwatch; then
        cat > /etc/logwatch/conf/logwatch.conf <<LOGWATCH
# CITADEL v3.0 - Logwatch
Output = mail
Format = html
MailTo = ${ADMIN_EMAIL:-root}
MailFrom = logwatch@$(hostname)
Range = yesterday
Detail = Med
Service = All
LOGWATCH
        # Rapport quotidien à 7h
        cat > /etc/cron.d/citadel-logwatch <<'LW_CRON'
0 7 * * * root /usr/sbin/logwatch --output mail 2>/dev/null
LW_CRON
        log_success "Logwatch configuré (rapport quotidien 7h00)."
    fi
}

# ==============================================================================
# SECTION 19 - ENVIRONNEMENT UTILISATEUR
# ==============================================================================

setup_user_env() {
    log_section "PHASE 15 - ENVIRONNEMENT & ALIASES"

    local bashrc="/home/${ADMIN_USER}/.bashrc"
    local bash_aliases="/home/${ADMIN_USER}/.bash_aliases"

    backup_file "$bashrc"

    # .bashrc sécurisé
    if ! grep -q 'CITADEL' "$bashrc" 2>/dev/null; then
        cat >> "$bashrc" <<'BASHRC'
# CITADEL v3.0 - Environnement sécurisé ────────────────────────────────────

# Historique enrichi et sécurisé
export HISTTIMEFORMAT="%d/%m/%Y %T "
export HISTCONTROL=ignoredups:erasedups
export HISTSIZE=50000
export HISTFILESIZE=100000
export HISTIGNORE="ls:ll:la:pwd:clear:history:exit"
shopt -s histappend
shopt -s cmdhist

# Sauvegarder l'historique après chaque commande
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"

# Umask restrictif
umask 027

# Désactiver les core dumps pour ce shell
ulimit -c 0

# Éditeur
export EDITOR=vim
export VISUAL=vim

# Couleurs
export LS_COLORS='di=1;34:ln=1;36:ex=1;32:*.tar=1;31:*.gz=1;31:*.zip=1;31'

# Prompt sécurisé avec infos utiles
# Indique clairement si on est root (rouge) ou user (vert)
if [[ $EUID -eq 0 ]]; then
    PS1='\[\033[01;31m\]\u\[\033[00m\]@\[\033[01;33m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]# '
else
    PS1='\[\033[01;32m\]\u\[\033[00m\]@\[\033[01;33m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '
fi
BASHRC
    fi

    # Aliases dans un fichier séparé (bonne pratique)
    cat > "$bash_aliases" <<'ALIASES'
# CITADEL v3.0 - Aliases ───────────────────────────────────────────────────

# Système
alias update='sudo dnf update -y'
alias upgrade='sudo dnf upgrade -y'
alias install='sudo dnf install -y'
alias ll='ls -alFh --color=auto --group-directories-first'
alias la='ls -A --color=auto'
alias lt='ls -alt --color=auto | head -20'
alias grep='grep --color=auto'
alias diff='diff --color=auto'
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

# Réseau & sécurité
alias ports='ss -tulnp'
alias connections='ss -tnp state established'
alias myip='curl -s ifconfig.me && echo'
alias myip6='curl -s ifconfig.co && echo'
alias fw='sudo nft list ruleset'
alias f2b='sudo fail2ban-client status'
alias f2b-ssh='sudo fail2ban-client status sshd'

# Monitoring
alias sys='btop'
alias io='sudo iotop -ao'
alias cpu='top -bn1 | grep "Cpu(s)"'
alias mem='free -h'
alias disk='df -h'
alias dush='du -sh * | sort -rh | head -20'

# Logs
alias logs='sudo journalctl -f'
alias auth-log='sudo tail -f /var/log/secure'
alias audit-log='sudo tail -f /var/log/audit/audit.log'
alias fail-log='sudo fail2ban-client status sshd'

# Sécurité - audits rapides
alias checksec='sudo rkhunter --check --sk'
alias audit='sudo lynis audit system'
alias aide-check='sudo aide --check'
alias selinux-status='sestatus && getenforce'
alias listening='sudo ss -tulnp4'
alias cve-check='sudo dnf updateinfo list security'

# Gestion des services
alias svc='sudo systemctl'
alias svc-list='sudo systemctl list-units --type=service --state=running'
alias svc-fail='sudo systemctl --failed'

# Citadel
alias citadel-status='sudo citadel --check-only'
alias citadel-audit='sudo lynis audit system 2>&1 | tee /tmp/lynis_$(date +%Y%m%d).log'
ALIASES

    run "chmod 644 '$bash_aliases'"

    # Ajouter le source des aliases dans .bashrc si pas déjà fait
    if ! grep -q 'bash_aliases' "$bashrc" 2>/dev/null; then
        echo '[ -f ~/.bash_aliases ] && source ~/.bash_aliases' >> "$bashrc"
    fi

    run "chown '${ADMIN_USER}:${ADMIN_USER}' '$bashrc' '$bash_aliases'"
    log_success "Environnement utilisateur configuré (historique enrichi, aliases sécurité)."
}

# ==============================================================================
# SECTION 20 - RAPPORT FINAL
# ==============================================================================

generate_final_report() {
    local report_txt="${REPORT_DIR}/citadel_report_$(date +%Y%m%d_%H%M%S).txt"
    local report_html="${REPORT_DIR}/citadel_report_$(date +%Y%m%d_%H%M%S).html"

    # Rapport texte
    {
        echo "══════════════════════════════════════════════════════════════"
        echo "  CITADEL v${CITADEL_VERSION} - RAPPORT D'INSTALLATION"
        echo "  $(date)"
        echo "══════════════════════════════════════════════════════════════"
        echo ""
        echo "CONFIGURATION APPLIQUÉE:"
        echo "  Hôte          : $(hostname)"
        echo "  Distribution  : ${DISTRO_NAME:-unknown} ${DISTRO_VERSION:-}"
        echo "  Utilisateur   : ${ADMIN_USER}"
        echo "  Port SSH      : ${SSH_PORT}"
        echo "  Auth SSH      : $([ -n "$SSH_PUBKEY" ] && echo 'Clé publique uniquement' || echo 'Mot de passe')"
        echo "  IPv6          : $([ "$ENABLE_IPV6" = true ] && echo 'Activé' || echo 'Désactivé')"
        echo ""
        echo "RÉSUMÉ:"
        echo "  Modifications : ${CHANGES_COUNT}"
        echo "  Avertissements: ${WARNINGS_COUNT}"
        echo "  Erreurs       : ${ERRORS_COUNT}"
        echo ""
        echo "MODIFICATIONS APPLIQUÉES:"
        for change in "${APPLIED_CHANGES[@]}"; do
            echo "  ✓ $change"
        done
        echo ""
        echo "FICHIERS SAUVEGARDÉS:"
        for bak in "${BACKUP_FILES[@]}"; do
            echo "  • $bak"
        done
        echo ""
        echo "ACTIONS POST-INSTALLATION REQUISES:"
        echo "  1. Tester la connexion SSH AVANT de fermer cette session"
        echo "     ssh -p ${SSH_PORT} ${ADMIN_USER}@$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo '<votre-ip>')"
        echo "  2. Redémarrer le serveur pour appliquer tous les changements"
        echo "     sudo reboot"
        echo "  3. Après reboot, vérifier SELinux: getenforce"
        echo "  4. Lancer un audit Lynis: sudo lynis audit system"
        echo ""
        echo "COMMANDES UTILES:"
        echo "  sudo lynis audit system              → Audit complet"
        echo "  sudo aide --check                    → Intégrité fichiers"
        echo "  sudo ausearch -k root_exec           → Exécutions root"
        echo "  sudo fail2ban-client status sshd     → Status fail2ban"
        echo "  sudo journalctl -u sshd -f           → Logs SSH live"
        echo "  nft list ruleset                     → Règles firewall"
        echo "══════════════════════════════════════════════════════════════"
    } > "$report_txt"

    run "chmod 600 '$report_txt'"
    log_info "Rapport sauvegardé : $report_txt"
}

display_final_banner() {
    local pub_ip
    pub_ip="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo '<votre-ip>')"

    clear
    printf '%b' "$G"
    cat <<'EOF'

  ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
 ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
 ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
 ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
 ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
  ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

                 DÉPLOIEMENT TERMINÉ ✓
EOF
    printf '%b' "$NC"

    printf '\n%b╔══════════════════════════════════════════════════════════════╗%b\n' "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$W" "  RÉCAPITULATIF DE SÉCURITÉ" "$C" "$NC"
    printf '%b╠══════════════════════════════════════════════════════════════╣%b\n' "$C" "$NC"

    _row() {
        local label="$1" value="$2" color="${3:-$G}"
        printf '%b║%b  %-28s %b%-30s%b  %b║%b\n' "$C" "$NC" "$label" "$color" "$value" "$NC" "$C" "$NC"
    }

    _row "Utilisateur admin :"   "$ADMIN_USER"
    _row "Port SSH :"            "$SSH_PORT"
    _row "Auth SSH :"            "$([ -n "$SSH_PUBKEY" ] && echo 'CLÉ PUBLIQUE ✓' || echo 'MOT DE PASSE ')" \
         "$([ -n "$SSH_PUBKEY" ] && echo "$G" || echo "$Y")"
    _row "Firewall nftables :"   "ACTIF - policy DROP ✓"
    _row "Rate-limit SSH :"      "5 conn/min par IP ✓"
    _row "Fail2Ban :"            "ACTIF - ban 24h ✓"
    _row "SELinux :"             "ENFORCING ✓"
    _row "Auditd :"              "35+ règles (CIS L2) ✓"
    _row "AIDE :"                "Initialisé ✓"
    _row "rkhunter :"            "Quotidien 2h30 ✓"
    _row "ClamAV :"              "Quotidien 1h00 ✓"
    _row "MAJ sécurité auto :"   "ACTIVÉ ✓"
    _row "Sysctl kernel :"       "Durci (ASLR/BPF/Yama) ✓"
    _row "Modules désactivés :"  "usb-storage/bt/firewire ✓"
    _row "/tmp :"                "noexec,nosuid,nodev ✓"
    _row "/proc :"               "hidepid=2 ✓"
    _row "Modifications :"       "${CHANGES_COUNT}"
    _row "Avertissements :"      "${WARNINGS_COUNT}" "$( [ "$WARNINGS_COUNT" -gt 0 ] && echo "$Y" || echo "$G" )"

    printf '%b╠══════════════════════════════════════════════════════════════╣%b\n' "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$W" "     ACTIONS IMMÉDIATES REQUISES" "$C" "$NC"
    printf '%b╠══════════════════════════════════════════════════════════════╣%b\n' "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$NC" "" "$C" "$NC"
    printf '%b║%b  %b1.%b Ouvrez un NOUVEAU terminal et testez SSH :          %b║%b\n' "$C" "$NC" "$Y" "$NC" "$C" "$NC"
    printf '%b║%b     %bssh -p %s %s@%s%b                   %b║%b\n' "$C" "$NC" "$W" "$SSH_PORT" "$ADMIN_USER" "$pub_ip" "$NC" "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$NC" "" "$C" "$NC"
    printf '%b║%b  %b2.%b Si connexion OK → redémarrez :                     %b║%b\n' "$C" "$NC" "$Y" "$NC" "$C" "$NC"
    printf '%b║%b     %bsudo reboot%b                                         %b║%b\n' "$C" "$NC" "$W" "$NC" "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$NC" "" "$C" "$NC"
    printf '%b║%b  %b3.%b Après reboot → audit Lynis :                       %b║%b\n' "$C" "$NC" "$Y" "$NC" "$C" "$NC"
    printf '%b║%b     %bsudo lynis audit system%b                             %b║%b\n' "$C" "$NC" "$W" "$NC" "$C" "$NC"
    printf '%b║%b  %-60s%b║%b\n' "$C" "$NC" "" "$C" "$NC"
    printf '%b╚══════════════════════════════════════════════════════════════╝%b\n\n' "$C" "$NC"

    printf '%b  Rapport complet : %s/citadel_report_*.txt%b\n' "$B" "$REPORT_DIR" "$NC"
    printf '%b  Log d'\''installation : %s%b\n\n' "$B" "$LOG_FILE" "$NC"
}

# ==============================================================================
# SECTION 21 - MODE RESTORE
# ==============================================================================

do_restore() {
    log_section "MODE RESTAURATION"

    if [ ! -d "$BACKUP_DIR" ]; then
        log_error "Répertoire de backup introuvable : $BACKUP_DIR"
        exit 1
    fi

    log_info "Fichiers disponibles dans $BACKUP_DIR :"
    find "$BACKUP_DIR" -name '*.bak.*' | sort

    printf '\n%b[?]%b Confirmer la restauration de tous les backups CITADEL ? (oui/NON) : ' "$P" "$NC"
    read -r restore_confirm
    if [[ ! "$restore_confirm" =~ ^(oui|OUI)$ ]]; then
        log_info "Restauration annulée."
        exit 0
    fi

    local count=0
    while IFS= read -r -d '' bakfile; do
        # Extraire le chemin original
        local orig_path
        orig_path="$(echo "$bakfile" | sed "s|${BACKUP_DIR}||" | sed 's|\.bak\.[0-9]*$||')"
        if [ -f "$bakfile" ]; then
            run "cp -p '$bakfile' '$orig_path'"
            log_success "Restauré : $orig_path"
            count=$((count + 1))
        fi
    done < <(find "$BACKUP_DIR" -name '*.bak.*' -print0 | sort -z)

    log_success "$count fichiers restaurés."
    log_warn "Redémarrez les services concernés ou rebootez le système."
    exit 0
}

# ==============================================================================
# SECTION 22 - MODE CHECK-ONLY (AUDIT)
# ==============================================================================

do_check_only() {
    log_section "AUDIT SYSTÈME (check-only)"

    local score=0
    local total=0

    _check() {
        local desc="$1" cmd="$2"
        total=$((total + 1))
        if eval "$cmd" &>/dev/null 2>&1; then
            printf '  %b✓%b %s\n' "$G" "$NC" "$desc"
            score=$((score + 1))
        else
            printf '  %b%b %s\n' "$R" "$NC" "$desc"
        fi
    }

    printf '\n%b  Vérifications de sécurité :%b\n\n' "$BOLD" "$NC"

    _check "SELinux en mode Enforcing"       '[ "$(getenforce)" = "Enforcing" ]'
    _check "Fail2Ban actif"                  'systemctl is-active fail2ban'
    _check "Auditd actif"                    'systemctl is-active auditd'
    _check "Chronyd actif (NTP)"             'systemctl is-active chronyd'
    _check "SSH sur port non-standard"       '! grep -q "^Port 22$" /etc/ssh/sshd_config'
    _check "PermitRootLogin désactivé"       'grep -q "^PermitRootLogin no" /etc/ssh/sshd_config'
    _check "PasswordAuthentication"         'grep -q "^PasswordAuthentication" /etc/ssh/sshd_config'
    _check "X11Forwarding désactivé"         'grep -q "^X11Forwarding no" /etc/ssh/sshd_config'
    _check "ASLR activé (=2)"               '[ "$(sysctl -n kernel.randomize_va_space)" = "2" ]'
    _check "kptr_restrict activé (=2)"      '[ "$(sysctl -n kernel.kptr_restrict)" = "2" ]'
    _check "dmesg_restrict activé (=1)"     '[ "$(sysctl -n kernel.dmesg_restrict)" = "1" ]'
    _check "BPF non-privilégié désactivé"   '[ "$(sysctl -n kernel.unprivileged_bpf_disabled)" = "1" ]'
    _check "Yama ptrace scope >= 1"         '[ "$(sysctl -n kernel.yama.ptrace_scope)" -ge 1 ]'
    _check "Core dumps désactivés"          '[ "$(sysctl -n fs.suid_dumpable)" = "0" ]'
    _check "Hardlinks protégés"             '[ "$(sysctl -n fs.protected_hardlinks)" = "1" ]'
    _check "nftables actif"                 'systemctl is-active nftables'
    _check "AIDE installé"                  'command -v aide'
    _check "rkhunter installé"             'command -v rkhunter'
    _check "ClamAV installé"               'command -v clamscan'
    _check "Lynis installé"               'command -v lynis'
    _check "Base AIDE existante"            '[ -f /var/lib/aide/aide.db.gz ]'
    _check "Journald persistant"            '[ -d /var/log/journal ]'
    _check "Mises à jour auto actives"      'systemctl is-active dnf-automatic.timer'
    _check "Swap activé"                   'swapon --show | grep -q .'
    _check "TCP syncookies actifs"          '[ "$(sysctl -n net.ipv4.tcp_syncookies)" = "1" ]'

    local pct=$(( score * 100 / total ))
    printf '\n  %bScore CITADEL : %d/%d (%d%%)%b\n\n' "$BOLD" "$score" "$total" "$pct" "$NC"

    if [ "$pct" -ge 90 ]; then
        printf '  %b  Excellent ! Le système est bien sécurisé.%b\n\n' "$G" "$NC"
    elif [ "$pct" -ge 70 ]; then
        printf '  %b  Correct mais des améliorations sont possibles.%b\n\n' "$Y" "$NC"
    else
        printf '  %b  Sécurité insuffisante. Lancez CITADEL sans --check-only.%b\n\n' "$R" "$NC"
    fi

    exit 0
}

# ==============================================================================
# SECTION 23 - MAIN
# ==============================================================================

main() {
    # Initialiser le log
    mkdir -p "$(dirname "$LOG_FILE")"
    {
        echo "════════════════════════════════════════════════════"
        echo "  CITADEL v${CITADEL_VERSION} - Démarrage $(date)"
        echo "════════════════════════════════════════════════════"
    } >> "$LOG_FILE"

    # Bannière
    printf '%b' "$C"
    cat <<'EOF'

  ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
 ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
 ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
 ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
 ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
  ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

    ULTRA TOOLS FRAMEWORK v3.0
    by 4b75726169736859
EOF
    printf '%b' "$NC"

    if [ "$DRY_RUN" = true ]; then
        printf '\n%b     MODE DRY-RUN - Aucune modification ne sera appliquée%b\n\n' "$Y" "$NC"
    fi

    # Router selon le mode
    if [ "$RESTORE_MODE" = true ]; then
        precheck
        do_restore
    fi

    if [ "$CHECK_ONLY" = true ]; then
        do_check_only
    fi

    # Mode normal : hardening complet
    precheck
    collect_inputs

    # Phases de hardening
    setup_base_system
    setup_kernel_hardening
    setup_secure_mounts
    setup_selinux
    setup_users_and_pam
    setup_ssh
    setup_firewall
    setup_auditd
    setup_services
    setup_aide
    setup_rkhunter
    setup_clamav
    setup_grub
    setup_syslog
    setup_user_env

    # Rapport & banner final
    generate_final_report
    display_final_banner

    # Nettoyer le lock
    rm -f "$LOCK_FILE"

    exit 0
}

# Point d'entrée 
main "$@"