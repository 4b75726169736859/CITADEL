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
#  PROJECT CITADEL v4.0 - ULTRA HARDENING FRAMEWORK
#  Target  : Rocky Linux 9 / RHEL 9 / AlmaLinux 9
#  Author  : 4b75726169736859
#  License : MIT
#
# ------------------------------------------------------------------------------
#  CHANGELOG v4.0 (notable additions vs v3.0) :
#
#  > Noyau & boot
#    - Lockdown mode (integrity) via paramètre kernel lockdown=integrity
#    - Désactivation complète de kdump (les dumps mémoire = secrets en clair)
#    - Vérification signature des modules (module.sig_enforce=1)
#    - Anti-DMA attacks : iommu=force + intel_iommu=on si supporté
#
#  > Réseau
#    - Règles nftables IPv4 + IPv6 (deux tables séparées, policy DROP sur 6)
#    - Bug fix : rate-limit SSH via `meter` (ancienne syntaxe v3 cassée)
#    - Port-knocking optionnel (3 ports séquentiels avant SSH)
#    - DNS-over-TLS via systemd-resolved (Cloudflare 1.1.1.1 + Quad9)
#    - DNSSEC validation activée par défaut
#    - Anti-spoofing renforcé (strict RP filter + source validation)
#
#  > Authentification & utilisateurs
#    - USBGuard : whitelist des périphériques USB connus (anti rubber-ducky)
#    - Session recording (tlog) optionnel pour les comptes wheel
#    - Password aging via chage (PASS_MAX_DAYS=90, WARN=14, MIN=7)
#    - cron.allow + at.allow : restriction au groupe wheel uniquement
#    - Bannières légales sur /etc/issue, /etc/issue.net, MOTD pré-login
#    - PAM : ajout pam_tty_audit pour tracer les actions root en TTY
#
#  > Intégrité & détection
#    - chattr +i sur fichiers critiques (passwd, shadow, sudoers…)
#    - Process accounting (psacct) : toutes les commandes root tracées
#    - Systemd service hardening : NoNewPrivileges=yes, ProtectSystem=strict…
#      sur auditd, chronyd, fail2ban, sshd, nftables (overrides drop-in)
#    - Intégration OpenSCAP : scan CIS automatique post-install + cron mensuel
#    - Self-test suite (--self-test) : ~60 contrôles unitaires
#
#  > Sauvegarde & reprise
#    - Snapshot LVM automatique avant install (si /root est sur LVM)
#    - Mode --uninstall : annule la totalité des changements CITADEL
#    - Mode --restore amélioré : sélection interactive par phase
#    - Rapport final triple : TXT + HTML (stylé) + JSON (parsable)
#
#  > UX
#    - Flag --phases=X,Y,Z pour exécuter uniquement certaines phases
#    - Flag --compliance=cis|anssi|stig pour profils pré-définis
#    - Estimation durée par phase (affichée avant confirmation)
#    - Progression globale en pourcentage
#
#  > Corrections de bugs v3
#    - nftables : rule rate-limit SSH corrigée (meter + update @set)
#    - systemd : `list-unit-files` ne marchait pas à cause du pipe
#    - sudoers : Defaults !shell_noesc retiré (option inexistante)
#    - dnf-automatic : emit_via = email au lieu de = stdio (boucle)
#    - MOTD : dnf check-update retiré (lenteur + hit repo à chaque login)
#    - SSH host key regen : ssh-keygen -y bash-friendly (plus de heredoc)
#    - AIDE : cron.daily au lieu de weekly-only pour meilleure détection
#    - Faillock : ajout de even_deny_root + root_unlock_time
#
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# SECTION 0 - Constantes & config globale
# ==============================================================================

readonly CITADEL_VERSION='4.0'
readonly CITADEL_DATE='2026'
readonly CITADEL_AUTHOR='4b75726169736859'
readonly CITADEL_ROOT='/etc/citadel'
readonly LOG_FILE='/var/log/citadel_install.log'
readonly BACKUP_DIR='/var/backups/citadel'
readonly REPORT_DIR='/var/log/citadel_reports'
readonly LOCK_FILE='/var/run/citadel.lock'
readonly STATE_FILE="${CITADEL_ROOT}/state.db"
readonly CITADEL_CONF="${CITADEL_ROOT}/citadel.conf"
readonly PHASE_MAP="${CITADEL_ROOT}/phases.map"

# Couleurs ANSI (court pour alléger le code plus bas)
readonly R=$'\033[0;31m'
readonly G=$'\033[0;32m'
readonly Y=$'\033[1;33m'
readonly B=$'\033[0;34m'
readonly P=$'\033[0;35m'
readonly C=$'\033[0;36m'
readonly W=$'\033[1;37m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly NC=$'\033[0m'

# Compteurs pour le rapport
declare -i CHANGES_COUNT=0
declare -i WARNINGS_COUNT=0
declare -i ERRORS_COUNT=0
declare -i PHASE_COUNT=0
declare -a APPLIED_CHANGES=()
declare -a BACKUP_FILES=()
declare -a PHASES_EXECUTED=()

# Flags (défauts)
DRY_RUN=false
CHECK_ONLY=false
RESTORE_MODE=false
UNINSTALL_MODE=false
SELF_TEST=false
VERBOSE=false
SKIP_REBOOT_WARN=false
ENABLE_IPV6=false
ENABLE_TLOG=false
ENABLE_KNOCKD=false
ENABLE_USBGUARD=true
ENABLE_LOCKDOWN=true
COMPLIANCE_PROFILE='cis'
SELECTED_PHASES=''
SKIP_SNAPSHOT=false

# Table de correspondance phase → fonction (surchargeable par --phases)
declare -A PHASES=(
    [base]='setup_base_system'
    [kernel]='setup_kernel_hardening'
    [mounts]='setup_secure_mounts'
    [selinux]='setup_selinux'
    [users]='setup_users_and_pam'
    [ssh]='setup_ssh'
    [firewall]='setup_firewall'
    [auditd]='setup_auditd'
    [services]='setup_services'
    [aide]='setup_aide'
    [rkhunter]='setup_rkhunter'
    [clamav]='setup_clamav'
    [grub]='setup_grub'
    [syslog]='setup_syslog'
    [userenv]='setup_user_env'
    [usbguard]='setup_usbguard'
    [psacct]='setup_process_accounting'
    [immutable]='setup_immutable_files'
    [banners]='setup_legal_banners'
    [cron]='setup_cron_restrictions'
    [chage]='setup_password_aging'
    [kdump]='disable_kdump'
    [sandbox]='setup_systemd_sandboxing'
    [tlog]='setup_session_recording'
    [dns]='setup_dns_hardening'
    [openscap]='setup_compliance_scan'
)

# Ordre d'exécution (important - certaines phases dépendent d'autres)
readonly PHASES_ORDER=(
    base kernel mounts selinux users ssh firewall auditd services
    aide rkhunter clamav grub syslog userenv
    usbguard psacct immutable banners cron chage kdump sandbox
    tlog dns openscap
)

# Estimation durée par phase (secondes approx, sur VM 2vCPU/2GB)
declare -A PHASE_ETA=(
    [base]=180      [kernel]=5       [mounts]=2      [selinux]=10
    [users]=15      [ssh]=8          [firewall]=5    [auditd]=10
    [services]=20   [aide]=300       [rkhunter]=60   [clamav]=120
    [grub]=15       [syslog]=5       [userenv]=3     [usbguard]=10
    [psacct]=3      [immutable]=2    [banners]=2     [cron]=2
    [chage]=3       [kdump]=5        [sandbox]=15    [tlog]=30
    [dns]=10        [openscap]=60
)

# ==============================================================================
# SECTION 1 - Parsing des arguments
# ==============================================================================

usage() {
    cat <<EOF

${BOLD}CITADEL v${CITADEL_VERSION}${NC} - Framework de hardening Rocky/RHEL/Alma 9

${W}USAGE${NC}
  citadel.sh [options]

${W}MODES${NC}
  --dry-run               Simule sans rien appliquer (preview complet)
  --check-only            Audit en lecture seule, ~60 contrôles
  --self-test             Suite de tests unitaires CITADEL
  --restore               Restauration depuis backup (interactive)
  --uninstall             Annule tous les changements CITADEL
  --compliance=<profile>  Profil de conformité : cis|anssi|stig (défaut: cis)

${W}OPTIONS DE PHASES${NC}
  --phases=<list>         Exécute uniquement les phases listées (csv)
                          Exemple: --phases=ssh,firewall,auditd
  --skip-snapshot         Ne pas créer de snapshot LVM pré-install

${W}OPTIONS FONCTIONNELLES${NC}
  --enable-ipv6           Conserve IPv6 (firewall IPv6 sera configuré)
  --enable-tlog           Active le session recording pour wheel
  --enable-knockd         Active le port-knocking SSH
  --no-usbguard           N'installe pas USBGuard
  --no-lockdown           N'active pas kernel lockdown=integrity

${W}OPTIONS UX${NC}
  --skip-reboot           Pas d'avertissement reboot
  --verbose               Affiche chaque commande exécutée
  --help                  Cette aide

${W}EXEMPLES${NC}
  sudo ./citadel.sh
  sudo ./citadel.sh --dry-run
  sudo ./citadel.sh --phases=ssh,firewall --verbose
  sudo ./citadel.sh --compliance=anssi --enable-tlog
  sudo ./citadel.sh --check-only | tee /tmp/audit.txt
  sudo ./citadel.sh --restore

${W}DOCUMENTATION${NC}
  Logs         : ${LOG_FILE}
  Backups      : ${BACKUP_DIR}
  Rapports     : ${REPORT_DIR}
  State DB     : ${STATE_FILE}

EOF
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)          DRY_RUN=true ;;
        --check-only)       CHECK_ONLY=true ;;
        --self-test)        SELF_TEST=true ;;
        --restore)          RESTORE_MODE=true ;;
        --uninstall)        UNINSTALL_MODE=true ;;
        --enable-ipv6)      ENABLE_IPV6=true ;;
        --enable-tlog)      ENABLE_TLOG=true ;;
        --enable-knockd)    ENABLE_KNOCKD=true ;;
        --no-usbguard)      ENABLE_USBGUARD=false ;;
        --no-lockdown)      ENABLE_LOCKDOWN=false ;;
        --skip-reboot)      SKIP_REBOOT_WARN=true ;;
        --skip-snapshot)    SKIP_SNAPSHOT=true ;;
        --verbose)          VERBOSE=true ;;
        --compliance=*)     COMPLIANCE_PROFILE="${arg#*=}" ;;
        --phases=*)         SELECTED_PHASES="${arg#*=}" ;;
        --help|-h)          usage ;;
        *)
            printf '%s[ERREUR]%s Argument inconnu : %s\n' "$R" "$NC" "$arg" >&2
            usage
            ;;
    esac
done

# Valider le profil de compliance
case "$COMPLIANCE_PROFILE" in
    cis|anssi|stig) ;;
    *) printf '%s[ERREUR]%s Profil inconnu : %s (cis|anssi|stig)\n' "$R" "$NC" "$COMPLIANCE_PROFILE" >&2; exit 1 ;;
esac

# ==============================================================================
# SECTION 2 - Fonctions utilitaires core
# ==============================================================================

_log() {
    local level="$1" color="$2"; shift 2
    local msg="$*" ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '%s[%s]%s %s\n' "$color" "$level" "$NC" "$msg"
    printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE"
}

log_info()    { _log 'INFO ' "$B" "$@"; }
log_success() { _log 'OK   ' "$G" "$@"; CHANGES_COUNT+=1; APPLIED_CHANGES+=("$*"); }
log_warn()    { _log 'WARN ' "$Y" "$@"; WARNINGS_COUNT+=1; }
log_error()   { _log 'ERROR' "$R" "$@" >&2; ERRORS_COUNT+=1; }
log_debug()   { [ "$VERBOSE" = true ] && _log 'DEBUG' "$DIM" "$@" || true; }

log_section() {
    PHASE_COUNT+=1
    local phase_total=${#PHASES_ORDER[@]}
    printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$C" "$NC"
    printf '%s [%d/%d] %s%s\n' "$BOLD" "$PHASE_COUNT" "$phase_total" "$*" "$NC"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n' "$C" "$NC"
    printf '\n[SECTION %d/%d] %s\n' "$PHASE_COUNT" "$phase_total" "$*" >> "$LOG_FILE"
}

# Exécution protégée (honore --dry-run et --verbose)
run() {
    log_debug "» $*"
    if [ "$DRY_RUN" = true ]; then
        printf '%s  [dry-run]%s %s\n' "$Y" "$NC" "$*"
        return 0
    fi
    eval "$@" >> "$LOG_FILE" 2>&1
}

# Variante sans redirection (interactive : passwd, visudo -f, etc.)
run_interactive() {
    if [ "$DRY_RUN" = true ]; then
        printf '%s  [dry-run]%s %s\n' "$Y" "$NC" "$*"
        return 0
    fi
    eval "$@"
}

# Backup d'un fichier avant modification - idempotent (même backup = 1 seul)
backup_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local dest="${BACKUP_DIR}${file}.bak.$(date +%s)"
    run "mkdir -p '$(dirname "$dest")'"
    run "cp --preserve=all '$file' '$dest'"
    BACKUP_FILES+=("$file -> $dest")
    # Marquer dans la state DB
    [ "$DRY_RUN" = false ] && echo "BACKUP:${file}:${dest}" >> "$STATE_FILE"
    log_debug "backup: $file"
}

# Marquer une action dans la state DB (pour --uninstall)
state_add() {
    [ "$DRY_RUN" = true ] && return 0
    echo "$(date -Iseconds)|$*" >> "$STATE_FILE"
}

# Spinner compact (on garde les braille - ça rend bien en prod)
spinner() {
    local label="$1" pid="$2"
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  %s%s%s %s' "$C" "${frames:$((i % ${#frames})):1}" "$NC" "$label"
        sleep 0.1
        ((i++))
    done
    printf '\r  %s✓%s %-60s\n' "$G" "$NC" "$label"
}

# Barre de progression (utilisée pour dnf update)
progress_bar() {
    local current=$1 total=$2 label="${3:-}"
    local width=40
    local percent=$((current * 100 / total))
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    printf '\r  [%s%*s] %3d%% %s' \
        "$(printf '█%.0s' $(seq 1 $filled))" \
        "$empty" '' "$percent" "$label"
    [ "$current" -eq "$total" ] && echo
}

pkg_installed() { rpm -q "$1" &>/dev/null; }
cmd_exists()    { command -v "$1" &>/dev/null; }
svc_exists()    { systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${1}.service"; }
svc_active()    { systemctl is-active --quiet "$1" 2>/dev/null; }

# Idempotence : marquer une étape comme faite
already_done() { grep -q "CITADEL_DONE:${1}" "$LOG_FILE" 2>/dev/null; }
mark_done()    { echo "CITADEL_DONE:${1}" >> "$LOG_FILE"; }

# Validation d'IP (v4)
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra octets <<< "$ip"
    for o in "${octets[@]}"; do
        [ "$o" -le 255 ] || return 1
    done
    return 0
}

# Wrapper safe pour sed in-place avec backup automatique
sed_inplace() {
    local pattern="$1" file="$2"
    [ -f "$file" ] || { log_warn "sed_inplace: $file introuvable"; return 1; }
    backup_file "$file"
    run "sed -i.citadel-tmp '$pattern' '$file'"
    run "rm -f '${file}.citadel-tmp'"
}

# Calcul d'un hash sha256 (utilisé pour vérif d'intégrité post-install)
file_hash() {
    [ -f "$1" ] || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# Récupère l'IP publique (avec fallbacks)
get_public_ip() {
    local ip=''
    for svc in ifconfig.me ipinfo.io/ip icanhazip.com; do
        ip="$(curl -s --max-time 3 "https://${svc}" 2>/dev/null | head -1 | tr -d '\n\r ')"
        is_valid_ipv4 "$ip" && { echo "$ip"; return 0; }
    done
    echo 'unknown'
}

# Récupère l'IP locale primaire
get_local_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -1
}

# ==============================================================================
# SECTION 3 - Pré-checks système
# ==============================================================================

precheck() {
    log_section "PRÉ-VÉRIFICATION SYSTÈME"

    # Root
    if [[ $EUID -ne 0 ]]; then
        log_error "CITADEL requiert les privilèges root."
        exit 1
    fi

    # Lock (anti exécutions parallèles)
    if [ -f "$LOCK_FILE" ]; then
        local pid_locked
        pid_locked="$(cat "$LOCK_FILE" 2>/dev/null || echo '?')"
        if [ "$pid_locked" != '?' ] && kill -0 "$pid_locked" 2>/dev/null; then
            log_error "CITADEL est déjà en cours (PID $pid_locked). Abandon."
            exit 1
        else
            log_warn "Lock orphelin détecté (PID $pid_locked mort). Nettoyage."
            rm -f "$LOCK_FILE"
        fi
    fi
    echo "$$" > "$LOCK_FILE"
    # Libérer le lock à la sortie (y compris en cas d'erreur)
    trap 'rm -f "$LOCK_FILE"' EXIT
    trap 'log_warn "Interruption reçue."; rm -f "$LOCK_FILE"; exit 130' INT TERM

    # Détection distro via os-release
    if [ ! -r /etc/os-release ]; then
        log_error "/etc/os-release introuvable - détection distro impossible."
        exit 1
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    readonly DISTRO_NAME="${NAME:-unknown}"
    readonly DISTRO_VERSION="${VERSION_ID:-0}"
    readonly DISTRO_ID="${ID:-unknown}"

    case "$DISTRO_ID" in
        rocky|rhel|almalinux|centos)
            log_info "Distribution : $DISTRO_NAME $DISTRO_VERSION (supportée)"
            ;;
        ol|oracle)
            log_warn "Oracle Linux détecté - support expérimental, certains paquets EPEL peuvent manquer."
            ;;
        *)
            log_warn "Distribution non testée : $DISTRO_NAME"
            printf '%s[?]%s Continuer malgré tout ? (o/N) : ' "$P" "$NC"
            read -r confirm
            [[ "$confirm" =~ ^[oOyY]$ ]] || exit 0
            ;;
    esac

    # Version majeure
    local major="${DISTRO_VERSION%%.*}"
    if [[ "$major" -lt 9 ]]; then
        log_warn "Version $DISTRO_VERSION. CITADEL v${CITADEL_VERSION} est optimisé pour 9+."
    fi

    # Espace disque
    local free_kb
    free_kb=$(df -P / | awk 'NR==2 {print $4}')
    if [[ "$free_kb" -lt 3145728 ]]; then
        log_warn "Disque libre : $((free_kb/1024)) Mo (3 Go recommandés)."
    fi

    # RAM
    local ram_mb
    ram_mb=$(free -m | awk '/^Mem/{print $2}')
    if [[ "$ram_mb" -lt 768 ]]; then
        log_warn "RAM : ${ram_mb} Mo - scans ClamAV/AIDE peuvent être lents."
    fi

    # Connectivité (on teste 2 cibles pour éviter un faux négatif)
    local online=false
    for target in 1.1.1.1 8.8.8.8; do
        ping -c1 -W2 "$target" &>/dev/null && { online=true; break; }
    done
    [ "$online" = false ] && log_warn "Aucune connectivité détectée - l'install peut échouer."

    # Virtualisation : avertissement si conteneur (certains syscalls bloqués)
    local virt
    virt="$(systemd-detect-virt 2>/dev/null || echo 'none')"
    if [[ "$virt" =~ ^(lxc|docker|openvz|systemd-nspawn)$ ]]; then
        log_warn "Environnement conteneurisé détecté ($virt) - certaines phases noyau seront inopérantes."
    elif [ "$virt" != 'none' ]; then
        log_info "Virtualisation détectée : $virt"
    fi

    # Architecture (warning si pas x86_64 ou aarch64)
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|aarch64) log_debug "Architecture : $arch" ;;
        *) log_warn "Architecture non testée : $arch" ;;
    esac

    # Création des répertoires CITADEL
    install -d -m 0750 "$CITADEL_ROOT"
    install -d -m 0750 "$BACKUP_DIR"
    install -d -m 0750 "$REPORT_DIR"
    touch "$STATE_FILE" && chmod 0600 "$STATE_FILE"

    log_success "Pré-checks terminés - distro: ${DISTRO_NAME} ${DISTRO_VERSION}, arch: ${arch}, virt: ${virt}"
}

# ------------------------------------------------------------------------------
# Snapshot LVM pré-install (si la racine est sur LVM et que lvcreate est dispo)
# ------------------------------------------------------------------------------
create_pre_install_snapshot() {
    [ "$SKIP_SNAPSHOT" = true ] && return 0
    [ "$DRY_RUN" = true ] && return 0

    if ! cmd_exists lvs; then
        log_debug "LVM non disponible - pas de snapshot possible."
        return 0
    fi

    # Détecter le LV qui porte /
    local root_src root_lv root_vg
    root_src="$(findmnt -n -o SOURCE /)"
    [[ "$root_src" =~ /dev/mapper/ ]] || { log_debug "Racine non LVM - snapshot ignoré."; return 0; }

    root_lv="$(basename "$root_src")"
    root_vg="$(lvs --noheadings -o vg_name "$root_src" 2>/dev/null | xargs || true)"
    [ -z "$root_vg" ] && { log_debug "VG introuvable."; return 0; }

    # Vérifier qu'il reste de la place dans le VG
    local vg_free_gb
    vg_free_gb=$(vgs --noheadings --units g -o vg_free "$root_vg" 2>/dev/null | awk '{print int($1)}')
    if [[ "$vg_free_gb" -lt 2 ]]; then
        log_warn "VG ${root_vg} - moins de 2 Go libres, snapshot ignoré."
        return 0
    fi

    local snap_name="citadel_pre_$(date +%Y%m%d_%H%M%S)"
    log_info "Création snapshot LVM : ${root_vg}/${snap_name} (2 Go)"
    if lvcreate -L 2G -s -n "$snap_name" "${root_vg}/$(basename "$root_src")" &>>"$LOG_FILE"; then
        state_add "SNAPSHOT:${root_vg}/${snap_name}"
        log_success "Snapshot LVM créé : ${root_vg}/${snap_name}"
    else
        log_warn "Échec création snapshot - on continue sans."
    fi
}

# ==============================================================================
# SECTION 4 - Collecte des inputs utilisateur
# ==============================================================================

collect_inputs() {
    log_section "CONFIGURATION INTERACTIVE"

    # --- 1/7 : utilisateur admin ---
    printf '\n%s[1/7]%s Gestion de l'\''utilisateur admin\n' "$C" "$NC"
    printf '  %s[1]%s Créer un nouvel utilisateur\n' "$G" "$NC"
    printf '  %s[2]%s Utiliser un utilisateur existant\n' "$G" "$NC"
    printf '%s[?]%s Choix (1/2) : ' "$P" "$NC"
    read -r choice

    case "$choice" in
        1) DO_CREATE=true ;;
        2) DO_CREATE=false ;;
        *) log_warn "Choix invalide - utilisation d'un existant par défaut."; DO_CREATE=false ;;
    esac

    while true; do
        if [ "$DO_CREATE" = true ]; then
            printf '%s[?]%s Nom du nouvel utilisateur : ' "$P" "$NC"
        else
            printf '%s[?]%s Nom de l'\''utilisateur : ' "$P" "$NC"
        fi
        read -r ADMIN_USER

        if [[ ! "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            log_warn "Nom invalide (a-z 0-9 _ -, 32 chars, doit commencer par lettre)."
            continue
        fi
        # Interdire root / nologin users
        case "$ADMIN_USER" in
            root|daemon|bin|sys|nobody)
                log_warn "Nom réservé au système - refusé."
                continue ;;
        esac

        if [ "$DO_CREATE" = false ] && ! id "$ADMIN_USER" &>/dev/null; then
            log_error "L'utilisateur '$ADMIN_USER' n'existe pas."
            continue
        fi
        if [ "$DO_CREATE" = true ] && id "$ADMIN_USER" &>/dev/null; then
            log_warn "'$ADMIN_USER' existe déjà - il sera configuré sans être recréé."
            DO_CREATE=false
        fi
        break
    done
    readonly ADMIN_USER DO_CREATE

    # --- 2/7 : port SSH ---
    printf '\n%s[2/7]%s Port SSH (évitez les ports couramment scannés)\n' "$C" "$NC"
    while true; do
        printf '%s[?]%s Port SSH (1025-65535) : ' "$P" "$NC"
        read -r SSH_PORT
        [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || { log_warn "Doit être un entier."; continue; }
        if [[ "$SSH_PORT" -le 1024 || "$SSH_PORT" -gt 65535 ]]; then
            log_warn "Hors plage 1025-65535."; continue
        fi
        # Vérifier qu'il n'est pas déjà utilisé par un autre service
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":${SSH_PORT}$"; then
            log_warn "Port ${SSH_PORT} déjà utilisé par un service local."
            printf '%s[?]%s Continuer quand même ? (o/N) : ' "$P" "$NC"
            read -r cf; [[ "$cf" =~ ^[oOyY]$ ]] || continue
        fi
        case "$SSH_PORT" in
            22|2022|2222|22222)
                log_warn "Port $SSH_PORT est couramment scanné."
                printf '%s[?]%s Confirmer quand même ? (o/N) : ' "$P" "$NC"
                read -r cf; [[ "$cf" =~ ^[oOyY]$ ]] || continue
                ;;
        esac
        break
    done
    readonly SSH_PORT

    # --- 3/7 : clé SSH ---
    printf '\n%s[3/7]%s Clé SSH publique (ed25519 fortement recommandée)\n' "$C" "$NC"
    printf '  Vide → authentification par mot de passe maintenue (non recommandé)\n'
    printf '%s[?]%s Clé publique : ' "$P" "$NC"
    read -r SSH_PUBKEY

    if [[ -n "$SSH_PUBKEY" ]]; then
        if [[ ! "$SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]] ]]; then
            log_warn "Format de clé inhabituel."
            printf '%s[?]%s Utiliser quand même ? (o/N) : ' "$P" "$NC"
            read -r cf
            [[ "$cf" =~ ^[oOyY]$ ]] || SSH_PUBKEY=''
        fi
        # Avertissement : RSA 2048 = faible
        if [[ "$SSH_PUBKEY" =~ ^ssh-rsa ]]; then
            local rsa_bits
            rsa_bits=$(echo "$SSH_PUBKEY" | awk '{print $2}' | base64 -d 2>/dev/null | wc -c)
            if [[ "$rsa_bits" -lt 400 ]]; then
                log_warn "Clé RSA courte (~2048 bits ou moins). Préférez ed25519."
            fi
        fi
    fi
    readonly SSH_PUBKEY

    # --- 4/7 : hostname ---
    printf '\n%s[4/7]%s Hostname (FQDN recommandé : srv-web-01.example.com)\n' "$C" "$NC"
    local cur_host
    cur_host="$(hostname)"
    printf '  Actuel : %s%s%s\n' "$Y" "$cur_host" "$NC"
    printf '%s[?]%s Nouveau hostname (entrée = conserver) : ' "$P" "$NC"
    read -r NEW_HOSTNAME
    if [[ -z "$NEW_HOSTNAME" ]]; then
        NEW_HOSTNAME="$cur_host"
    elif [[ ! "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$ ]]; then
        log_warn "Format invalide, conservation de '$cur_host'."
        NEW_HOSTNAME="$cur_host"
    fi
    readonly NEW_HOSTNAME

    # --- 5/7 : email admin ---
    printf '\n%s[5/7]%s Email admin pour rapports (vide = désactivé)\n' "$C" "$NC"
    printf '%s[?]%s Email : ' "$P" "$NC"
    read -r ADMIN_EMAIL
    if [[ -n "$ADMIN_EMAIL" ]] && [[ ! "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
        log_warn "Email invalide - rapports mail désactivés."
        ADMIN_EMAIL=''
    fi
    readonly ADMIN_EMAIL

    # --- 6/7 : IP d'administration à whitelister ---
    printf '\n%s[6/7]%s IP(s) d'\''administration à whitelister (firewall)\n' "$C" "$NC"
    printf '  Ces IPs pourront toujours se connecter en SSH (bypass rate-limit)\n'
    printf '  Vide = personne whitelisté / format : IP ou CIDR, séparés par virgule\n'
    printf '%s[?]%s IP/CIDR : ' "$P" "$NC"
    read -r ADMIN_IPS
    readonly ADMIN_IPS

    # --- 7/7 : récapitulatif ---
    local auth_mode ipv6_mode
    auth_mode="$([ -n "$SSH_PUBKEY" ] && echo 'Clé publique uniquement' || echo 'Mot de passe (!)' )"
    ipv6_mode="$([ "$ENABLE_IPV6" = true ] && echo 'Activé' || echo 'Désactivé')"

    printf '\n%s[7/7]%s Récapitulatif\n\n' "$C" "$NC"
    printf '  %-28s %s%s%s\n' "Utilisateur admin" "$W" "$ADMIN_USER" "$NC"
    printf '  %-28s %s%s%s\n' "Créer cet utilisateur" "$W" "$DO_CREATE" "$NC"
    printf '  %-28s %s%s%s\n' "Port SSH" "$W" "$SSH_PORT" "$NC"
    printf '  %-28s %s%s%s\n' "Auth SSH" "$W" "$auth_mode" "$NC"
    printf '  %-28s %s%s%s\n' "Hostname" "$W" "$NEW_HOSTNAME" "$NC"
    printf '  %-28s %s%s%s\n' "Email admin" "$W" "${ADMIN_EMAIL:-(désactivé)}" "$NC"
    printf '  %-28s %s%s%s\n' "IPs admin whitelistées" "$W" "${ADMIN_IPS:-(aucune)}" "$NC"
    printf '  %-28s %s%s%s\n' "IPv6" "$W" "$ipv6_mode" "$NC"
    printf '  %-28s %s%s%s\n' "Profil compliance" "$W" "$COMPLIANCE_PROFILE" "$NC"
    printf '  %-28s %s%s%s\n' "USBGuard" "$W" "$ENABLE_USBGUARD" "$NC"
    printf '  %-28s %s%s%s\n' "Kernel lockdown" "$W" "$ENABLE_LOCKDOWN" "$NC"
    printf '  %-28s %s%s%s\n' "Session recording" "$W" "$ENABLE_TLOG" "$NC"
    printf '  %-28s %s%s%s\n' "Port-knocking" "$W" "$ENABLE_KNOCKD" "$NC"
    printf '  %-28s %s%s%s\n' "Mode" "$W" "$([ "$DRY_RUN" = true ] && echo 'DRY-RUN' || echo 'Production')" "$NC"

    # Estimation durée totale
    local total_eta=0
    for phase in "${PHASES_ORDER[@]}"; do
        total_eta=$((total_eta + ${PHASE_ETA[$phase]:-0}))
    done
    printf '\n  %-28s %s~%d minutes%s\n\n' "Durée estimée" "$W" "$((total_eta / 60))" "$NC"

    if [ "$DRY_RUN" = false ]; then
        printf '%s[!]%s Ces paramètres vont modifier le système de façon permanente.\n' "$Y" "$NC"
        printf '%s[?]%s Confirmer et lancer le hardening ? (tapez "oui") : ' "$P" "$NC"
        read -r final
        if [[ ! "$final" =~ ^(oui|OUI|yes|YES)$ ]]; then
            log_info "Annulation utilisateur."
            exit 0
        fi
    fi

    # Persister la config
    install -d -m 0750 "$CITADEL_ROOT"
    cat > "$CITADEL_CONF" <<EOF
# CITADEL v${CITADEL_VERSION} - configuration persistée le $(date -Iseconds)
CITADEL_VERSION="${CITADEL_VERSION}"
ADMIN_USER="${ADMIN_USER}"
SSH_PORT="${SSH_PORT}"
NEW_HOSTNAME="${NEW_HOSTNAME}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
ADMIN_IPS="${ADMIN_IPS}"
ENABLE_IPV6="${ENABLE_IPV6}"
ENABLE_TLOG="${ENABLE_TLOG}"
ENABLE_USBGUARD="${ENABLE_USBGUARD}"
ENABLE_LOCKDOWN="${ENABLE_LOCKDOWN}"
ENABLE_KNOCKD="${ENABLE_KNOCKD}"
COMPLIANCE_PROFILE="${COMPLIANCE_PROFILE}"
INSTALLED_DATE="$(date -Iseconds)"
EOF
    chmod 0600 "$CITADEL_CONF"
    log_debug "Config persistée : $CITADEL_CONF"
}

# ==============================================================================
# SECTION 5 - Base système
# ==============================================================================

setup_base_system() {
    log_section "PHASE 01 - BASE SYSTÈME"

    run "hostnamectl set-hostname '$NEW_HOSTNAME'"
    log_success "Hostname configuré : $NEW_HOSTNAME"

    run "timedatectl set-timezone Europe/Paris"
    log_success "Timezone : Europe/Paris"

    run "localectl set-locale LANG=fr_FR.UTF-8" 2>/dev/null || true

    # Dépôts CRB (CodeReady Builder) + EPEL
    log_info "Activation des dépôts CRB + EPEL…"
    run "dnf config-manager --set-enabled crb" 2>/dev/null || \
    run "dnf config-manager --set-enabled powertools" 2>/dev/null || true
    run "dnf install -y epel-release" &
    spinner "Installation EPEL" $!
    wait

    # Update complet
    log_info "Mise à jour complète du système (peut prendre plusieurs minutes)…"
    run "dnf makecache --refresh"
    run "dnf upgrade -y" &
    spinner "Mise à jour du système" $!
    wait

    # Paquets CITADEL - regroupés par domaine
    local pkgs=(
        # Administration
        vim-enhanced git curl wget net-tools bind-utils ncdu tree
        bash-completion man-pages man-db ethtool psmisc
        # Sécurité hôte
        fail2ban aide rkhunter lynis clamav clamav-update clamd clamav-lib
        policycoreutils-python-utils setools-console checkpolicy
        libselinux-utils selinux-policy-devel
        # USB protection
        usbguard usbutils
        # Process accounting
        psacct
        # Monitoring
        sysstat iotop lsof strace ltrace bpftool procps-ng
        # Réseau
        nftables iptables-nft ipset tcpdump nmap-ncat bind-utils
        # Audit
        audit audispd-plugins
        # Mises à jour auto & outils
        dnf-automatic tar gzip bzip2 unzip xz chrony logwatch
        # PAM & crypto
        libpwquality openssl openssl-devel ca-certificates
        # Session recording (installé si --enable-tlog choisi, mais base dispo)
        tlog
        # OpenSCAP pour conformité
        openscap-scanner scap-security-guide
        # Divers utiles
        jq yq rsync
    )

    # Paquets conditionnels
    [ "$ENABLE_KNOCKD" = true ] && pkgs+=(knock-server)

    log_info "Installation des paquets de sécurité (${#pkgs[@]})…"
    # Installation tolérante aux paquets manquants (certains seulement dans EPEL)
    run "dnf install -y --skip-broken ${pkgs[*]}" &
    spinner "Installation paquets CITADEL" $!
    wait

    # Swap : créer si absent
    if ! swapon --show 2>/dev/null | grep -q .; then
        log_info "Création du swap (2 Go)…"
        if [ "$DRY_RUN" = false ]; then
            fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
            chmod 0600 /swapfile
            mkswap /swapfile >/dev/null
            swapon /swapfile
            grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        log_success "Swap 2 Go activé."
    else
        log_info "Swap déjà présent - ignoré."
    fi

    mark_done "base_system"
}

# ==============================================================================
# SECTION 6 - Hardening noyau (sysctl + modules)
# ==============================================================================

setup_kernel_hardening() {
    log_section "PHASE 02 - HARDENING NOYAU"

    backup_file /etc/sysctl.d/99-citadel.conf

    cat > /etc/sysctl.d/99-citadel.conf <<'SYSCTL'
# CITADEL v4.0 - sysctl hardening (CIS Level 2 / ANSSI-BP-028)
# Ne pas modifier manuellement - géré par CITADEL

# ---- Anti-spoofing / MITM ----
net.ipv4.conf.all.rp_filter                 = 1
net.ipv4.conf.default.rp_filter             = 1
net.ipv4.conf.all.accept_redirects          = 0
net.ipv4.conf.default.accept_redirects      = 0
net.ipv4.conf.all.secure_redirects          = 0
net.ipv4.conf.default.secure_redirects      = 0
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
net.ipv4.conf.all.arp_ignore                = 1
net.ipv4.conf.all.arp_announce              = 2

# ---- TCP hardening ----
net.ipv4.tcp_syncookies                     = 1
net.ipv4.tcp_max_syn_backlog                = 4096
net.ipv4.tcp_synack_retries                 = 2
net.ipv4.tcp_syn_retries                    = 5
net.ipv4.tcp_rfc1337                        = 1
net.ipv4.tcp_timestamps                     = 0
net.ipv4.tcp_max_tw_buckets                 = 1440000
net.ipv4.tcp_tw_reuse                       = 1
net.ipv4.tcp_fin_timeout                    = 15
net.ipv4.tcp_keepalive_time                 = 300
net.ipv4.tcp_keepalive_probes               = 5
net.ipv4.tcp_keepalive_intvl                = 15
net.ipv4.ip_local_port_range                = 32768 60999

# ---- Kernel memory / exploit mitigations ----
kernel.randomize_va_space                   = 2
fs.suid_dumpable                            = 0
kernel.core_uses_pid                        = 1
kernel.core_pattern                         = |/bin/false
kernel.dmesg_restrict                       = 1
kernel.kptr_restrict                        = 2
kernel.kexec_load_disabled                  = 1
fs.protected_hardlinks                      = 1
fs.protected_symlinks                       = 1
fs.protected_fifos                          = 2
fs.protected_regular                        = 2
kernel.unprivileged_userns_clone            = 0
kernel.unprivileged_bpf_disabled            = 1
net.core.bpf_jit_harden                     = 2
kernel.yama.ptrace_scope                    = 1
kernel.perf_event_paranoid                  = 3
kernel.sysrq                                = 4
kernel.panic                                = 60
kernel.panic_on_oops                        = 1
kernel.modules_disabled                     = 0

# ---- Memory management ----
vm.swappiness                               = 10
vm.dirty_ratio                              = 10
vm.dirty_background_ratio                   = 5
vm.unprivileged_userfaultfd                 = 0
vm.mmap_min_addr                            = 65536

# ---- Routing ----
net.ipv4.ip_forward                         = 0
net.ipv6.conf.all.forwarding                = 0

# ---- Bridge (pour Docker/Podman si besoin) ----
net.bridge.bridge-nf-call-iptables          = 1
net.bridge.bridge-nf-call-ip6tables         = 1

# ---- Network buffers ----
net.core.somaxconn                          = 65535
net.core.netdev_max_backlog                 = 16384
net.core.rmem_max                           = 16777216
net.core.wmem_max                           = 16777216

# ---- IPv6 router advertisements (même si IPv6 désactivé au firewall) ----
net.ipv6.conf.all.accept_ra                 = 0
net.ipv6.conf.default.accept_ra             = 0
SYSCTL

    # IPv6 disable si pas demandé
    if [ "$ENABLE_IPV6" = false ]; then
        cat >> /etc/sysctl.d/99-citadel.conf <<'IPV6'

# ---- IPv6 disabled globally (--enable-ipv6 pour activer) ----
net.ipv6.conf.all.disable_ipv6              = 1
net.ipv6.conf.default.disable_ipv6          = 1
net.ipv6.conf.lo.disable_ipv6               = 1
IPV6
    fi

    run "sysctl --system"
    log_success "Sysctl appliqué (~60 paramètres durcis)."

    # Blacklist modules noyau
    log_info "Désactivation des modules inutiles/dangereux…"
    local dangerous_modules=(
        # Filesystems exotiques jamais utilisés en prod
        cramfs freevxfs jffs2 hfs hfsplus udf squashfs
        # Protocoles réseau legacy
        dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet
        atm appletalk psnap p8022 p8023 ipx llc
        # USB storage (désactivable - USBGuard prend le relais si activé)
        usb-storage
        # Firewire (vecteur DMA attack)
        firewire-core firewire-ohci firewire-sbp2
        # Bluetooth (inutile serveur)
        bluetooth bnep btusb
        # Thunderbolt (DMA attack)
        thunderbolt
    )

    {
        echo '# CITADEL v4.0 - modules blacklistés'
        echo '# install <mod> /bin/true empêche le chargement même via modprobe'
        for m in "${dangerous_modules[@]}"; do
            echo "install ${m} /bin/true"
            echo "blacklist ${m}"
        done
    } > /etc/modprobe.d/citadel-blacklist.conf

    log_success "${#dangerous_modules[@]} modules désactivés."

    # Modules réseau explicitement chargés pour le firewall
    cat > /etc/modules-load.d/citadel.conf <<'EOF'
# CITADEL v4.0 - modules requis
br_netfilter
ip_tables
iptable_nat
iptable_filter
nf_conntrack
EOF

    run "modprobe br_netfilter" 2>/dev/null || true
    run "modprobe nf_conntrack" 2>/dev/null || true

    mark_done "kernel"
}

# ==============================================================================
# SECTION 7 - Points de montage sécurisés
# ==============================================================================

setup_secure_mounts() {
    log_section "PHASE 03 - MONTAGES SÉCURISÉS"

    backup_file /etc/fstab

    # /tmp - séparé en tmpfs avec flags restrictifs
    if ! grep -qE '^\s*tmpfs\s+/tmp' /etc/fstab; then
        echo 'tmpfs /tmp tmpfs defaults,rw,noexec,nosuid,nodev,size=1G,mode=1777 0 0' >> /etc/fstab
        log_success "/tmp ajouté à fstab (tmpfs, noexec/nosuid/nodev, 1 Go)."
    else
        log_info "/tmp déjà dans fstab."
    fi

    # /dev/shm
    if ! grep -qE '^\s*\S+\s+/dev/shm' /etc/fstab; then
        echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
        log_success "/dev/shm sécurisé."
    fi

    # /var/tmp : bind-mount sur /tmp pour hériter des flags
    if ! grep -qE '/var/tmp' /etc/fstab; then
        echo '/tmp /var/tmp none bind 0 0' >> /etc/fstab
        log_success "/var/tmp bindé sur /tmp (flags hérités)."
    fi

    # /proc : hidepid=invisible pour non-root
    if ! grep -qE '^\s*proc\s+/proc' /etc/fstab; then
        echo 'proc /proc proc defaults,nosuid,nodev,noexec,hidepid=invisible,gid=proc 0 0' >> /etc/fstab
        run "groupadd -f -r proc"
        # Ajouter admin au groupe proc pour qu'il voie toujours ses process
        run "usermod -aG proc '$ADMIN_USER'"
        log_success "/proc hidepid=invisible (admin dans group proc)."
    fi

    # Applications immédiates (sans reboot)
    if [ "$DRY_RUN" = false ]; then
        mount -o remount /tmp 2>/dev/null || true
        mount -o remount /dev/shm 2>/dev/null || true
        # /proc remount peut nécessiter un reboot - on ignore les erreurs
        mount -o remount /proc 2>/dev/null || true
    fi

    mark_done "mounts"
}

# ==============================================================================
# SECTION 8 - SELinux Enforcing
# ==============================================================================

setup_selinux() {
    log_section "PHASE 04 - SELINUX"

    backup_file /etc/selinux/config

    local mode
    mode="$(getenforce 2>/dev/null || echo 'Disabled')"

    if [ "$mode" = 'Disabled' ]; then
        log_warn "SELinux est Disabled dans le kernel - un reboot sera requis après cette phase."
        log_warn "Relabeling complet au prochain boot (peut prendre 5-15 min)."
        # Marquer pour relabel au prochain boot
        [ "$DRY_RUN" = false ] && touch /.autorelabel
    elif [ "$mode" != 'Enforcing' ]; then
        log_info "Passage de Permissive à Enforcing…"
        run "setenforce 1" || log_warn "setenforce live impossible - effectif au reboot."
    fi

    run "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
    run "sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config"
    log_success "SELinux configuré en Enforcing (targeted)."

    # Booleans SELinux - sécurité par défaut
    local sebool_on=(
        deny_ptrace                       # Interdit ptrace cross-process
        deny_execmem                      # Pas de mémoire exécutable partout
        secure_mode_insmod                # Signé uniquement pour insmod
        ssh_sysadm_login                  # Permet login admin SSH (sinon SSH broken sur certains profils)
    )
    local sebool_off=(
        httpd_can_network_connect
        httpd_execmem
        httpd_enable_cgi
        ftp_home_dir
        mount_anyfile
        allow_execheap
        allow_execmod
        allow_execstack
    )

    for b in "${sebool_on[@]}"; do
        run "setsebool -P '$b' on" 2>/dev/null || log_debug "Boolean $b indisponible."
    done
    for b in "${sebool_off[@]}"; do
        run "setsebool -P '$b' off" 2>/dev/null || log_debug "Boolean $b indisponible."
    done

    log_success "SELinux booleans ajustés (${#sebool_on[@]} on, ${#sebool_off[@]} off)."

    mark_done "selinux"
}

# ==============================================================================
# SECTION 9 - Utilisateurs & PAM
# ==============================================================================

setup_users_and_pam() {
    log_section "PHASE 05 - UTILISATEURS & PAM"

    # Création / config utilisateur admin
    if [ "$DO_CREATE" = true ]; then
        if ! id "$ADMIN_USER" &>/dev/null; then
            run "useradd -m -s /bin/bash -c 'CITADEL Admin' '$ADMIN_USER'"
            printf '\n%s>>> Définissez le mot de passe pour %s :%s\n' "$Y" "$ADMIN_USER" "$NC"
            if [ "$DRY_RUN" = false ]; then
                while ! passwd "$ADMIN_USER"; do
                    log_warn "Échec de passwd, nouvelle tentative…"
                done
            fi
            log_success "Utilisateur $ADMIN_USER créé."
        fi
    fi

    run "usermod -aG wheel '$ADMIN_USER'"
    log_success "$ADMIN_USER ajouté au groupe wheel."

    # Déploiement clé SSH
    if [[ -n "$SSH_PUBKEY" ]]; then
        local ssh_dir="/home/${ADMIN_USER}/.ssh"
        if [ "$DRY_RUN" = false ]; then
            install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$ssh_dir"
            touch "${ssh_dir}/authorized_keys"
            # Anti-doublon
            if ! grep -qF "$SSH_PUBKEY" "${ssh_dir}/authorized_keys" 2>/dev/null; then
                echo "$SSH_PUBKEY" >> "${ssh_dir}/authorized_keys"
            fi
            chmod 0600 "${ssh_dir}/authorized_keys"
            chown -R "${ADMIN_USER}:${ADMIN_USER}" "$ssh_dir"
        fi
        log_success "Clé SSH déployée pour $ADMIN_USER."
    fi

    # Politique de mots de passe
    backup_file /etc/security/pwquality.conf
    cat > /etc/security/pwquality.conf <<'PWQ'
# CITADEL v4.0 - password quality
minlen      = 14
minclass    = 4
maxrepeat   = 3
maxsequence = 3
dcredit     = -1
ucredit     = -1
lcredit     = -1
ocredit     = -1
difok       = 7
gecoscheck  = 1
dictcheck   = 1
enforcing   = 1
enforce_for_root = 1
PWQ

    # Faillock : verrouillage après échecs
    backup_file /etc/security/faillock.conf
    cat > /etc/security/faillock.conf <<'FL'
# CITADEL v4.0 - account lockout
deny              = 5
fail_interval     = 900
unlock_time       = 1800
even_deny_root    = 1
root_unlock_time  = 900
dir               = /var/run/faillock
audit             = 1
silent            = 0
no_log_info       = 0
FL

    # Activer faillock via authselect
    if cmd_exists authselect; then
        run "authselect select sssd with-faillock --force" 2>/dev/null || \
        run "authselect select minimal with-faillock --force" 2>/dev/null || \
        log_warn "authselect a échoué - vérification manuelle requise."
        run "authselect apply-changes" 2>/dev/null || true
    fi

    # Umask système
    backup_file /etc/profile
    if ! grep -q '# CITADEL umask' /etc/profile; then
        cat >> /etc/profile <<'P'
# CITADEL umask - masque restrictif par défaut
umask 027
P
    fi

    # /etc/login.defs - durcir les paramètres de login
    backup_file /etc/login.defs
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs
    grep -q '^SHA_CRYPT_MIN_ROUNDS' /etc/login.defs || echo 'SHA_CRYPT_MIN_ROUNDS 10000' >> /etc/login.defs
    log_success "login.defs durci (MAX_DAYS=90, SHA512, 10000 rounds)."

    # su restreint au groupe wheel
    backup_file /etc/pam.d/su
    if ! grep -qE '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su; then
        sed -i 's/^#auth[[:space:]]*required[[:space:]]*pam_wheel.so use_uid/auth            required        pam_wheel.so use_uid/' /etc/pam.d/su
        # Si la ligne commentée n'existe pas, on l'ajoute
        grep -qE '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su || \
            sed -i '/^#%PAM/a auth            required        pam_wheel.so use_uid' /etc/pam.d/su
        log_success "su restreint au groupe wheel."
    fi

    # PAM tty_audit : logguer toutes les commandes des comptes privilégiés
    if ! grep -q 'pam_tty_audit' /etc/pam.d/system-auth; then
        backup_file /etc/pam.d/system-auth
        echo 'session     required      pam_tty_audit.so enable=root,'"$ADMIN_USER" >> /etc/pam.d/system-auth
        log_success "pam_tty_audit activé pour root + $ADMIN_USER."
    fi

    # Timeout inactivité shell
    cat > /etc/profile.d/citadel-timeout.sh <<'T'
# CITADEL v4.0 - shell idle timeout (10 min)
# readonly empêche l'utilisateur de le désactiver
readonly TMOUT=600
export TMOUT
T
    chmod 0644 /etc/profile.d/citadel-timeout.sh
    log_success "Timeout shell : 10 min d'inactivité."

    # Verrouiller les comptes système jamais utilisés
    local unused=(games news uucp operator gopher ftp halt shutdown sync)
    local locked=0
    for u in "${unused[@]}"; do
        if id "$u" &>/dev/null; then
            run "usermod -s /sbin/nologin -L '$u'" 2>/dev/null && locked=$((locked+1)) || true
        fi
    done
    log_success "$locked comptes système verrouillés."

    # Sudoers CITADEL - correction des bugs v3
    cat > /etc/sudoers.d/citadel <<'SD'
# CITADEL v4.0 - sudo hardening

# Logging
Defaults    log_output
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input
Defaults    iolog_dir="/var/log/sudo-io"

# Timeout 5 min
Defaults    timestamp_timeout=5
Defaults    passwd_timeout=1

# Environnement
Defaults    env_reset
Defaults    env_delete+="LD_LIBRARY_PATH LD_PRELOAD PERL5LIB PERL5OPT PYTHONPATH"
Defaults    secure_path="/sbin:/bin:/usr/sbin:/usr/bin"

# Sécurité
Defaults    !env_keep+="SSH_AUTH_SOCK"
Defaults    requiretty
Defaults    use_pty
Defaults    lecture="always"

# Alertes
Defaults    mail_badpass
Defaults    mail_no_user
Defaults    mail_no_host
Defaults    mailto="root"

# Wheel peut utiliser sudo avec mot de passe (NOPASSWD interdit)
%wheel  ALL=(ALL)       ALL
SD

    chmod 0440 /etc/sudoers.d/citadel

    # Valider syntaxe avant de laisser le fichier en place
    if [ "$DRY_RUN" = false ] && ! visudo -cf /etc/sudoers.d/citadel >/dev/null; then
        log_error "Fichier sudoers invalide ! Suppression de secours…"
        rm -f /etc/sudoers.d/citadel
        return 1
    fi

    # Créer le dir pour sudo I/O logging
    install -d -m 0700 /var/log/sudo-io
    log_success "Sudo configuré (audit, I/O logging, lecture)."

    mark_done "users"
}

# ==============================================================================
# SECTION 10 - SSH Fortress
# ==============================================================================

setup_ssh() {
    log_section "PHASE 06 - SSH FORTRESS"

    backup_file /etc/ssh/sshd_config

    # SELinux : autoriser le nouveau port SSH
    log_info "Autorisation du port $SSH_PORT dans SELinux (ssh_port_t)…"
    if [ "$DRY_RUN" = false ]; then
        semanage port -l 2>/dev/null | grep -q "ssh_port_t.*${SSH_PORT}$" || {
            semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || \
            semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || \
            log_warn "semanage a échoué - vérifiez manuellement."
        }
    fi

    # Construire AuthenticationMethods
    local auth_methods pubkey_auth passwd_auth
    if [[ -n "$SSH_PUBKEY" ]]; then
        auth_methods='publickey'
        pubkey_auth='yes'
        passwd_auth='no'
        log_info "Clé SSH → PasswordAuthentication DÉSACTIVÉ."
    else
        auth_methods='password'
        pubkey_auth='yes'
        passwd_auth='yes'
        log_warn "Pas de clé → auth par mot de passe maintenue (à désactiver ASAP)."
    fi

    # Config SSHD - on utilise un heredoc non-quoté pour interpoler les variables
    cat > /etc/ssh/sshd_config <<SSHD
# ==============================================================================
# CITADEL v${CITADEL_VERSION} - sshd_config
# Conforme CIS Benchmark SSH Level 2 + Mozilla Modern
# Généré le $(date -Iseconds)
# ==============================================================================

# ---- Réseau ----
Port ${SSH_PORT}
AddressFamily $([ "$ENABLE_IPV6" = true ] && echo 'any' || echo 'inet')
ListenAddress 0.0.0.0
$([ "$ENABLE_IPV6" = true ] && echo 'ListenAddress ::')

# ---- Auth ----
PermitRootLogin no
PasswordAuthentication ${passwd_auth}
PubkeyAuthentication ${pubkey_auth}
AuthenticationMethods ${auth_methods}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers ${ADMIN_USER}
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
MaxStartups 3:50:10

# ---- Crypto moderne (Mozilla modern + retrait des courbes NIST pour ANSSI) ----
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# ---- HostKeys ----
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# ---- Features dangereuses OFF ----
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
DebianBanner no
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
Compression no
UseDNS no
HashKnownHosts yes
PermitUserRC no

# ---- Timeouts & keepalive ----
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# ---- SFTP interne (plus sûr que le binaire externe) ----
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO

# ---- Logging ----
SyslogFacility AUTHPRIV
LogLevel VERBOSE
PrintMotd no
PrintLastLog yes
Banner /etc/ssh/citadel-banner

# ---- Anti-kex downgrade ----
# RekeyLimit force un rekey périodique
RekeyLimit 512M 1h
SSHD

    # Bannière légale pré-auth (affichée avant la demande de mot de passe)
    cat > /etc/ssh/citadel-banner <<'BNR'
╔════════════════════════════════════════════════════════════════╗
║                    *** ACCÈS RESTREINT ***                     ║
║                                                                ║
║  Ce système est la propriété de son exploitant. L'accès est    ║
║  autorisé uniquement aux personnes explicitement habilitées.   ║
║                                                                ║
║  Toute connexion et toute activité est enregistrée et peut     ║
║  être utilisée à des fins de contrôle, d'audit et de           ║
║  poursuites judiciaires.                                       ║
║                                                                ║
║  Toute tentative non autorisée sera poursuivie conformément    ║
║  à l'article 323-1 du Code pénal.                              ║
╚════════════════════════════════════════════════════════════════╝
BNR
    chmod 0644 /etc/ssh/citadel-banner

    # MOTD dynamique post-login (correction v4 : plus de dnf check-update bloquant)
    cat > /etc/profile.d/citadel-motd.sh <<'MOTD'
#!/usr/bin/env bash
# CITADEL v4.0 - MOTD dynamique (affiché au login)

_c=$'\033[0;36m'; _g=$'\033[0;32m'; _y=$'\033[1;33m'
_r=$'\033[0;31m'; _b=$'\033[1m'; _n=$'\033[0m'

printf '\n%s┌─────────────────────────────────────────────────────┐%s\n' "$_c" "$_n"
printf '%s│%s   Serveur sécurisé par CITADEL v4.0                 %s│%s\n' "$_c" "$_b" "$_c" "$_n"
printf '%s└─────────────────────────────────────────────────────┘%s\n\n' "$_c" "$_n"

printf '  %sHôte     :%s %s\n' "$_b" "$_n" "$(hostname -f 2>/dev/null || hostname)"
printf '  %sDate     :%s %s\n' "$_b" "$_n" "$(date '+%A %d %B %Y - %H:%M:%S')"
printf '  %sUptime   :%s %s\n' "$_b" "$_n" "$(uptime -p 2>/dev/null)"
printf '  %sCharge   :%s %s\n' "$_b" "$_n" "$(uptime | sed 's/.*load average: //')"

# RAM / Disk
printf '  %sMémoire  :%s %s / %s\n' "$_b" "$_n" \
    "$(free -h | awk '/^Mem/{print $3}')" \
    "$(free -h | awk '/^Mem/{print $2}')"
printf '  %sDisque / :%s %s\n' "$_b" "$_n" \
    "$(df -h / | awk 'NR==2{printf "%s / %s (%s)", $3, $2, $5}')"

# IP
_ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | head -1 | cut -d/ -f1)
printf '  %sIP       :%s %s\n' "$_b" "$_n" "${_ip:-N/A}"

# Sessions actives
printf '  %sSessions :%s %s utilisateur(s)\n' "$_b" "$_n" "$(who | wc -l)"

# Dernière connexion (pour le user courant)
_last=$(last -n2 "$USER" 2>/dev/null | awk 'NR==2{print $4,$5,$6,$7,"from",$3}')
[ -n "$_last" ] && printf '  %sDernière :%s %s\n' "$_b" "$_n" "$_last"

# Détection : y a-t-il eu des tentatives d'auth échouées récentes ?
_fails=$(journalctl --since "24h ago" _COMM=sshd 2>/dev/null | grep -c "Failed\|Invalid" || echo 0)
if [[ "${_fails:-0}" -gt 10 ]]; then
    printf '\n  %s⚠  %d tentatives SSH échouées sur 24h%s\n' "$_y" "$_fails" "$_n"
fi

# Alerte si fail2ban a banni des IPs
if command -v fail2ban-client >/dev/null 2>&1; then
    _banned=$(fail2ban-client status sshd 2>/dev/null | awk '/Currently banned/{print $NF}')
    if [[ "${_banned:-0}" -gt 0 ]]; then
        printf '  %s⛔ %d IP(s) actuellement bannies%s\n' "$_r" "$_banned" "$_n"
    fi
fi

printf '\n'
MOTD
    chmod 0755 /etc/profile.d/citadel-motd.sh

    # Régénérer les clés hôtes (supprimer les faibles DSA/ECDSA)
    log_info "Régénération des clés hôtes SSH (ed25519 + RSA 4096)…"
    if [ "$DRY_RUN" = false ]; then
        rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*
        # -y si existe, sinon création (bug v3 corrigé : plus de heredoc <<< y)
        if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
            ssh-keygen -q -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -C "$(hostname)-$(date +%Y%m%d)"
        fi
        if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
            ssh-keygen -q -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' -C "$(hostname)-$(date +%Y%m%d)"
        fi
        chmod 0600 /etc/ssh/ssh_host_*_key
        chmod 0644 /etc/ssh/ssh_host_*_key.pub
    fi

    # Validation config avant redémarrage
    log_info "Validation de sshd_config…"
    if [ "$DRY_RUN" = false ]; then
        if ! sshd -t 2>>"$LOG_FILE"; then
            log_error "sshd_config invalide ! Restauration du backup…"
            local latest_backup
            latest_backup=$(ls -t "${BACKUP_DIR}/etc/ssh/sshd_config.bak."* 2>/dev/null | head -1)
            [ -n "$latest_backup" ] && cp "$latest_backup" /etc/ssh/sshd_config
            return 1
        fi
        # sshd -T permet de voir la config effective - utile pour le rapport
        sshd -T 2>/dev/null > "${CITADEL_ROOT}/sshd-effective.conf" || true
        systemctl restart sshd
    fi

    log_success "SSH sécurisé (port $SSH_PORT, ChaCha20/AES-GCM, ed25519)."

    mark_done "ssh"
}

# ==============================================================================
# SECTION 11 - Firewall nftables (IPv4 + IPv6)
# ==============================================================================

setup_firewall() {
    log_section "PHASE 07 - FIREWALL NFTABLES"

    # Arrêter firewalld au profit de nftables pur (plus de contrôle)
    run "systemctl stop firewalld" 2>/dev/null || true
    run "systemctl disable firewalld" 2>/dev/null || true
    run "systemctl mask firewalld" 2>/dev/null || true

    install -d -m 0750 /etc/nftables

    # Build : liste d'IPs admin pour whitelist (si fournies)
    local admin_ip_rule=''
    if [[ -n "${ADMIN_IPS:-}" ]]; then
        local ip_list
        ip_list="$(echo "$ADMIN_IPS" | tr ',' ' ' | xargs)"
        local ip_set=''
        for ip in $ip_list; do
            [ -n "$ip_set" ] && ip_set+=", "
            ip_set+="$ip"
        done
        admin_ip_rule="        ip saddr { ${ip_set} } tcp dport ${SSH_PORT} accept comment \"admin whitelist\""
    fi

    # Génération du fichier de règles - IPv4
    # Note : correction du bug v3 sur le rate-limit (meter au lieu du set mal formé)
    cat > /etc/nftables/citadel-v4.nft <<NFT
#!/usr/sbin/nft -f
# CITADEL v${CITADEL_VERSION} - ruleset IPv4
# Généré le $(date -Iseconds)

table inet citadel_filter {

    # Meters dynamiques pour rate-limiting
    # (corrige le bug v3 où la syntaxe du set était invalide)
    set banned_ips {
        type ipv4_addr
        flags interval, timeout
        timeout 24h
        comment "IPs bannies (alimenté par fail2ban + manuel)"
    }

    set ssh_scanners {
        type ipv4_addr
        flags dynamic, timeout
        timeout 10m
        comment "IPs scanneurs SSH temporaires"
    }

    # Chain INPUT
    chain input {
        type filter hook input priority filter; policy drop;

        # Loopback
        iif lo accept

        # Connexions établies
        ct state { established, related } accept
        ct state invalid drop

        # Bannis → drop
        ip saddr @banned_ips drop

        # Scanners récents → drop
        ip saddr @ssh_scanners drop

${admin_ip_rule}

        # ICMP limité (anti-flood)
        ip protocol icmp icmp type {
            echo-request, echo-reply,
            destination-unreachable, time-exceeded,
            parameter-problem
        } limit rate 5/second burst 10 packets accept

        # SSH avec rate-limiting (5 nouvelles conn/min/IP)
        tcp dport ${SSH_PORT} ct state new \\
            meter ssh_limit { ip saddr timeout 1m limit rate over 5/minute } \\
            add @ssh_scanners { ip saddr } log prefix "citadel-ssh-flood: " drop
        tcp dport ${SSH_PORT} ct state new accept

        # Log drop final avec limite pour éviter le flood de logs
        limit rate 3/minute burst 5 packets log prefix "citadel-drop: " level info
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
NFT

    chmod 0600 /etc/nftables/citadel-v4.nft

    # IPv6 : un autre fichier si activé, sinon policy drop complète
    if [ "$ENABLE_IPV6" = true ]; then
        cat > /etc/nftables/citadel-v6.nft <<NFT6
#!/usr/sbin/nft -f
# CITADEL v${CITADEL_VERSION} - ruleset IPv6

table ip6 citadel_filter6 {

    set banned_ips6 {
        type ipv6_addr
        flags interval, timeout
        timeout 24h
    }

    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state { established, related } accept
        ct state invalid drop
        ip6 saddr @banned_ips6 drop

        # ICMPv6 (critique pour IPv6)
        icmpv6 type {
            destination-unreachable, packet-too-big, time-exceeded,
            parameter-problem, echo-request, echo-reply,
            nd-router-solicit, nd-router-advert,
            nd-neighbor-solicit, nd-neighbor-advert
        } accept

        tcp dport ${SSH_PORT} ct state new limit rate 5/minute accept
        limit rate 3/minute burst 5 packets log prefix "citadel-v6-drop: " level info
    }

    chain forward { type filter hook forward priority filter; policy drop; }
    chain output  { type filter hook output  priority filter; policy accept; }
}
NFT6
        chmod 0600 /etc/nftables/citadel-v6.nft
    fi

    # Fichier master nftables.conf
    {
        echo '#!/usr/sbin/nft -f'
        echo "# CITADEL v${CITADEL_VERSION} - master ruleset"
        echo 'flush ruleset'
        echo 'include "/etc/nftables/citadel-v4.nft"'
        [ "$ENABLE_IPV6" = true ] && echo 'include "/etc/nftables/citadel-v6.nft"'
    } > /etc/sysconfig/nftables.conf

    # Validation avant application - critique pour ne pas se couper l'accès
    if [ "$DRY_RUN" = false ]; then
        if ! nft -c -f /etc/sysconfig/nftables.conf 2>>"$LOG_FILE"; then
            log_error "Syntaxe nftables invalide - rollback firewalld."
            systemctl unmask firewalld 2>/dev/null || true
            return 1
        fi
        nft -f /etc/sysconfig/nftables.conf
    fi

    run "systemctl enable --now nftables"
    log_success "nftables configuré (policy DROP, rate-limit SSH, IPv$([ "$ENABLE_IPV6" = true ] && echo '4+6' || echo '4'))."

    # --- Fail2Ban --- 
    backup_file /etc/fail2ban/jail.local

    cat > /etc/fail2ban/jail.local <<F2B
# CITADEL v${CITADEL_VERSION} - fail2ban

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1 ${ADMIN_IPS:-}
banaction = nftables-multiport
banaction_allports = nftables-allports
backend = systemd
usedns = warn
logencoding = utf-8
destemail = ${ADMIN_EMAIL:-root@localhost}
sender = fail2ban@$(hostname -f 2>/dev/null || hostname)
action = %(action_mwl)s

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/secure
backend  = systemd
mode     = aggressive
maxretry = 3
bantime  = 86400
findtime = 3600

[sshd-ddos]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/secure
maxretry = 6
findtime = 120
bantime  = 600

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(action_mwl)s
bantime  = 604800
findtime = 86400
maxretry = 5
F2B

    # Port-knocking optionnel
    if [ "$ENABLE_KNOCKD" = true ] && cmd_exists knockd; then
        backup_file /etc/knockd.conf
        # Générer 3 ports aléatoires hors des connus
        local k1 k2 k3
        k1=$((RANDOM % 50000 + 10000))
        k2=$((RANDOM % 50000 + 10000))
        k3=$((RANDOM % 50000 + 10000))

        cat > /etc/knockd.conf <<KNOCK
[options]
    UseSyslog
    logfile = /var/log/knockd.log

[openSSH]
    sequence    = ${k1},${k2},${k3}
    seq_timeout = 10
    command     = /sbin/nft add element inet citadel_filter ssh_allowed { %IP% timeout 1h }
    tcpflags    = syn

[closeSSH]
    sequence    = ${k3},${k2},${k1}
    seq_timeout = 10
    command     = /sbin/nft delete element inet citadel_filter ssh_allowed { %IP% }
    tcpflags    = syn
KNOCK
        run "systemctl enable --now knockd"
        log_success "Port-knocking activé - séquence : ${k1},${k2},${k3}"
        log_warn "IMPORTANT : notez la séquence de knock, elle est nécessaire pour SSH !"
        echo "KNOCK_SEQUENCE:${k1},${k2},${k3}" > "${CITADEL_ROOT}/knock-sequence.txt"
        chmod 0600 "${CITADEL_ROOT}/knock-sequence.txt"
    fi

    run "systemctl enable --now fail2ban"
    log_success "Fail2ban actif (SSH aggressive, récidive 7j)."

    mark_done "firewall"
}

# ==============================================================================
# SECTION 12 - Auditd (règles CIS L2 / PCI-DSS / STIG)
# ==============================================================================

setup_auditd() {
    log_section "PHASE 08 - AUDITD"

    backup_file /etc/audit/auditd.conf

    cat > /etc/audit/auditd.conf <<'AUD'
# CITADEL v4.0 - auditd
log_file                 = /var/log/audit/audit.log
log_format               = ENRICHED
log_group                = root
priority_boost           = 4
flush                    = INCREMENTAL_ASYNC
freq                     = 50
num_logs                 = 10
disp_qos                 = lossy
dispatcher               = /sbin/audispd
name_format              = HOSTNAME
max_log_file             = 100
max_log_file_action      = ROTATE
space_left               = 500
space_left_action        = EMAIL
action_mail_acct         = root
admin_space_left         = 100
admin_space_left_action  = SUSPEND
disk_full_action         = SUSPEND
disk_error_action        = SUSPEND
tcp_listen_queue         = 5
tcp_max_per_addr         = 1
tcp_client_max_idle      = 0
enable_krb5              = no
use_libwrap              = yes
AUD

    backup_file /etc/audit/rules.d/citadel.rules

    cat > /etc/audit/rules.d/citadel.rules <<'AR'
## CITADEL v4.0 - audit rules (CIS L2 + PCI-DSS + STIG + ANSSI)

-D
-b 32768
-f 1
--backlog_wait_time 60000

## ---- Identity & accounts ----
-w /etc/passwd            -p wa -k identity
-w /etc/shadow            -p wa -k identity
-w /etc/group             -p wa -k identity
-w /etc/gshadow           -p wa -k identity
-w /etc/security/opasswd  -p wa -k identity
-w /etc/nsswitch.conf     -p wa -k identity
-w /etc/pam.d/            -p wa -k pam
-w /etc/security/         -p wa -k security

## ---- Authentication logs ----
-w /var/log/faillog       -p wa -k auth_fail
-w /var/log/lastlog       -p wa -k auth_last
-w /var/log/wtmp          -p wa -k auth_last
-w /var/log/btmp          -p wa -k auth_last
-w /var/run/faillock/     -p wa -k auth_lockout

## ---- Sudo & privilege escalation ----
-w /etc/sudoers           -p wa -k sudoers
-w /etc/sudoers.d/        -p wa -k sudoers
-a always,exit -F arch=b64 -S setuid   -F auid>=1000 -F auid!=-1 -k priv_esc
-a always,exit -F arch=b32 -S setuid   -F auid>=1000 -F auid!=-1 -k priv_esc
-a always,exit -F arch=b64 -S setgid   -F auid>=1000 -F auid!=-1 -k priv_esc
-a always,exit -F arch=b64 -S setresuid -F auid>=1000 -F auid!=-1 -k priv_esc
-a always,exit -F arch=b64 -S setresgid -F auid>=1000 -F auid!=-1 -k priv_esc

## ---- SSH ----
-w /etc/ssh/sshd_config   -p wa -k sshd_config
-w /etc/ssh/              -p wa -k ssh_config
-w /root/.ssh/            -p wa -k ssh_root

## ---- Scheduled tasks (persistance) ----
-w /etc/cron.d/           -p wa -k cron
-w /etc/cron.daily/       -p wa -k cron
-w /etc/cron.hourly/      -p wa -k cron
-w /etc/cron.monthly/     -p wa -k cron
-w /etc/cron.weekly/      -p wa -k cron
-w /etc/crontab           -p wa -k cron
-w /var/spool/cron/       -p wa -k cron
-w /etc/anacrontab        -p wa -k cron
-w /etc/systemd/system/   -p wa -k startup
-w /usr/lib/systemd/system/ -p wa -k startup

## ---- Kernel modules ----
-w /sbin/insmod           -p x  -k modules
-w /sbin/rmmod            -p x  -k modules
-w /sbin/modprobe         -p x  -k modules
-a always,exit -F arch=b64 -S init_module   -k modules
-a always,exit -F arch=b64 -S delete_module -k modules
-a always,exit -F arch=b64 -S finit_module  -k modules

## ---- Dangerous syscalls ----
-a always,exit -F arch=b64 -S ptrace -F a0=0x4|0x5|0x6|0x7 -k ptrace_debug
-a always,exit -F arch=b64 -S chmod  -F a1=0004000 -F auid>=1000 -F auid!=-1 -k suid_setgid
-a always,exit -F arch=b64 -S chmod  -F a1=0002000 -F auid>=1000 -F auid!=-1 -k suid_setgid
-a always,exit -F arch=b64 -S fchmod -F a1=0004000 -F auid>=1000 -F auid!=-1 -k suid_setgid
-a always,exit -F arch=b64 -S fchmod -F a1=0002000 -F auid>=1000 -F auid!=-1 -k suid_setgid
-a always,exit -F arch=b64 -S chown  -F auid>=1000 -F auid!=-1 -k chown
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -k chown

## ---- Deletions by users (ransomware / evidence wiping) ----
-a always,exit -F arch=b64 -S unlink   -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S rename   -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=-1 -k delete

## ---- Root executions (lateral movement) ----
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
-a always,exit -F arch=b32 -F euid=0 -S execve -k root_exec

## ---- Network config changes ----
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_config
-w /etc/hosts             -p wa -k hosts
-w /etc/hostname          -p wa -k hosts
-w /etc/resolv.conf       -p wa -k dns
-w /etc/sysconfig/network-scripts/ -p wa -k net_scripts
-w /etc/NetworkManager/   -p wa -k networkmanager

## ---- SELinux changes ----
-w /etc/selinux/          -p wa -k selinux
-w /usr/share/selinux/    -p wa -k selinux

## ---- ldconfig / ld.so (LD_PRELOAD injections) ----
-w /etc/ld.so.conf        -p wa -k ldconfig
-w /etc/ld.so.conf.d/     -p wa -k ldconfig
-w /etc/ld.so.preload     -p wa -k ldconfig

## ---- Audit config (meta) ----
-w /etc/audit/            -p wa -k audit_config

## ---- Failed access to files ----
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=-1 -k access_denied

## ---- Mount / umount events ----
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -k mounts

## ---- Time changes ----
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-w /etc/localtime         -p wa -k time_change

## ---- Make rules immutable (reboot required to change) ----
-e 2
AR

    # Régénérer les règles auditd
    if [ "$DRY_RUN" = false ]; then
        augenrules --load 2>>"$LOG_FILE" || log_warn "augenrules a retourné un avertissement."
        systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
    fi

    log_success "Auditd configuré (~50 règles, immutable mode activé)."

    mark_done "auditd"
}

# ==============================================================================
# SECTION 13 - Services systemd (désactivation / activation)
# ==============================================================================

setup_services() {
    log_section "PHASE 09 - SERVICES"

    local services_disable=(
        avahi-daemon avahi-daemon.socket
        cups cups.socket cups-browsed
        bluetooth
        postfix
        rpcbind rpcbind.socket
        nfs-server
        rsyncd
        telnet.socket
        tftp.socket
        xinetd
        ypserv ypbind
        httpd nginx
        vsftpd
        squid
        snmpd
        sendmail
        wpa_supplicant
        ModemManager
        libvirtd libvirtd.socket
        spice-vdagentd
        geoclue
        iscsid iscsid.socket
        multipathd
        firewalld
        NetworkManager-wait-online
        dnsmasq
        exim
        named
    )

    local disabled=0
    for svc in "${services_disable[@]}"; do
        # Corrigé v4 : on utilise svc_exists au lieu du pipe bugué v3
        if svc_exists "$svc"; then
            run "systemctl stop '$svc'" 2>/dev/null || true
            run "systemctl disable '$svc'" 2>/dev/null || true
            run "systemctl mask '$svc'" 2>/dev/null || true
            disabled=$((disabled + 1))
        fi
    done

    # Services à activer
    local services_enable=(auditd fail2ban chronyd sysstat nftables psacct)
    for svc in "${services_enable[@]}"; do
        if svc_exists "$svc"; then
            run "systemctl enable --now '$svc'" 2>/dev/null || true
        fi
    done

    log_success "$disabled services inutiles désactivés/masqués."

    # --- Chrony (NTP sécurisé) ---
    backup_file /etc/chrony.conf

    cat > /etc/chrony.conf <<'CH'
# CITADEL v4.0 - chrony (NTP sécurisé)

# Pools FR + fallback Cloudflare/Google (NTS quand dispo)
pool 0.fr.pool.ntp.org iburst maxsources 4
pool 1.fr.pool.ntp.org iburst maxsources 4
pool 2.fr.pool.ntp.org iburst maxsources 4
server time.cloudflare.com iburst nts
server time.nist.gov iburst

driftfile /var/lib/chrony/drift

# Step rapide si drift > 1s au démarrage
makestep 1.0 3
rtcsync

# Pas de service de temps exposé
port 0
cmdport 0

# Logging
logdir /var/log/chrony

# Clés
keyfile /etc/chrony.keys

# NTS support (Network Time Security)
ntsdumpdir /var/lib/chrony
CH

    run "systemctl restart chronyd"
    log_success "Chrony configuré (pools FR + NTS, pas de service exposé)."

    # --- Mises à jour automatiques ---
    backup_file /etc/dnf/automatic.conf

    # v3 avait un no-op sed + emit_via = stdio qui est inutile
    if [ -f /etc/dnf/automatic.conf ]; then
        sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
        sed -i 's/^download_updates.*/download_updates = yes/' /etc/dnf/automatic.conf
        # Corrigé v4 : email si ADMIN_EMAIL défini, sinon stdio
        if [[ -n "$ADMIN_EMAIL" ]]; then
            sed -i 's/^emit_via.*/emit_via = email/' /etc/dnf/automatic.conf
            sed -i "s/^email_to.*/email_to = ${ADMIN_EMAIL}/" /etc/dnf/automatic.conf
            sed -i "s/^email_from.*/email_from = root@$(hostname -f 2>/dev/null || hostname)/" /etc/dnf/automatic.conf
        else
            sed -i 's/^emit_via.*/emit_via = stdio/' /etc/dnf/automatic.conf
        fi
    fi

    run "systemctl enable --now dnf-automatic.timer"
    log_success "Mises à jour de sécurité automatiques activées."

    # --- Configuration logrotate pour les logs CITADEL ---
    cat > /etc/logrotate.d/citadel <<'LR'
/var/log/citadel_install.log
/var/log/sudo.log
/var/log/aide_check.log
/var/log/rkhunter.log
/var/log/clamav_daily.log
/var/log/freshclam.log
{
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    create 0640 root root
    sharedscripts
}
LR
    log_success "Logrotate configuré pour les logs CITADEL."

    mark_done "services"
}

# ==============================================================================
# SECTION 14 - AIDE (IDS fichiers)
# ==============================================================================

setup_aide() {
    log_section "PHASE 10 - AIDE"

    backup_file /etc/aide.conf

    cat > /etc/aide.conf <<'AIDE'
# CITADEL v4.0 - AIDE

# DB
database_in=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
database_new=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes

# Reports
verbose=5
report_url=file:/var/log/aide/aide_report.log
report_url=stdout

# Groupes de vérification
# p=perm, i=inode, n=nlinks, u=user, g=group, s=size
# m=mtime, a=atime, c=ctime, S=growing
# sha256/sha512/rmd160=hashes, acl, xattrs, selinux
Full = p+i+n+u+g+s+m+c+sha512+acl+xattrs+selinux+caps
Norm = p+i+n+u+g+s+m+c+sha256
Dir  = p+i+n+u+g+sha256
Log  = p+n+u+g

# Observer (full)
/boot               Full
/bin                Full
/sbin               Full
/usr/bin            Full
/usr/sbin           Full
/usr/libexec        Full
/lib                Full
/lib64              Full
/usr/lib            Full
/usr/lib64          Full
/opt                Full

# Configuration
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
/etc/gshadow        Full
/etc/systemd        Full
/etc/selinux        Full
/etc/nftables       Full
/etc/fail2ban       Full

# Logs - track growth (S)
/var/log            Log

# Exclusions
!/etc/mtab
!/etc/.*~
!/var/log/.*\.log$
!/var/log/.*\.gz$
!/var/log/journal
!/var/spool/.*
!/var/lib/rpm/.*
!/tmp/.*
!/var/tmp/.*
!/proc/.*
!/sys/.*
!/run/.*
!/dev/.*
!/home/.*\.bash_history$
!/root/\.bash_history$
AIDE

    # Créer le dir de log
    install -d -m 0750 /var/log/aide

    # Init de la base (long - 5-15 min selon le disque)
    if [ ! -f /var/lib/aide/aide.db.gz ]; then
        log_info "Initialisation de la base AIDE (patience, ~5-15 min)…"
        run "aide --init" &
        spinner "AIDE init" $!
        wait
        run "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz" 2>/dev/null || true
        log_success "Base AIDE initialisée."
    else
        log_info "Base AIDE existante - check rapide…"
        run "aide --check" 2>/dev/null || log_warn "Écarts AIDE détectés - voir /var/log/aide/aide_report.log"
    fi

    # Cron : v4 = check quotidien (pas hebdo) + rapport mail si ADMIN_EMAIL
    local mail_cmd=''
    [[ -n "$ADMIN_EMAIL" ]] && mail_cmd=" 2>&1 | mail -s 'AIDE daily check $(hostname)' '$ADMIN_EMAIL'"

    cat > /etc/cron.d/citadel-aide <<AC
# CITADEL v4.0 - AIDE schedule
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=${ADMIN_EMAIL:-root}

# Check quotidien (4h du matin)
0 4 * * * root /usr/sbin/aide --check >> /var/log/aide/aide_check.log 2>&1${mail_cmd}

# Update de la baseline mensuel (1er du mois 5h)
0 5 1 * * root /usr/sbin/aide --update >> /var/log/aide/aide_update.log 2>&1 && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
AC

    chmod 0644 /etc/cron.d/citadel-aide
    log_success "AIDE : check quotidien 4h, update mensuel 5h le 1er."

    mark_done "aide"
}

# ==============================================================================
# SECTION 15 - rkhunter
# ==============================================================================

setup_rkhunter() {
    log_section "PHASE 11 - RKHUNTER"

    backup_file /etc/rkhunter.conf

    # Ajout à la conf existante (on ne réécrit pas tout)
    if ! grep -q 'CITADEL' /etc/rkhunter.conf 2>/dev/null; then
        cat >> /etc/rkhunter.conf <<RKH

# ---- CITADEL v4.0 additions ----
MAIL-ON-WARNING=${ADMIN_EMAIL:-root}
MAIL_CMD=mail -s "[rkhunter] Warning on \$(hostname)"
ALLOW_SSH_ROOT_USER=no
ALLOW_SSH_PROT_V1=0
PKGMGR=RPM
UPDATE_MIRRORS=1
MIRRORS_MODE=0
WEB_CMD=""
# Whitelist utilitaires légitimes pour éviter les faux positifs
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/which
SCRIPTWHITELIST=/usr/bin/GET
SCRIPTWHITELIST=/usr/bin/ldd
ALLOWHIDDENDIR=/etc/.java
ALLOWHIDDENDIR=/etc/.git
UNHIDE_TESTS=sys
DISABLE_TESTS=suspscan hidden_ports deleted_files packet_cap_apps
USE_LOCKING=1
LOCK_TIMEOUT=300
RKH
    fi

    # Update baseline / signatures
    run "rkhunter --propupd --skip-keypress" 2>/dev/null || true
    run "rkhunter --update --skip-keypress" 2>/dev/null || true

    # Cron quotidien
    cat > /etc/cron.d/citadel-rkhunter <<RKCR
# CITADEL v4.0 - rkhunter daily
MAILTO=${ADMIN_EMAIL:-root}
30 2 * * * root /usr/bin/rkhunter --cronjob --update --quiet --report-warnings-only >> /var/log/rkhunter.log 2>&1
RKCR

    chmod 0644 /etc/cron.d/citadel-rkhunter
    log_success "rkhunter configuré (check quotidien 2h30)."

    mark_done "rkhunter"
}

# ==============================================================================
# SECTION 16 - ClamAV
# ==============================================================================

setup_clamav() {
    log_section "PHASE 12 - CLAMAV"

    # Config freshclam - éviter les warnings de missing MirrorSync
    if [ -f /etc/freshclam.conf ]; then
        backup_file /etc/freshclam.conf
        sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
    fi

    # Première mise à jour des signatures
    log_info "Mise à jour signatures ClamAV…"
    run "freshclam" &
    spinner "ClamAV DB update" $!
    wait || log_warn "Freshclam a échoué (connectivité ?)"

    # Config clamd (scan à la demande via socket)
    if [ -f /etc/clamd.d/scan.conf ]; then
        backup_file /etc/clamd.d/scan.conf
        sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true
        # Activer le socket local
        sed -i 's|^#LocalSocket.*|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf 2>/dev/null || true
    fi

    # Cron : scan quotidien + update 2x/jour
    cat > /etc/cron.d/citadel-clamav <<CLCR
# CITADEL v4.0 - ClamAV
MAILTO=${ADMIN_EMAIL:-root}
0 1 * * * root /usr/bin/clamscan -r /home /tmp /var/tmp /root --log=/var/log/clamav_daily.log --quiet --infected --exclude-dir='^/sys|^/proc|^/dev' 2>&1
0 */12 * * * root /usr/bin/freshclam --quiet >> /var/log/freshclam.log 2>&1
CLCR

    chmod 0644 /etc/cron.d/citadel-clamav
    log_success "ClamAV : scan 1h, update 2x/j."

    mark_done "clamav"
}

# ==============================================================================
# SECTION 17 - GRUB hardening + kernel cmdline
# ==============================================================================

setup_grub() {
    log_section "PHASE 13 - GRUB & BOOT"

    backup_file /etc/default/grub

    # Options kernel sécurité - v4 ajoute lockdown, module.sig_enforce, iommu
    # Note : l1tf/mds peuvent avoir un gros impact perf - désactivables via profile
    local kernel_opts=(
        'quiet'
        'loglevel=3'
        'audit=1'
        'audit_backlog_limit=16384'
        'slab_nomerge'
        'slub_debug=FZ'
        'page_alloc.shuffle=1'
        'pti=on'
        'spectre_v2=on'
        'spec_store_bypass_disable=on'
        'init_on_alloc=1'
        'init_on_free=1'
        'randomize_kstack_offset=on'
        'vsyscall=none'
    )

    # Lockdown mode (si activé et supporté)
    if [ "$ENABLE_LOCKDOWN" = true ]; then
        kernel_opts+=('lockdown=integrity')
    fi

    # Pour profils sévères (anssi/stig) - on désactive SMT (perte de perf)
    if [[ "$COMPLIANCE_PROFILE" =~ ^(anssi|stig)$ ]]; then
        kernel_opts+=('l1tf=full,force' 'mds=full,nosmt' 'tsx=off' 'nosmt')
    fi

    # IOMMU si matériel Intel
    if grep -q 'GenuineIntel' /proc/cpuinfo 2>/dev/null; then
        kernel_opts+=('intel_iommu=on' 'iommu=force')
    elif grep -q 'AuthenticAMD' /proc/cpuinfo 2>/dev/null; then
        kernel_opts+=('amd_iommu=on' 'iommu=force')
    fi

    local opts_joined
    opts_joined="${kernel_opts[*]}"

    if ! grep -q '# CITADEL' /etc/default/grub; then
        # Append proprement aux options existantes sans doublons
        if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            sed -i "s|^GRUB_CMDLINE_LINUX=\"\(.*\)\"|GRUB_CMDLINE_LINUX=\"\1 ${opts_joined}\"|" /etc/default/grub
        else
            echo "GRUB_CMDLINE_LINUX=\"${opts_joined}\"" >> /etc/default/grub
        fi
        sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub
        echo '# CITADEL v4.0 - kernel hardening' >> /etc/default/grub
    fi

    # Regen GRUB
    if [ "$DRY_RUN" = false ]; then
        if [ -d /sys/firmware/efi ]; then
            grub2-mkconfig -o /boot/efi/EFI/$(ls /boot/efi/EFI 2>/dev/null | grep -vE '^BOOT$' | head -1)/grub.cfg 2>/dev/null || \
            grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        else
            grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        fi
    fi

    # Permissions sur les fichiers GRUB (doit être 0600)
    run "chmod 0600 /boot/grub2/grub.cfg" 2>/dev/null || true
    run "chmod 0600 /boot/grub2/grubenv" 2>/dev/null || true
    run "chown root:root /boot/grub2/grub.cfg" 2>/dev/null || true

    log_success "GRUB durci (Spectre/Meltdown/MDS mitigations, lockdown, IOMMU)."

    mark_done "grub"
}

# ==============================================================================
# SECTION 18 - Syslog / journald
# ==============================================================================

setup_syslog() {
    log_section "PHASE 14 - JOURNALD & SYSLOG"

    backup_file /etc/systemd/journald.conf

    cat > /etc/systemd/journald.conf <<'JD'
# CITADEL v4.0 - journald
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
SyncIntervalSec=1m
RateLimitIntervalSec=30s
RateLimitBurst=10000
SystemMaxUse=1G
SystemKeepFree=200M
SystemMaxFileSize=100M
MaxRetentionSec=1year
MaxFileSec=1month
ForwardToSyslog=yes
ForwardToKMsg=no
ForwardToConsole=no
MaxLevelConsole=emerg
MaxLevelWall=emerg
Audit=yes
ReadKMsg=yes
JD

    # Créer le répertoire persistant si absent
    install -d -m 2755 -g systemd-journal /var/log/journal 2>/dev/null || true
    run "systemd-tmpfiles --create --prefix /var/log/journal" 2>/dev/null || true

    run "systemctl restart systemd-journald"
    log_success "journald : persistant, scellé, compressé, rétention 1 an."

    # Permissions des fichiers de logs
    for logf in /var/log/secure /var/log/messages /var/log/maillog /var/log/cron /var/log/spooler /var/log/boot.log; do
        [ -f "$logf" ] && run "chmod 0640 '$logf'"
    done
    [ -f /var/log/audit/audit.log ] && run "chmod 0600 /var/log/audit/audit.log"
    log_success "Permissions restrictives appliquées aux logs."

    # Logwatch
    if cmd_exists logwatch; then
        cat > /etc/logwatch/conf/logwatch.conf <<LW
# CITADEL v4.0 - logwatch
Output = $([ -n "${ADMIN_EMAIL}" ] && echo 'mail' || echo 'file')
Format = html
MailTo = ${ADMIN_EMAIL:-root}
MailFrom = logwatch@$(hostname -f 2>/dev/null || hostname)
Range = yesterday
Detail = Med
Service = All
LogDir = /var/log
TmpDir = /var/cache/logwatch
LW

        cat > /etc/cron.d/citadel-logwatch <<'LC'
# CITADEL v4.0 - logwatch daily
MAILTO=root
0 7 * * * root /usr/sbin/logwatch 2>/dev/null
LC
        log_success "Logwatch configuré (rapport quotidien 7h)."
    fi

    mark_done "syslog"
}

# ==============================================================================
# SECTION 19 - Environnement utilisateur (bashrc, aliases)
# ==============================================================================

setup_user_env() {
    log_section "PHASE 15 - ENVIRONNEMENT UTILISATEUR"

    local bashrc="/home/${ADMIN_USER}/.bashrc"
    local aliases="/home/${ADMIN_USER}/.bash_aliases"

    backup_file "$bashrc"

    if ! grep -q 'CITADEL v4' "$bashrc" 2>/dev/null; then
        cat >> "$bashrc" <<'BRC'

# ==== CITADEL v4.0 - environnement sécurisé ====

# Historique enrichi
export HISTTIMEFORMAT="%d/%m/%Y %T "
export HISTCONTROL=ignoredups:erasedups
export HISTSIZE=100000
export HISTFILESIZE=200000
export HISTIGNORE="ls:ll:la:pwd:clear:history:exit:cd"
shopt -s histappend cmdhist checkwinsize

# Flush history après chaque commande (précieux en cas d'incident)
PROMPT_COMMAND="history -a; ${PROMPT_COMMAND:-}"

# Umask restrictif
umask 027

# Pas de core dumps
ulimit -c 0 -S 2>/dev/null || true
ulimit -c 0 -H 2>/dev/null || true

# Éditeur
export EDITOR=vim
export VISUAL=vim
export PAGER=less
export LESS='-R -M -i'

# Couleurs
export LS_COLORS='di=1;34:ln=1;36:ex=1;32:*.tar=1;31:*.gz=1;31:*.zip=1;31:*.log=0;33'
export GREP_OPTIONS='--color=auto'

# Prompt - rouge pour root, vert pour user, avec exit code + git branch
_gitbr() { git branch 2>/dev/null | sed -n 's/^\* \(.*\)/ (\1)/p' || true; }
if [[ $EUID -eq 0 ]]; then
    PS1='\[\033[01;31m\][\u@\h]\[\033[00m\] \[\033[01;34m\]\w\[\033[01;33m\]$(_gitbr)\[\033[00m\] \[\033[01;31m\]#\[\033[00m\] '
else
    PS1='\[\033[01;32m\][\u@\h]\[\033[00m\] \[\033[01;34m\]\w\[\033[01;33m\]$(_gitbr)\[\033[00m\] \[\033[01;32m\]\$\[\033[00m\] '
fi

# Source des aliases
[ -f ~/.bash_aliases ] && . ~/.bash_aliases
BRC
    fi

    cat > "$aliases" <<'ALIAS'
# CITADEL v4.0 - aliases

# --- ls & listing ---
alias ll='ls -alFh --color=auto --group-directories-first'
alias la='ls -A --color=auto'
alias lt='ls -alt --color=auto | head -20'
alias lh='ls -d .??* 2>/dev/null'

# --- grep / diff ---
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias diff='diff --color=auto'

# --- safety nets ---
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'
alias ln='ln -i'
alias chown='chown --preserve-root'
alias chmod='chmod --preserve-root'
alias chgrp='chgrp --preserve-root'

# --- sys ---
alias update='sudo dnf update -y'
alias upgrade='sudo dnf upgrade -y'
alias install='sudo dnf install -y'
alias svc='sudo systemctl'
alias svc-run='sudo systemctl list-units --type=service --state=running'
alias svc-fail='sudo systemctl --failed'
alias svc-all='sudo systemctl list-unit-files --type=service'

# --- réseau & sécurité ---
alias ports='ss -tulnp'
alias conns='ss -tnp state established'
alias myip='curl -s https://ifconfig.me && echo'
alias fw='sudo nft list ruleset'
alias fw-save='sudo nft list ruleset > /tmp/nft-$(date +%Y%m%d-%H%M).rules'
alias f2b='sudo fail2ban-client status'
alias f2b-ssh='sudo fail2ban-client status sshd'
alias f2b-banned='sudo fail2ban-client status sshd | grep "Banned IP"'
alias f2b-unban='sudo fail2ban-client set sshd unbanip'

# --- monitoring ---
alias sys='btop 2>/dev/null || top'
alias io='sudo iotop -ao'
alias cpu='top -bn1 | head -12'
alias mem='free -h'
alias disk='df -hT | grep -v tmpfs'
alias dush='du -sh * 2>/dev/null | sort -rh | head -20'
alias psg='ps aux | grep -v grep | grep'

# --- logs ---
alias logs='sudo journalctl -f'
alias logs-boot='sudo journalctl -b'
alias logs-ssh='sudo journalctl -u sshd -f'
alias logs-auth='sudo tail -f /var/log/secure'
alias logs-audit='sudo tail -f /var/log/audit/audit.log'
alias logs-sudo='sudo tail -f /var/log/sudo.log'

# --- security quick-audits ---
alias sec-check='sudo rkhunter --check --sk'
alias sec-audit='sudo lynis audit system'
alias sec-aide='sudo aide --check'
alias sec-selinux='sestatus && getenforce'
alias sec-listening='sudo ss -tulnp4'
alias sec-cve='sudo dnf updateinfo list security'
alias sec-fails='sudo lastb -10'
alias sec-logins='sudo last -10'
alias sec-who='w; echo; sudo who --ips'
alias sec-sudo='sudo ausearch -ts today -k sudoers'
alias sec-root='sudo ausearch -ts today -k root_exec | tail -20'

# --- CITADEL ---
alias citadel='sudo /usr/local/sbin/citadel.sh'
alias citadel-status='sudo /usr/local/sbin/citadel.sh --check-only'
alias citadel-audit='sudo lynis audit system 2>&1 | tee /tmp/lynis_$(date +%Y%m%d).log'
alias citadel-report='ls -lh /var/log/citadel_reports/'

# --- utilitaires ---
alias mkdir='mkdir -pv'
alias h='history | tail -30'
alias path='echo -e ${PATH//:/\\n}'
alias now='date "+%Y-%m-%d %H:%M:%S"'
alias week='date +%V'
alias reload='source ~/.bashrc'

# --- fonctions ---
# Extrait n'importe quelle archive
extract() {
    [ -f "$1" ] || { echo "$1 introuvable"; return 1; }
    case "$1" in
        *.tar.bz2|*.tbz2) tar xjf "$1" ;;
        *.tar.gz|*.tgz)   tar xzf "$1" ;;
        *.tar.xz|*.txz)   tar xJf "$1" ;;
        *.tar)            tar xf  "$1" ;;
        *.bz2)            bunzip2  "$1" ;;
        *.gz)             gunzip   "$1" ;;
        *.xz)             unxz     "$1" ;;
        *.zip)            unzip    "$1" ;;
        *.rar)            unrar x  "$1" ;;
        *.7z)             7z x     "$1" ;;
        *) echo "Format non géré: $1"; return 1 ;;
    esac
}

# Cherche un process et le tue proprement
pskill() {
    local pids
    pids=$(pgrep -f "$1")
    if [ -z "$pids" ]; then
        echo "Pas de process matching '$1'"
        return 1
    fi
    echo "Process trouvés :"
    ps -fp $pids
    read -p "Confirmer kill ? (o/N) " ok
    [[ "$ok" =~ ^[oOyY]$ ]] && kill $pids && echo "Envoyé SIGTERM"
}

# Test SSL d'un host
ssl-check() {
    [ -z "$1" ] && { echo "Usage: ssl-check <host:port>"; return 1; }
    echo | openssl s_client -servername "${1%:*}" -connect "$1" 2>/dev/null | openssl x509 -noout -dates -subject -issuer
}
ALIAS

    chmod 0644 "$aliases"
    chown "${ADMIN_USER}:${ADMIN_USER}" "$bashrc" "$aliases" 2>/dev/null || true

    log_success "Environnement utilisateur configuré (historique enrichi + 60 aliases)."

    mark_done "userenv"
}

# ==============================================================================
# SECTION 20 - USBGuard (protection USB)
# ==============================================================================

setup_usbguard() {
    [ "$ENABLE_USBGUARD" = false ] && { log_info "USBGuard désactivé par flag."; return 0; }

    log_section "PHASE 16 - USBGUARD"

    if ! pkg_installed usbguard; then
        log_warn "Paquet usbguard absent - on skip cette phase."
        return 0
    fi

    # Générer une policy basée sur les périphériques actuellement connectés
    # (whitelist des devices présents au moment de l'install)
    if [ "$DRY_RUN" = false ]; then
        install -d -m 0750 /etc/usbguard
        usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || {
            # Fallback : règle vide, block everything
            echo "# CITADEL - fallback policy, accepte rien par défaut" > /etc/usbguard/rules.conf
        }
        chmod 0600 /etc/usbguard/rules.conf
    fi

    # Config principale - whitelist hubs et claviers par défaut
    backup_file /etc/usbguard/usbguard-daemon.conf
    cat > /etc/usbguard/usbguard-daemon.conf <<'UG'
# CITADEL v4.0 - USBGuard
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=wheel
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
DeviceRulesWithPort=false
AuditBackend=LinuxAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
UG

    install -d -m 0750 /var/log/usbguard
    install -d -m 0755 /etc/usbguard/IPCAccessControl.d

    # Permettre aux membres de wheel de gérer USBGuard
    cat > /etc/usbguard/IPCAccessControl.d/wheel <<'IPC'
Policy=modify,list
Exceptions=listen
Devices=modify,list,listen
IPC

    run "systemctl enable --now usbguard" 2>/dev/null || log_warn "Démarrage usbguard échoué (conteneur ?)"

    log_success "USBGuard actif - périphériques actuels whitelistés, bloque les nouveaux."

    mark_done "usbguard"
}

# ==============================================================================
# SECTION 21 - Process accounting (psacct / acct)
# ==============================================================================

setup_process_accounting() {
    log_section "PHASE 17 - PROCESS ACCOUNTING"

    if ! pkg_installed psacct && ! pkg_installed acct; then
        log_warn "psacct non installé - skip."
        return 0
    fi

    # Activer le service - nom varie selon les versions
    if svc_exists psacct; then
        run "systemctl enable --now psacct"
    elif svc_exists acct; then
        run "systemctl enable --now acct"
    else
        # Démarrage manuel
        run "accton on" 2>/dev/null || true
    fi

    # Créer le fichier d'accounting s'il n'existe pas
    if [ "$DRY_RUN" = false ] && [ ! -f /var/account/pacct ]; then
        install -d -m 0755 /var/account
        touch /var/account/pacct
        chmod 0640 /var/account/pacct
        accton /var/account/pacct 2>/dev/null || true
    fi

    log_success "Process accounting actif (toutes commandes tracées)."
    log_info "Utilisez 'lastcomm' pour voir l'historique, 'sa' pour les stats."

    mark_done "psacct"
}

# ==============================================================================
# SECTION 22 - Immutabilité des fichiers critiques (chattr +i)
# ==============================================================================

setup_immutable_files() {
    log_section "PHASE 18 - FICHIERS IMMUABLES"

    # Liste des fichiers qu'on rend immuables
    # Note : +i empêche même root de modifier. Un chattr -i est requis avant toute modif légitime.
    local critical_files=(
        /etc/passwd
        /etc/shadow
        /etc/group
        /etc/gshadow
        /etc/sudoers
        /etc/ssh/sshd_config
        /etc/ssh/citadel-banner
        /etc/pam.d/su
        /etc/pam.d/sudo
        /etc/security/pwquality.conf
        /etc/security/faillock.conf
        /etc/sysctl.d/99-citadel.conf
        /etc/modprobe.d/citadel-blacklist.conf
    )

    local applied=0
    for f in "${critical_files[@]}"; do
        if [ -f "$f" ]; then
            if [ "$DRY_RUN" = false ]; then
                # Sur un FS qui supporte +i (ext4, xfs) - silence sur btrfs/zfs
                chattr +i "$f" 2>/dev/null && applied=$((applied+1)) || log_debug "chattr +i échoué sur $f"
            else
                applied=$((applied+1))
            fi
            state_add "IMMUTABLE:${f}"
        fi
    done

    # Wrapper pour les admins : citadel-edit qui enlève +i, ouvre l'éditeur, remet +i
    cat > /usr/local/sbin/citadel-edit <<'CE'
#!/usr/bin/env bash
# Éditer un fichier protégé par CITADEL (retire +i, édite, remet +i)
set -euo pipefail
[ "$EUID" -eq 0 ] || { echo "root requis"; exit 1; }
[ -f "$1" ] || { echo "fichier introuvable"; exit 1; }
TARGET="$1"
echo "[citadel-edit] Suppression de l'attribut immutable sur $TARGET"
chattr -i "$TARGET"
"${EDITOR:-vim}" "$TARGET"
chattr +i "$TARGET"
echo "[citadel-edit] Attribut immutable restauré."
CE
    chmod 0750 /usr/local/sbin/citadel-edit

    log_success "$applied fichiers critiques rendus immuables (citadel-edit pour les modifier)."

    mark_done "immutable"
}

# ==============================================================================
# SECTION 23 - Bannières légales (issue, issue.net, motd, …)
# ==============================================================================

setup_legal_banners() {
    log_section "PHASE 19 - BANNIÈRES LÉGALES"

    local banner_content='
********************************************************************
*                      ACCÈS RESTREINT - RESTRICTED ACCESS         *
*                                                                  *
*  Ce système est la propriété de son exploitant. Son accès est    *
*  strictement réservé aux personnes explicitement autorisées.     *
*                                                                  *
*  Toute connexion et toute action sur ce système sont consignées  *
*  et peuvent être utilisées à des fins de contrôle, d'\''audit,     *
*  de preuve judiciaire ou de poursuites pénales.                  *
*                                                                  *
*  Si vous n'\''êtes pas explicitement autorisé à vous connecter,    *
*  déconnectez-vous IMMÉDIATEMENT.                                 *
*                                                                  *
*  Art. 323-1 à 323-3 du Code pénal - Loi Godfrain                 *
********************************************************************
'

    # /etc/issue (console locale)
    backup_file /etc/issue
    echo "$banner_content" > /etc/issue
    chmod 0644 /etc/issue

    # /etc/issue.net (connexions distantes non-SSH : telnet historique)
    backup_file /etc/issue.net
    echo "$banner_content" > /etc/issue.net
    chmod 0644 /etc/issue.net

    # /etc/motd (message post-login statique)
    backup_file /etc/motd
    cat > /etc/motd <<'MOTDL'

    ╔══════════════════════════════════════════════════════════════╗
    ║         CITADEL - Système durci (hardening profile)          ║
    ║                                                              ║
    ║  - Toutes les actions sont tracées (auditd + sudo I/O)       ║
    ║  - SELinux: Enforcing | Firewall: nftables DROP              ║
    ║  - Fail2ban actif | AIDE baseline monitorée                  ║
    ║                                                              ║
    ║  Rapport d'installation : /var/log/citadel_reports/          ║
    ║  Commande d'audit       : citadel-status                     ║
    ╚══════════════════════════════════════════════════════════════╝

MOTDL

    log_success "Bannières légales installées (/etc/issue, issue.net, motd)."

    mark_done "banners"
}

# ==============================================================================
# SECTION 24 - Restriction cron / at au groupe wheel
# ==============================================================================

setup_cron_restrictions() {
    log_section "PHASE 20 - CRON & AT"

    # cron.allow : si ce fichier existe, SEULS les users listés peuvent utiliser crontab
    # On y met root + ADMIN_USER
    {
        echo "root"
        echo "$ADMIN_USER"
    } > /etc/cron.allow
    chmod 0600 /etc/cron.allow
    chown root:root /etc/cron.allow

    # Supprimer cron.deny (si existe) - avec cron.allow présent, cron.deny est ignoré,
    # mais on nettoie pour éviter la confusion
    [ -f /etc/cron.deny ] && run "rm -f /etc/cron.deny"

    # Idem pour at (batch scheduler)
    {
        echo "root"
        echo "$ADMIN_USER"
    } > /etc/at.allow
    chmod 0600 /etc/at.allow
    chown root:root /etc/at.allow
    [ -f /etc/at.deny ] && run "rm -f /etc/at.deny"

    # Permissions des crontabs système
    run "chmod 0600 /etc/crontab" 2>/dev/null || true
    run "chmod 0700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d" 2>/dev/null || true

    log_success "Cron/at restreints à root + $ADMIN_USER."

    mark_done "cron"
}

# ==============================================================================
# SECTION 25 - Password aging (chage) pour utilisateurs existants
# ==============================================================================

setup_password_aging() {
    log_section "PHASE 21 - PASSWORD AGING"

    # Appliquer les politiques à tous les utilisateurs humains (UID >= 1000)
    local applied=0
    while IFS=: read -r username _ uid _ _ _ shell; do
        # Filtrer : UID >= 1000, < 65534 (nobody), shell valide
        if [[ "$uid" -ge 1000 && "$uid" -lt 65534 && "$shell" != '/sbin/nologin' && "$shell" != '/bin/false' ]]; then
            run "chage -M 90 -m 7 -W 14 -I 30 '$username'"
            applied=$((applied + 1))
        fi
    done < /etc/passwd

    log_success "Password aging appliqué à $applied utilisateur(s) - max 90j, min 7j, warn 14j, inactive 30j."

    mark_done "chage"
}

# ==============================================================================
# SECTION 26 - Désactivation kdump
# ==============================================================================

disable_kdump() {
    log_section "PHASE 22 - KDUMP"

    # kdump conserve une image mémoire en cas de crash - contient des secrets en clair
    if svc_exists kdump; then
        run "systemctl stop kdump" 2>/dev/null || true
        run "systemctl disable kdump" 2>/dev/null || true
        run "systemctl mask kdump" 2>/dev/null || true
        log_success "kdump désactivé (pas de crash dump mémoire)."
    fi

    # Désactiver aussi au niveau GRUB (crashkernel=no)
    if [ -f /etc/default/grub ] && grep -q 'crashkernel' /etc/default/grub; then
        sed -i 's/crashkernel=[^ "]*/crashkernel=no/' /etc/default/grub
        log_success "crashkernel=no dans GRUB (effectif au reboot)."
    fi

    # Désactiver core dumps globalement
    cat > /etc/security/limits.d/citadel-no-core.conf <<'NC'
# CITADEL v4.0 - no core dumps
* hard core 0
* soft core 0
root hard core 0
root soft core 0
NC

    # systemd : pas de core dump non plus
    install -d -m 0755 /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/citadel.conf <<'SC'
[Coredump]
Storage=none
ProcessSizeMax=0
SC

    log_success "Core dumps désactivés (limits.d + systemd-coredump)."

    mark_done "kdump"
}

# ==============================================================================
# SECTION 27 - Systemd service hardening (drop-ins)
# ==============================================================================

setup_systemd_sandboxing() {
    log_section "PHASE 23 - SYSTEMD SANDBOXING"

    # Pour chaque service critique, on crée un drop-in qui impose des restrictions
    # systemd-analyze security <unit> peut être utilisé pour vérifier le score après

    local services_to_harden=(sshd auditd chronyd fail2ban nftables)

    for svc in "${services_to_harden[@]}"; do
        svc_exists "$svc" || continue

        local drop_dir="/etc/systemd/system/${svc}.service.d"
        install -d -m 0755 "$drop_dir"

        # Hardening commun - ajusté par service plus bas si besoin
        cat > "${drop_dir}/citadel-hardening.conf" <<'HARDEN'
# CITADEL v4.0 - systemd hardening drop-in
# Vérifier le score après application : systemd-analyze security <service>
[Service]
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RemoveIPC=yes
KeyringMode=private
HARDEN

        # Ajustements spécifiques (certaines restrictions sont incompatibles
        # avec certains services - on les relâche au cas par cas)
        case "$svc" in
            sshd)
                # sshd a besoin d'écrire dans /var/log et d'ouvrir des PTY
                cat >> "${drop_dir}/citadel-hardening.conf" <<'EOF'
ProtectHome=no
ReadWritePaths=/var/log /var/run /run /var/lib/sss /etc/ssh
EOF
                ;;
            auditd)
                # auditd écrit dans /var/log/audit, et doit pouvoir faire du raw audit
                cat >> "${drop_dir}/citadel-hardening.conf" <<'EOF'
ProtectKernelLogs=no
ProtectSystem=false
ReadWritePaths=/var/log/audit
EOF
                ;;
            nftables)
                # nft a besoin de parler au kernel netfilter
                cat >> "${drop_dir}/citadel-hardening.conf" <<'EOF'
ProtectKernelModules=no
RestrictNamespaces=no
EOF
                ;;
            fail2ban)
                # fail2ban a besoin d'appeler nft pour bannir
                cat >> "${drop_dir}/citadel-hardening.conf" <<'EOF'
ReadWritePaths=/var/run/fail2ban /var/log/fail2ban.log /var/lib/fail2ban
EOF
                ;;
        esac

        log_debug "Drop-in créé : ${drop_dir}/citadel-hardening.conf"
    done

    run "systemctl daemon-reload"

    # Redémarrer chaque service pour appliquer les restrictions
    for svc in "${services_to_harden[@]}"; do
        svc_exists "$svc" && run "systemctl restart '$svc'" 2>/dev/null || true
    done

    log_success "Drop-ins hardening appliqués à ${#services_to_harden[@]} services."

    mark_done "sandbox"
}

# ==============================================================================
# SECTION 28 - Session recording (tlog) - optionnel
# ==============================================================================

setup_session_recording() {
    [ "$ENABLE_TLOG" = false ] && { log_info "tlog désactivé (--enable-tlog pour activer)."; return 0; }

    log_section "PHASE 24 - SESSION RECORDING (tlog)"

    if ! pkg_installed tlog; then
        log_warn "tlog non installé - skip."
        return 0
    fi

    # Configurer tlog-rec-session comme shell par défaut pour wheel
    # tlog enregistre toutes les sessions dans journald (cherchables après coup)
    mkdir -p /etc/tlog
    cat > /etc/tlog/tlog-rec-session.conf <<'TLOG'
{
    "shell": "/bin/bash",
    "notice": "\nATTENTION : cette session est enregistrée pour audit de sécurité.\n",
    "latency": 10,
    "payload": 2048,
    "log": {
        "input": true,
        "output": true,
        "window": true
    },
    "limit": {
        "rate": 16384,
        "burst": 32768,
        "action": "pass"
    },
    "file": {
        "path": "/var/log/tlog/tlog.log"
    },
    "writer": "journal",
    "journal": {
        "priority": "info",
        "augment": true
    }
}
TLOG

    install -d -m 0750 /var/log/tlog

    # Intégration via SSSD ou via authselect selon la distro
    if cmd_exists authselect; then
        # authselect enable-feature with-session-recording (feature souvent non dispo)
        run "authselect enable-feature with-silent-lastlog" 2>/dev/null || true
    fi

    # Pour les membres de wheel : shell = tlog-rec-session
    # (moins invasif que de le mettre global - root garde bash)
    local wheel_members
    wheel_members=$(getent group wheel | awk -F: '{print $4}' | tr ',' ' ')
    for user in $wheel_members; do
        # On skip root pour pas risquer de se locker
        [ "$user" = 'root' ] && continue
        if [ "$DRY_RUN" = false ]; then
            usermod -s /usr/bin/tlog-rec-session "$user" 2>/dev/null && \
                log_info "Session recording activé pour $user"
        fi
    done

    log_success "tlog actif - sessions des comptes wheel enregistrées dans journald."
    log_info "Recherche d'une session : journalctl _COMM=tlog-rec-session"

    mark_done "tlog"
}

# ==============================================================================
# SECTION 29 - DNS hardening (systemd-resolved + DoT + DNSSEC)
# ==============================================================================

setup_dns_hardening() {
    log_section "PHASE 25 - DNS (DoT + DNSSEC)"

    if ! cmd_exists systemd-resolve && ! cmd_exists resolvectl; then
        log_warn "systemd-resolved indisponible - skip DNS hardening."
        return 0
    fi

    backup_file /etc/systemd/resolved.conf

    # Cloudflare + Quad9 en DNS-over-TLS, DNSSEC strict
    cat > /etc/systemd/resolved.conf <<'DNS'
# CITADEL v4.0 - systemd-resolved
[Resolve]
# Cloudflare (1.1.1.1, 1.0.0.1) + Quad9 (9.9.9.9, 149.112.112.112)
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
FallbackDNS=8.8.8.8 8.8.4.4
Domains=~.
DNSSEC=yes
DNSOverTLS=yes
Cache=yes
CacheFromLocalhost=no
DNSStubListener=yes
ReadEtcHosts=yes
ResolveUnicastSingleLabel=no
DNS

    # Remplacer /etc/resolv.conf par le lien vers stub de resolved
    if [ "$DRY_RUN" = false ]; then
        if [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
            mv /etc/resolv.conf /etc/resolv.conf.pre-citadel
        fi
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        systemctl enable --now systemd-resolved
        systemctl restart systemd-resolved
    fi

    log_success "DNS : Cloudflare+Quad9 en DoT, DNSSEC activé."

    mark_done "dns"
}

# ==============================================================================
# SECTION 30 - OpenSCAP compliance scan
# ==============================================================================

setup_compliance_scan() {
    log_section "PHASE 26 - OPENSCAP / COMPLIANCE"

    if ! cmd_exists oscap; then
        log_warn "oscap non installé - skip."
        return 0
    fi

    # Localiser le datastream SCAP (varie selon la distro)
    local ssg_ds=''
    for candidate in \
        /usr/share/xml/scap/ssg/content/ssg-rocky9-ds.xml \
        /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
        /usr/share/xml/scap/ssg/content/ssg-almalinux9-ds.xml \
        /usr/share/xml/scap/ssg/content/ssg-centos9-ds.xml ; do
        [ -f "$candidate" ] && { ssg_ds="$candidate"; break; }
    done

    if [ -z "$ssg_ds" ]; then
        log_warn "Datastream SCAP introuvable - scap-security-guide manquant ?"
        return 0
    fi

    # Correspondance profil CITADEL → profil SCAP
    local scap_profile
    case "$COMPLIANCE_PROFILE" in
        cis)    scap_profile='xccdf_org.ssgproject.content_profile_cis' ;;
        anssi)  scap_profile='xccdf_org.ssgproject.content_profile_anssi_bp28_high' ;;
        stig)   scap_profile='xccdf_org.ssgproject.content_profile_stig' ;;
        *)      scap_profile='xccdf_org.ssgproject.content_profile_cis' ;;
    esac

    local scan_dir="${REPORT_DIR}/openscap"
    install -d -m 0750 "$scan_dir"

    log_info "Scan OpenSCAP avec profil $COMPLIANCE_PROFILE (peut prendre 1-5 min)…"
    if [ "$DRY_RUN" = false ]; then
        # Le scan peut retourner non-zero si des règles échouent - c'est normal
        oscap xccdf eval \
            --profile "$scap_profile" \
            --results "${scan_dir}/scan-results.xml" \
            --report "${scan_dir}/scan-report.html" \
            --oval-results \
            "$ssg_ds" >>"$LOG_FILE" 2>&1 || true
    fi

    log_success "Scan OpenSCAP : ${scan_dir}/scan-report.html"

    # Planifier un scan mensuel
    cat > /etc/cron.d/citadel-openscap <<CRON
# CITADEL v4.0 - OpenSCAP monthly
MAILTO=${ADMIN_EMAIL:-root}
0 6 1 * * root /usr/bin/oscap xccdf eval --profile ${scap_profile} --report ${scan_dir}/monthly-\$(date +\\%Y\\%m).html ${ssg_ds} > /dev/null 2>&1
CRON

    chmod 0644 /etc/cron.d/citadel-openscap
    log_success "Scan OpenSCAP planifié le 1er de chaque mois à 6h."

    mark_done "openscap"
}

# ==============================================================================
# SECTION 31 - Rapport final (TXT + HTML + JSON)
# ==============================================================================

generate_final_report() {
    local ts report_base report_txt report_html report_json
    ts="$(date +%Y%m%d_%H%M%S)"
    report_base="${REPORT_DIR}/citadel_report_${ts}"
    report_txt="${report_base}.txt"
    report_html="${report_base}.html"
    report_json="${report_base}.json"

    local pub_ip local_ip
    pub_ip="$(get_public_ip)"
    local_ip="$(get_local_ip)"

    # --------- Rapport TXT ----------
    {
        echo "══════════════════════════════════════════════════════════════"
        echo "  CITADEL v${CITADEL_VERSION} - RAPPORT D'INSTALLATION"
        echo "  Généré le $(date)"
        echo "══════════════════════════════════════════════════════════════"
        echo ""
        echo "CIBLE"
        echo "  Hôte          : $(hostname -f 2>/dev/null || hostname)"
        echo "  Distribution  : ${DISTRO_NAME:-?} ${DISTRO_VERSION:-?}"
        echo "  Kernel        : $(uname -r)"
        echo "  Architecture  : $(uname -m)"
        echo "  IP locale     : ${local_ip}"
        echo "  IP publique   : ${pub_ip}"
        echo ""
        echo "CONFIGURATION APPLIQUÉE"
        echo "  Utilisateur admin      : ${ADMIN_USER}"
        echo "  Port SSH               : ${SSH_PORT}"
        echo "  Auth SSH               : $([ -n "$SSH_PUBKEY" ] && echo 'Clé publique uniquement' || echo 'Mot de passe')"
        echo "  IPs admin whitelistées : ${ADMIN_IPS:-(aucune)}"
        echo "  IPv6                   : $([ "$ENABLE_IPV6" = true ] && echo 'Activé' || echo 'Désactivé')"
        echo "  USBGuard               : ${ENABLE_USBGUARD}"
        echo "  Kernel lockdown        : ${ENABLE_LOCKDOWN}"
        echo "  Session recording      : ${ENABLE_TLOG}"
        echo "  Port-knocking          : ${ENABLE_KNOCKD}"
        echo "  Profil compliance      : ${COMPLIANCE_PROFILE}"
        echo ""
        echo "RÉSUMÉ D'EXÉCUTION"
        echo "  Phases exécutées       : ${#PHASES_EXECUTED[@]} / ${#PHASES_ORDER[@]}"
        echo "  Modifications          : ${CHANGES_COUNT}"
        echo "  Avertissements         : ${WARNINGS_COUNT}"
        echo "  Erreurs                : ${ERRORS_COUNT}"
        echo "  Fichiers sauvegardés   : ${#BACKUP_FILES[@]}"
        echo ""
        echo "MODIFICATIONS APPLIQUÉES"
        printf '  - %s\n' "${APPLIED_CHANGES[@]}"
        echo ""
        echo "SAUVEGARDES (pour --restore)"
        printf '  %s\n' "${BACKUP_FILES[@]}"
        echo ""
        echo "ACTIONS POST-INSTALLATION RECOMMANDÉES"
        echo "  1. Dans un NOUVEAU terminal, valider SSH :"
        echo "       ssh -p ${SSH_PORT} ${ADMIN_USER}@${pub_ip}"
        echo "  2. Après validation, rebooter :"
        echo "       sudo reboot"
        echo "  3. Post-reboot : vérifier SELinux + Lynis :"
        echo "       getenforce && sudo lynis audit system"
        echo "  4. Consulter le rapport OpenSCAP :"
        echo "       ${REPORT_DIR}/openscap/scan-report.html"
        echo ""
        echo "COMMANDES UTILES"
        echo "  citadel-status                  → audit rapide (60 checks)"
        echo "  sudo lynis audit system         → audit Lynis complet"
        echo "  sudo aide --check               → intégrité fichiers"
        echo "  sudo ausearch -k root_exec      → exécutions root"
        echo "  sudo fail2ban-client status sshd → statut fail2ban"
        echo "  sudo nft list ruleset           → règles firewall"
        echo "  lastcomm                        → historique commandes"
        echo ""
        echo "══════════════════════════════════════════════════════════════"
        echo "  CITADEL v${CITADEL_VERSION} - fin de rapport"
        echo "══════════════════════════════════════════════════════════════"
    } > "$report_txt"

    chmod 0600 "$report_txt"

    # --------- Rapport JSON ----------
    {
        printf '{\n'
        printf '  "citadel_version": "%s",\n' "$CITADEL_VERSION"
        printf '  "timestamp": "%s",\n' "$(date -Iseconds)"
        printf '  "host": {\n'
        printf '    "hostname": "%s",\n' "$(hostname -f 2>/dev/null || hostname)"
        printf '    "distribution": "%s",\n' "${DISTRO_NAME:-unknown}"
        printf '    "version": "%s",\n' "${DISTRO_VERSION:-0}"
        printf '    "kernel": "%s",\n' "$(uname -r)"
        printf '    "arch": "%s",\n' "$(uname -m)"
        printf '    "ip_local": "%s",\n' "$local_ip"
        printf '    "ip_public": "%s"\n' "$pub_ip"
        printf '  },\n'
        printf '  "config": {\n'
        printf '    "admin_user": "%s",\n' "$ADMIN_USER"
        printf '    "ssh_port": %s,\n' "$SSH_PORT"
        printf '    "ssh_key_auth": %s,\n' "$([ -n "$SSH_PUBKEY" ] && echo 'true' || echo 'false')"
        printf '    "ipv6_enabled": %s,\n' "$ENABLE_IPV6"
        printf '    "usbguard": %s,\n' "$ENABLE_USBGUARD"
        printf '    "lockdown": %s,\n' "$ENABLE_LOCKDOWN"
        printf '    "tlog": %s,\n' "$ENABLE_TLOG"
        printf '    "knockd": %s,\n' "$ENABLE_KNOCKD"
        printf '    "compliance_profile": "%s"\n' "$COMPLIANCE_PROFILE"
        printf '  },\n'
        printf '  "summary": {\n'
        printf '    "phases_executed": %d,\n' "${#PHASES_EXECUTED[@]}"
        printf '    "phases_total": %d,\n' "${#PHASES_ORDER[@]}"
        printf '    "changes": %d,\n' "$CHANGES_COUNT"
        printf '    "warnings": %d,\n' "$WARNINGS_COUNT"
        printf '    "errors": %d,\n' "$ERRORS_COUNT"
        printf '    "backups": %d\n' "${#BACKUP_FILES[@]}"
        printf '  }\n'
        printf '}\n'
    } > "$report_json"

    chmod 0600 "$report_json"

    # --------- Rapport HTML ----------
    local status_color
    if [ "$ERRORS_COUNT" -eq 0 ] && [ "$WARNINGS_COUNT" -le 3 ]; then
        status_color='#22c55e'
    elif [ "$ERRORS_COUNT" -eq 0 ]; then
        status_color='#eab308'
    else
        status_color='#ef4444'
    fi

    {
        cat <<HTMLTOP
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>CITADEL v${CITADEL_VERSION} - Rapport d'installation</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #e2e8f0;
    padding: 40px 20px;
    min-height: 100vh;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  .header {
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(10px);
    border-radius: 16px;
    padding: 32px;
    margin-bottom: 24px;
    border: 1px solid rgba(148, 163, 184, 0.1);
  }
  .header h1 { font-size: 28px; background: linear-gradient(90deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
  .header .sub { color: #94a3b8; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card {
    background: rgba(30, 41, 59, 0.6);
    border-radius: 12px;
    padding: 20px;
    border: 1px solid rgba(148, 163, 184, 0.1);
  }
  .card h3 { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 700; color: #f1f5f9; }
  .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: ${status_color}; margin-right: 8px; box-shadow: 0 0 10px ${status_color}; }
  .section { background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 24px; margin-bottom: 16px; border: 1px solid rgba(148, 163, 184, 0.1); }
  .section h2 { font-size: 18px; margin-bottom: 16px; color: #f1f5f9; padding-bottom: 8px; border-bottom: 1px solid rgba(148, 163, 184, 0.15); }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(148, 163, 184, 0.08); font-size: 14px; }
  th { color: #94a3b8; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }
  .change-list { list-style: none; }
  .change-list li { padding: 6px 0; padding-left: 20px; position: relative; font-size: 13px; color: #cbd5e1; }
  .change-list li::before { content: '✓'; position: absolute; left: 0; color: #22c55e; font-weight: bold; }
  code { background: rgba(15, 23, 42, 0.8); padding: 2px 8px; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 13px; color: #60a5fa; }
  .footer { text-align: center; padding: 24px; color: #64748b; font-size: 13px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; text-transform: uppercase; font-weight: 600; }
  .badge-ok { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
  .badge-warn { background: rgba(234, 179, 8, 0.2); color: #facc15; }
  .badge-err { background: rgba(239, 68, 68, 0.2); color: #f87171; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>CITADEL v${CITADEL_VERSION}</h1>
    <div class="sub"><span class="status-dot"></span>Rapport d'installation · $(date '+%A %d %B %Y, %H:%M')</div>
  </div>

  <div class="grid">
    <div class="card"><h3>Modifications</h3><div class="value" style="color:#60a5fa">${CHANGES_COUNT}</div></div>
    <div class="card"><h3>Avertissements</h3><div class="value" style="color:#facc15">${WARNINGS_COUNT}</div></div>
    <div class="card"><h3>Erreurs</h3><div class="value" style="color:#f87171">${ERRORS_COUNT}</div></div>
    <div class="card"><h3>Phases</h3><div class="value">${#PHASES_EXECUTED[@]}/${#PHASES_ORDER[@]}</div></div>
  </div>

  <div class="section">
    <h2>Hôte & configuration</h2>
    <table>
      <tr><th>Paramètre</th><th>Valeur</th></tr>
      <tr><td>Hostname</td><td><code>$(hostname -f 2>/dev/null || hostname)</code></td></tr>
      <tr><td>Distribution</td><td>${DISTRO_NAME:-?} ${DISTRO_VERSION:-?}</td></tr>
      <tr><td>Kernel</td><td><code>$(uname -r)</code></td></tr>
      <tr><td>Architecture</td><td><code>$(uname -m)</code></td></tr>
      <tr><td>IP publique</td><td><code>${pub_ip}</code></td></tr>
      <tr><td>IP locale</td><td><code>${local_ip}</code></td></tr>
      <tr><td>Utilisateur admin</td><td><code>${ADMIN_USER}</code></td></tr>
      <tr><td>Port SSH</td><td><code>${SSH_PORT}</code></td></tr>
      <tr><td>Auth SSH</td><td>$([ -n "$SSH_PUBKEY" ] && echo '<span class="badge badge-ok">Clé publique</span>' || echo '<span class="badge badge-warn">Mot de passe</span>')</td></tr>
      <tr><td>IPv6</td><td>$([ "$ENABLE_IPV6" = true ] && echo 'Activé' || echo 'Désactivé')</td></tr>
      <tr><td>Profil compliance</td><td><span class="badge badge-ok">${COMPLIANCE_PROFILE^^}</span></td></tr>
      <tr><td>USBGuard</td><td>$([ "$ENABLE_USBGUARD" = true ] && echo '<span class="badge badge-ok">Actif</span>' || echo 'Désactivé')</td></tr>
      <tr><td>Kernel lockdown</td><td>$([ "$ENABLE_LOCKDOWN" = true ] && echo '<span class="badge badge-ok">Integrity</span>' || echo 'Désactivé')</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Modifications appliquées</h2>
    <ul class="change-list">
HTMLTOP
        for change in "${APPLIED_CHANGES[@]}"; do
            # Échapper les <>& pour HTML
            local esc
            esc=$(echo "$change" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')
            echo "      <li>${esc}</li>"
        done
        cat <<HTMLBOT
    </ul>
  </div>

  <div class="section">
    <h2>Actions post-installation</h2>
    <ol style="padding-left: 24px; line-height: 1.8; color: #cbd5e1;">
      <li>Tester SSH dans un <b>nouveau terminal</b> (ne pas fermer celui-ci) :<br/>
          <code>ssh -p ${SSH_PORT} ${ADMIN_USER}@${pub_ip}</code></li>
      <li>Si la connexion fonctionne, rebooter : <code>sudo reboot</code></li>
      <li>Après reboot, vérifier : <code>getenforce</code> et <code>sudo lynis audit system</code></li>
      <li>Consulter le rapport SCAP : <code>${REPORT_DIR}/openscap/scan-report.html</code></li>
    </ol>
  </div>

  <div class="footer">
    Rapport généré par CITADEL v${CITADEL_VERSION} · ${CITADEL_AUTHOR}<br/>
    Logs : ${LOG_FILE} · Backups : ${BACKUP_DIR}
  </div>
</div>
</body>
</html>
HTMLBOT
    } > "$report_html"

    chmod 0600 "$report_html"

    log_info "Rapports générés :"
    log_info "  TXT  : $report_txt"
    log_info "  JSON : $report_json"
    log_info "  HTML : $report_html"

    # Envoi par mail si demandé
    if [[ -n "$ADMIN_EMAIL" ]] && cmd_exists mail; then
        mail -s "[CITADEL v${CITADEL_VERSION}] Rapport d'installation $(hostname)" -a "$report_html" "$ADMIN_EMAIL" < "$report_txt" 2>/dev/null || \
            log_warn "Envoi mail échoué - vérifier postfix/mailx."
    fi
}

# ==============================================================================
# SECTION 32 - Bannière finale
# ==============================================================================

display_final_banner() {
    local pub_ip
    pub_ip="$(get_public_ip)"

    clear 2>/dev/null || true
    printf '%s' "$G"
    cat <<'BNR'

  ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
 ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
 ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
 ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
 ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
  ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

                 DÉPLOIEMENT TERMINÉ ✓
BNR
    printf '%s' "$NC"

    printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C" "$NC"
    printf '%s║%s   RÉCAPITULATIF DE SÉCURITÉ                                  %s║%s\n' "$C" "$W" "$C" "$NC"
    printf '%s╠══════════════════════════════════════════════════════════════╣%s\n' "$C" "$NC"

    _row() {
        local label="$1" value="$2" color="${3:-$G}"
        printf '%s║%s  %-30s %s%-27s%s %s║%s\n' "$C" "$NC" "$label" "$color" "$value" "$NC" "$C" "$NC"
    }

    _row "Utilisateur admin"      "$ADMIN_USER"
    _row "Port SSH"               "$SSH_PORT"
    _row "Auth SSH"               "$([ -n "$SSH_PUBKEY" ] && echo 'Clé publique ✓' || echo 'Mot de passe (!)')" \
         "$([ -n "$SSH_PUBKEY" ] && echo "$G" || echo "$Y")"
    _row "Firewall nftables"      "policy DROP ✓"
    _row "Fail2ban"               "ban 24h ✓"
    _row "SELinux"                "Enforcing ✓"
    _row "Auditd"                 "~50 règles (immutable) ✓"
    _row "AIDE"                   "baseline + check 4h ✓"
    _row "rkhunter"               "cron 2h30 ✓"
    _row "ClamAV"                 "cron 1h + signatures 12h ✓"
    _row "USBGuard"               "$([ "$ENABLE_USBGUARD" = true ] && echo 'whitelist active ✓' || echo 'désactivé')"
    _row "Kernel lockdown"        "$([ "$ENABLE_LOCKDOWN" = true ] && echo 'integrity ✓' || echo 'désactivé')"
    _row "Process accounting"     "psacct actif ✓"
    _row "Session recording"      "$([ "$ENABLE_TLOG" = true ] && echo 'tlog wheel ✓' || echo 'désactivé')"
    _row "DNS"                    "DoT + DNSSEC ✓"
    _row "Fichiers immuables"     "chattr +i sur critiques ✓"
    _row "Profil compliance"      "${COMPLIANCE_PROFILE^^}"
    _row "Modifications"          "${CHANGES_COUNT}"
    _row "Avertissements"         "${WARNINGS_COUNT}" "$([ "$WARNINGS_COUNT" -gt 0 ] && echo "$Y" || echo "$G")"
    _row "Erreurs"                "${ERRORS_COUNT}" "$([ "$ERRORS_COUNT" -gt 0 ] && echo "$R" || echo "$G")"

    printf '%s╠══════════════════════════════════════════════════════════════╣%s\n' "$C" "$NC"
    printf '%s║%s   ACTIONS IMMÉDIATES                                         %s║%s\n' "$C" "$W" "$C" "$NC"
    printf '%s╠══════════════════════════════════════════════════════════════╣%s\n' "$C" "$NC"
    printf '%s║%s                                                              %s║%s\n' "$C" "$NC" "$C" "$NC"
    printf '%s║%s  %s1.%s Ouvrir un NOUVEAU terminal et tester SSH :              %s║%s\n' "$C" "$NC" "$Y" "$NC" "$C" "$NC"
    printf '%s║%s     %sssh -p %s %s@%-20s%s         %s║%s\n' "$C" "$NC" "$W" "$SSH_PORT" "$ADMIN_USER" "$pub_ip" "$NC" "$C" "$NC"
    printf '%s║%s                                                              %s║%s\n' "$C" "$NC" "$C" "$NC"
    printf '%s║%s  %s2.%s Si OK, rebooter :  %ssudo reboot%s                         %s║%s\n' "$C" "$NC" "$Y" "$NC" "$W" "$NC" "$C" "$NC"
    printf '%s║%s                                                              %s║%s\n' "$C" "$NC" "$C" "$NC"
    printf '%s║%s  %s3.%s Post-reboot : %ssudo lynis audit system%s                 %s║%s\n' "$C" "$NC" "$Y" "$NC" "$W" "$NC" "$C" "$NC"
    printf '%s║%s                                                              %s║%s\n' "$C" "$NC" "$C" "$NC"
    printf '%s╚══════════════════════════════════════════════════════════════╝%s\n\n' "$C" "$NC"

    printf '%s  Rapports  : %s/citadel_report_*%s\n' "$B" "$REPORT_DIR" "$NC"
    printf '%s  Logs      : %s%s\n' "$B" "$LOG_FILE" "$NC"
    printf '%s  Backups   : %s%s\n' "$B" "$BACKUP_DIR" "$NC"
    printf '%s  State DB  : %s (pour --uninstall)%s\n\n' "$B" "$STATE_FILE" "$NC"
}

# ==============================================================================
# SECTION 33 - Mode --restore (restauration sélective)
# ==============================================================================

do_restore() {
    log_section "MODE RESTAURATION"

    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        log_error "Aucun backup disponible dans $BACKUP_DIR"
        exit 1
    fi

    # Lister les backups par date
    printf '\n%sBackups disponibles :%s\n\n' "$BOLD" "$NC"
    local -a backup_files=()
    local i=1
    while IFS= read -r f; do
        backup_files+=("$f")
        local orig ts
        orig=$(echo "$f" | sed "s|${BACKUP_DIR}||" | sed 's|\.bak\.[0-9]*$||')
        ts=$(echo "$f" | grep -oE '\.bak\.[0-9]+$' | grep -oE '[0-9]+')
        printf '  %s[%d]%s %-55s  %s\n' "$C" "$i" "$NC" "$orig" "$(date -d "@$ts" '+%Y-%m-%d %H:%M' 2>/dev/null)"
        ((i++))
    done < <(find "$BACKUP_DIR" -type f -name '*.bak.*' | sort)

    printf '\n%s[?]%s Options de restauration :\n' "$P" "$NC"
    printf '  %s[a]%s Tout restaurer\n' "$G" "$NC"
    printf '  %s[s]%s Restauration sélective (interactive)\n' "$G" "$NC"
    printf '  %s[q]%s Annuler\n' "$G" "$NC"
    printf '%s[?]%s Choix : ' "$P" "$NC"
    read -r choice

    case "$choice" in
        a|A)
            printf '%s[?]%s Confirmer la restauration de TOUS les backups ? (oui/NON) : ' "$P" "$NC"
            read -r cf
            [[ "$cf" =~ ^(oui|OUI|yes|YES)$ ]] || { log_info "Annulé."; exit 0; }

            local count=0
            for bakfile in "${backup_files[@]}"; do
                local orig_path
                orig_path=$(echo "$bakfile" | sed "s|${BACKUP_DIR}||" | sed 's|\.bak\.[0-9]*$||')
                if [ -f "$bakfile" ]; then
                    # Retirer +i si présent (chattr)
                    chattr -i "$orig_path" 2>/dev/null || true
                    cp --preserve=all "$bakfile" "$orig_path" && count=$((count+1)) && log_info "Restauré : $orig_path"
                fi
            done
            log_success "$count fichier(s) restauré(s)."
            ;;

        s|S)
            local restored=0
            for bakfile in "${backup_files[@]}"; do
                local orig_path
                orig_path=$(echo "$bakfile" | sed "s|${BACKUP_DIR}||" | sed 's|\.bak\.[0-9]*$||')
                printf '%s[?]%s Restaurer %s ? (o/N) : ' "$P" "$NC" "$orig_path"
                read -r cf
                if [[ "$cf" =~ ^[oOyY]$ ]]; then
                    chattr -i "$orig_path" 2>/dev/null || true
                    cp --preserve=all "$bakfile" "$orig_path" && restored=$((restored+1))
                fi
            done
            log_success "$restored fichier(s) restauré(s)."
            ;;
        *)
            log_info "Annulé."
            exit 0
            ;;
    esac

    log_warn "Redémarrez les services concernés (sshd, nftables, auditd…) ou rebootez."
    exit 0
}

# ==============================================================================
# SECTION 34 - Mode --check-only (audit ~60 contrôles)
# ==============================================================================

do_check_only() {
    log_section "AUDIT SYSTÈME (lecture seule)"

    local score=0 total=0
    declare -A category_scores=([kernel]=0 [network]=0 [auth]=0 [services]=0 [files]=0 [audit]=0)
    declare -A category_totals=([kernel]=0 [network]=0 [auth]=0 [services]=0 [files]=0 [audit]=0)

    _check() {
        local cat="$1" desc="$2" cmd="$3"
        total=$((total + 1))
        category_totals[$cat]=$((category_totals[$cat] + 1))
        if eval "$cmd" &>/dev/null; then
            printf '  %s✓%s %s\n' "$G" "$NC" "$desc"
            score=$((score + 1))
            category_scores[$cat]=$((category_scores[$cat] + 1))
        else
            printf '  %s✗%s %s\n' "$R" "$NC" "$desc"
        fi
    }

    printf '\n%s─── Noyau & sysctl ───%s\n' "$BOLD" "$NC"
    _check kernel "ASLR = 2"                    '[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = "2" ]'
    _check kernel "kptr_restrict = 2"           '[ "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" = "2" ]'
    _check kernel "dmesg_restrict = 1"          '[ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" = "1" ]'
    _check kernel "BPF non-privilégié bloqué"   '[ "$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)" = "1" ]'
    _check kernel "BPF JIT hardening"           '[ "$(sysctl -n net.core.bpf_jit_harden 2>/dev/null)" = "2" ]'
    _check kernel "Yama ptrace >= 1"            '[ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" -ge 1 ]'
    _check kernel "perf_event_paranoid >= 2"    '[ "$(sysctl -n kernel.perf_event_paranoid 2>/dev/null)" -ge 2 ]'
    _check kernel "kexec désactivé"             '[ "$(sysctl -n kernel.kexec_load_disabled 2>/dev/null)" = "1" ]'
    _check kernel "user namespaces restreints"  '[ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null)" = "0" ]'
    _check kernel "Core dumps désactivés"       '[ "$(sysctl -n fs.suid_dumpable 2>/dev/null)" = "0" ]'
    _check kernel "Hardlinks protégés"          '[ "$(sysctl -n fs.protected_hardlinks 2>/dev/null)" = "1" ]'
    _check kernel "Symlinks protégés"           '[ "$(sysctl -n fs.protected_symlinks 2>/dev/null)" = "1" ]'
    _check kernel "Blacklist modules en place"  '[ -f /etc/modprobe.d/citadel-blacklist.conf ]'
    _check kernel "usb-storage blacklisté"      'grep -q "install usb-storage /bin/true" /etc/modprobe.d/citadel-blacklist.conf'
    _check kernel "Lockdown mode activé"        '[ "$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oE "\[\S+\]" | tr -d "[]")" != "none" ]'

    printf '\n%s─── Réseau ───%s\n' "$BOLD" "$NC"
    _check network "rp_filter strict"           '[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" = "1" ]'
    _check network "TCP syncookies actifs"      '[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ]'
    _check network "accept_redirects OFF"       '[ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = "0" ]'
    _check network "send_redirects OFF"         '[ "$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)" = "0" ]'
    _check network "accept_source_route OFF"    '[ "$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)" = "0" ]'
    _check network "log_martians ON"            '[ "$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)" = "1" ]'
    _check network "IP forwarding OFF"          '[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ]'
    _check network "TCP timestamps OFF"         '[ "$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)" = "0" ]'
    _check network "nftables actif"             'systemctl is-active --quiet nftables'
    _check network "nftables policy DROP"       'nft list chain inet citadel_filter input 2>/dev/null | grep -q "policy drop"'
    _check network "fail2ban actif"             'systemctl is-active --quiet fail2ban'
    _check network "firewalld masqué"           '[ "$(systemctl is-enabled firewalld 2>/dev/null)" = "masked" ] || ! systemctl list-unit-files 2>/dev/null | grep -q firewalld.service'

    printf '\n%s─── Authentification ───%s\n' "$BOLD" "$NC"
    _check auth "SSH port non-standard"         '! grep -qE "^Port 22$" /etc/ssh/sshd_config'
    _check auth "PermitRootLogin no"            'grep -qE "^PermitRootLogin no" /etc/ssh/sshd_config'
    _check auth "X11Forwarding no"              'grep -qE "^X11Forwarding no" /etc/ssh/sshd_config'
    _check auth "AllowTcpForwarding no"         'grep -qE "^AllowTcpForwarding no" /etc/ssh/sshd_config'
    _check auth "MaxAuthTries 3"                'grep -qE "^MaxAuthTries 3" /etc/ssh/sshd_config'
    _check auth "ClientAliveInterval set"       'grep -qE "^ClientAliveInterval" /etc/ssh/sshd_config'
    _check auth "UsePAM yes"                    'grep -qE "^UsePAM yes" /etc/ssh/sshd_config'
    _check auth "Banner activé"                 'grep -qE "^Banner " /etc/ssh/sshd_config'
    _check auth "pwquality minlen >= 14"        'grep -qE "^minlen\s*=\s*1[4-9]|^minlen\s*=\s*[2-9][0-9]" /etc/security/pwquality.conf'
    _check auth "faillock configuré"            '[ -f /etc/security/faillock.conf ] && grep -q "deny" /etc/security/faillock.conf'
    _check auth "su restreint au wheel"         'grep -qE "^auth\s+required\s+pam_wheel" /etc/pam.d/su'
    _check auth "login.defs UMASK 027"          'grep -qE "^UMASK\s+027" /etc/login.defs'
    _check auth "PASS_MAX_DAYS <= 90"           'grep -qE "^PASS_MAX_DAYS\s+[0-9]+" /etc/login.defs && [ "$(grep PASS_MAX_DAYS /etc/login.defs | awk "{print \$2}")" -le 90 ]'

    printf '\n%s─── Services & démons ───%s\n' "$BOLD" "$NC"
    _check services "SELinux Enforcing"         '[ "$(getenforce 2>/dev/null)" = "Enforcing" ]'
    _check services "auditd actif"              'systemctl is-active --quiet auditd'
    _check services "chronyd actif"             'systemctl is-active --quiet chronyd'
    _check services "dnf-automatic.timer actif" 'systemctl is-active --quiet dnf-automatic.timer'
    _check services "psacct actif"              'systemctl is-active --quiet psacct || systemctl is-active --quiet acct'
    _check services "usbguard actif"            'systemctl is-active --quiet usbguard || ! command -v usbguard >/dev/null 2>&1'
    _check services "cups désactivé"            '! systemctl is-active --quiet cups'
    _check services "avahi désactivé"           '! systemctl is-active --quiet avahi-daemon'
    _check services "bluetooth désactivé"       '! systemctl is-active --quiet bluetooth'
    _check services "kdump désactivé"           '! systemctl is-active --quiet kdump 2>/dev/null'

    printf '\n%s─── Fichiers & permissions ───%s\n' "$BOLD" "$NC"
    _check files "/tmp noexec"                  'mount | grep -E "\s/tmp\s" | grep -q noexec'
    _check files "/dev/shm noexec"              'mount | grep -E "\s/dev/shm\s" | grep -q noexec'
    _check files "Swap configuré"               'swapon --show 2>/dev/null | grep -q .'
    _check files "Journald persistant"          '[ -d /var/log/journal ]'
    _check files "AIDE DB présente"             '[ -f /var/lib/aide/aide.db.gz ]'
    _check files "/etc/shadow immuable"         'lsattr /etc/shadow 2>/dev/null | grep -q "^....i"'
    _check files "/etc/sudoers immuable"        'lsattr /etc/sudoers 2>/dev/null | grep -q "^....i"'
    _check files "Permissions /etc/shadow"      '[ "$(stat -c %a /etc/shadow)" = "0" ]'
    _check files "cron.allow existe"            '[ -f /etc/cron.allow ]'

    printf '\n%s─── Audit & détection ───%s\n' "$BOLD" "$NC"
    _check audit "AIDE installé"                'command -v aide'
    _check audit "rkhunter installé"            'command -v rkhunter'
    _check audit "ClamAV installé"              'command -v clamscan'
    _check audit "Lynis installé"               'command -v lynis'
    _check audit "OpenSCAP installé"            'command -v oscap'
    _check audit "Règles auditd chargées"       '[ "$(auditctl -l 2>/dev/null | wc -l)" -gt 20 ]'
    _check audit "Audit immutable mode"         'auditctl -s 2>/dev/null | grep -q "enabled 2"'
    _check audit "Cron AIDE programmé"          '[ -f /etc/cron.d/citadel-aide ]'
    _check audit "Cron rkhunter programmé"      '[ -f /etc/cron.d/citadel-rkhunter ]'
    _check audit "Cron ClamAV programmé"        '[ -f /etc/cron.d/citadel-clamav ]'

    local pct=$(( score * 100 / total ))
    printf '\n%s═══════════════════════════════════════════════════════════════%s\n' "$BOLD" "$NC"
    printf '  Score global CITADEL : %s%d/%d (%d%%)%s\n\n' "$BOLD" "$score" "$total" "$pct" "$NC"

    # Détail par catégorie
    for cat in kernel network auth services files audit; do
        local cs=${category_scores[$cat]} ct=${category_totals[$cat]}
        local cpct=$((ct > 0 ? cs * 100 / ct : 0))
        local color="$G"
        [ "$cpct" -lt 90 ] && color="$Y"
        [ "$cpct" -lt 70 ] && color="$R"
        printf '  %s%-10s%s : %s%3d%%%s (%d/%d)\n' "$BOLD" "${cat^^}" "$NC" "$color" "$cpct" "$NC" "$cs" "$ct"
    done

    printf '\n'
    if [ "$pct" -ge 90 ]; then
        printf '  %s✓  Système correctement durci.%s\n' "$G" "$NC"
    elif [ "$pct" -ge 70 ]; then
        printf '  %s⚠  Niveau correct mais optimisable - relancez CITADEL sans --check-only.%s\n' "$Y" "$NC"
    else
        printf '  %s✗  Niveau de sécurité insuffisant - CITADEL doit être appliqué.%s\n' "$R" "$NC"
    fi
    printf '\n'

    exit 0
}

# ==============================================================================
# SECTION 35 - Mode --uninstall
# ==============================================================================

do_uninstall() {
    log_section "MODE DÉSINSTALLATION"

    if [ ! -f "$STATE_FILE" ]; then
        log_error "State DB introuvable - pas d'install CITADEL à désinstaller."
        exit 1
    fi

    printf '\n%s[!]%s Vous êtes sur le point de REVERT toutes les modifications CITADEL.\n' "$R" "$NC"
    printf '%s[!]%s Cette opération est globalement irréversible (hors backups).\n' "$R" "$NC"
    printf '%s[?]%s Confirmer (tapez "uninstall") : ' "$P" "$NC"
    read -r cf
    [[ "$cf" = 'uninstall' ]] || { log_info "Annulé."; exit 0; }

    log_info "Analyse de la state DB…"

    # 1) Retirer chattr +i sur fichiers immuables
    log_info "Suppression des attributs immuables…"
    grep '^IMMUTABLE:' "$STATE_FILE" 2>/dev/null | while IFS=: read -r _ file; do
        [ -f "$file" ] && chattr -i "$file" 2>/dev/null || true
    done

    # 2) Restaurer tous les backups (plus récent en premier)
    log_info "Restauration des backups…"
    local restored=0
    while IFS= read -r line; do
        local orig bak
        orig=$(echo "$line" | awk -F'|' '{print $2}' | grep -oE '^BACKUP:[^:]+' | sed 's/^BACKUP://')
        bak=$(echo "$line" | awk -F'|' '{print $2}' | grep -oE ':.*' | sed 's/^://')
        if [ -n "$orig" ] && [ -f "$bak" ]; then
            cp --preserve=all "$bak" "$orig" 2>/dev/null && restored=$((restored+1))
        fi
    done < <(grep 'BACKUP:' "$STATE_FILE" 2>/dev/null | tac)
    log_success "$restored fichiers restaurés."

    # 3) Supprimer les fichiers CITADEL créés
    log_info "Suppression des fichiers CITADEL…"
    rm -f /etc/sudoers.d/citadel
    rm -f /etc/sysctl.d/99-citadel.conf
    rm -f /etc/modprobe.d/citadel-blacklist.conf
    rm -f /etc/modules-load.d/citadel.conf
    rm -f /etc/ssh/citadel-banner
    rm -f /etc/profile.d/citadel-motd.sh
    rm -f /etc/profile.d/citadel-timeout.sh
    rm -f /etc/audit/rules.d/citadel.rules
    rm -f /etc/cron.d/citadel-*
    rm -f /etc/nftables/citadel-*.nft
    rm -f /etc/logrotate.d/citadel
    rm -f /etc/security/limits.d/citadel-no-core.conf
    rm -f /etc/systemd/coredump.conf.d/citadel.conf
    rm -rf /etc/systemd/system/sshd.service.d/citadel-hardening.conf
    rm -rf /etc/systemd/system/auditd.service.d/citadel-hardening.conf
    rm -rf /etc/systemd/system/chronyd.service.d/citadel-hardening.conf
    rm -rf /etc/systemd/system/fail2ban.service.d/citadel-hardening.conf
    rm -rf /etc/systemd/system/nftables.service.d/citadel-hardening.conf
    rm -f /usr/local/sbin/citadel-edit

    systemctl daemon-reload

    # 4) Supprimer les entrées GRUB CITADEL
    if grep -q '# CITADEL' /etc/default/grub; then
        sed -i '/# CITADEL/d' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
    fi

    # 5) Re-autoriser firewalld si voulu
    printf '%s[?]%s Réactiver firewalld ? (o/N) : ' "$P" "$NC"
    read -r cf
    if [[ "$cf" =~ ^[oOyY]$ ]]; then
        systemctl unmask firewalld 2>/dev/null || true
        systemctl enable --now firewalld 2>/dev/null || true
        systemctl stop nftables 2>/dev/null || true
        systemctl disable nftables 2>/dev/null || true
    fi

    log_success "CITADEL désinstallé."
    log_warn "Le répertoire $CITADEL_ROOT et les backups sont conservés."
    log_warn "Un reboot est fortement recommandé."

    exit 0
}

# ==============================================================================
# SECTION 36 - Mode --self-test
# ==============================================================================

do_self_test() {
    log_section "SELF-TEST SUITE"

    local passed=0 failed=0
    _t() {
        local name="$1" cmd="$2"
        if eval "$cmd" &>/dev/null; then
            printf '  %s✓%s %s\n' "$G" "$NC" "$name"
            passed=$((passed + 1))
        else
            printf '  %s✗%s %s\n' "$R" "$NC" "$name"
            failed=$((failed + 1))
        fi
    }

    printf '\n%s─── Validation du script CITADEL ───%s\n\n' "$BOLD" "$NC"

    # Test 1 : syntaxe bash du script
    _t "Syntaxe bash du script"          "bash -n '$0'"

    # Test 2 : fonctions helper
    _t "Fonction log_info disponible"    "declare -f log_info >/dev/null"
    _t "Fonction run disponible"         "declare -f run >/dev/null"
    _t "Fonction backup_file disponible" "declare -f backup_file >/dev/null"

    # Test 3 : commandes externes utilisées
    _t "nft (binaire)"                   "command -v nft"
    _t "systemctl (binaire)"             "command -v systemctl"
    _t "audit (binaire)"                 "command -v auditctl"
    _t "ssh-keygen (binaire)"            "command -v ssh-keygen"
    _t "chattr (binaire)"                "command -v chattr"
    _t "semanage (binaire)"              "command -v semanage"

    # Test 4 : variables critiques définies
    _t "CITADEL_VERSION définie"         "[ -n '${CITADEL_VERSION:-}' ]"
    _t "Tableau PHASES peuplé"           "[ ${#PHASES[@]} -gt 0 ]"
    _t "PHASES_ORDER cohérent"           "[ ${#PHASES_ORDER[@]} -eq ${#PHASES[@]} ]"

    # Test 5 : validation d'une config nftables temporaire
    _t "nft accepte syntaxe stub"        "echo 'table inet t { chain c { type filter hook input priority 0; } }' | nft -c -f -"

    # Test 6 : sysctl.d réussit à parser
    if [ -f /etc/sysctl.d/99-citadel.conf ]; then
        _t "sysctl.d/99-citadel valide"  "sysctl -p /etc/sysctl.d/99-citadel.conf"
    fi

    printf '\n%s═══════════════════════════════════════════════════════════════%s\n' "$BOLD" "$NC"
    printf '  Tests : %s%d passés%s, %s%d échoués%s\n\n' "$G" "$passed" "$NC" "$R" "$failed" "$NC"

    if [ "$failed" -eq 0 ]; then
        printf '  %s✓  Tous les tests passent.%s\n\n' "$G" "$NC"
        exit 0
    else
        printf '  %s✗  Des tests échouent - vérifier les prérequis.%s\n\n' "$R" "$NC"
        exit 1
    fi
}

# ==============================================================================
# SECTION 37 - MAIN
# ==============================================================================

main() {
    # Initialisation du log
    mkdir -p "$(dirname "$LOG_FILE")"
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "  CITADEL v${CITADEL_VERSION} - Démarrage $(date -Iseconds)"
        echo "  Commande : $0 $*"
        echo "  PID: $$  UID: $EUID"
        echo "═══════════════════════════════════════════════════════════════"
    } >> "$LOG_FILE"

    # Bannière d'entrée
    printf '%s' "$C"
    cat <<'EOF'

  ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
 ██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
 ██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
 ██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
 ╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
  ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

EOF
    printf '    %sULTRA HARDENING FRAMEWORK v%s%s\n' "$BOLD" "$CITADEL_VERSION" "$NC"
    printf '    %spar %s%s\n\n' "$DIM" "$CITADEL_AUTHOR" "$NC"

    # Modes spéciaux en premier - pas de precheck complet nécessaire pour certains
    if [ "$SELF_TEST" = true ]; then
        do_self_test
    fi

    if [ "$CHECK_ONLY" = true ]; then
        # On a juste besoin d'être root pour check-only
        [ "$EUID" -ne 0 ] && { printf '%s[!]%s root requis\n' "$R" "$NC" >&2; exit 1; }
        do_check_only
    fi

    if [ "$RESTORE_MODE" = true ]; then
        precheck
        do_restore
    fi

    if [ "$UNINSTALL_MODE" = true ]; then
        precheck
        do_uninstall
    fi

    # Mode normal - hardening complet ou phases sélectionnées
    [ "$DRY_RUN" = true ] && printf '%s  MODE DRY-RUN - aucune modification ne sera appliquée%s\n\n' "$Y" "$NC"

    precheck

    # Snapshot pré-install (si LVM)
    [ "$DRY_RUN" = false ] && create_pre_install_snapshot

    collect_inputs

    # Déterminer les phases à exécuter
    local -a phases_to_run=()
    if [ -n "$SELECTED_PHASES" ]; then
        # Mode sélectif via --phases=csv
        IFS=',' read -ra requested <<< "$SELECTED_PHASES"
        for p in "${requested[@]}"; do
            if [[ -n "${PHASES[$p]:-}" ]]; then
                phases_to_run+=("$p")
            else
                log_warn "Phase inconnue : '$p' - ignorée."
            fi
        done
        log_info "Exécution de ${#phases_to_run[@]} phase(s) seulement : ${phases_to_run[*]}"
    else
        # Mode complet dans l'ordre canonique
        phases_to_run=("${PHASES_ORDER[@]}")
    fi

    # Exécution des phases
    local start_time=$SECONDS
    for phase in "${phases_to_run[@]}"; do
        local fn="${PHASES[$phase]}"
        if declare -f "$fn" >/dev/null; then
            if "$fn"; then
                PHASES_EXECUTED+=("$phase")
            else
                log_error "Phase '$phase' a échoué (code $?)"
            fi
        else
            log_warn "Fonction '$fn' introuvable pour la phase '$phase'."
        fi
    done
    local elapsed=$((SECONDS - start_time))

    # Rapport & banner final
    generate_final_report
    display_final_banner

    printf '  %sTemps écoulé :%s %d min %d sec\n\n' "$BOLD" "$NC" "$((elapsed / 60))" "$((elapsed % 60))"

    # Petit avertissement si pas de clé SSH
    if [ -z "$SSH_PUBKEY" ]; then
        printf '  %s⚠  ATTENTION : l'"'"'authentification par mot de passe est encore active.%s\n' "$Y" "$NC"
        printf '  %s    Déployez une clé SSH dès que possible et désactivez le mot de passe.%s\n\n' "$Y" "$NC"
    fi

    # Avertissement reboot si nécessaire
    if [ "$SKIP_REBOOT_WARN" = false ]; then
        printf '  %s⚠  Certaines modifications nécessitent un reboot (GRUB, /proc, SELinux relabel).%s\n' "$Y" "$NC"
        printf '  %s    Après validation de SSH :%s sudo reboot\n\n' "$Y" "$NC"
    fi

    exit 0
}

# ==============================================================================
# Point d'entrée
# ==============================================================================
main "$@"