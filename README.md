# Project Citadel — v2.0

> **Universal Hardening Suite — Rocky Linux 9 / RHEL 9**
> Transforme une installation minimale en serveur de production sécurisé, auditable et prêt pour la conteneurisation.


## Présentation

**Project Citadel** est un script de hardening Bash conçu pour Rocky Linux 9 et RHEL 9. En une seule exécution interactive, il configure un socle sécurisé universel adapté à tout type de déploiement : Web, Base de données, Applicatif, ou futur cluster de conteneurs.

Le script ne fait aucune hypothèse sur l'usage final du serveur : il prépare le noyau, le pare-feu et les modules réseau pour une compatibilité immédiate avec Docker, Podman ou des solutions VPN, sans installer ces outils si vous n'en avez pas besoin.


## Fonctionnalités v2.0

### Système & Maintenance
| Élément | Détail |
|---|---|
| **Identité** | Hostname + timezone Europe/Paris |
| **Dépôts** | CRB & EPEL activés automatiquement |
| **Mises à jour** | Full upgrade + `dnf-automatic` (security only) |
| **Swap** | Création intelligente d'un fichier 2 Go si absent (anti OOM) |
| **Mode dry-run** | `--dry-run` : simulation complète sans modifier le système |

### Contrôle d'Accès
| Élément | Détail |
|---|---|
| **Utilisateur** | Création ou élévation d'un admin dédié (groupe `wheel`) |
| **Validation** | Format Unix strict du nom d'utilisateur vérifié |
| **Clé SSH** | Déploiement automatique dans `authorized_keys` si fournie |

### SSH Fortress
| Paramètre | Valeur |
|---|---|
| `Port` | Configurable (validé entre 1025–65535) |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` si clé fournie, `yes` sinon (avec avertissement) |
| `AuthenticationMethods` | `publickey` si clé fournie |
| `MaxAuthTries` | `3` |
| `X11Forwarding` | `no` |
| `ClientAliveInterval` | `300` (session kickée après 10 min d'inactivité) |
| `LoginGraceTime` | `30s` |
| `PrintLastLog` | `yes` (dernière connexion visible à chaque login) |
| **Validation** | `sshd -t` exécuté avant tout restart — restauration auto si config invalide |

**MOTD dynamique post-auth** : s'affiche après l'authentification uniquement — entièrement compatible SFTP/SCP/rsync (contrairement à `/etc/issue.net`). Affiche hostname, date, load, mémoire, disque et uptime.

### Hardening Kernel (sysctl)

**Réseau :**
- Protection IP Spoofing (`rp_filter`)
- Anti-MITM (ignore redirects ICMP)
- Anti-SYN Flood (`tcp_syncookies`, backlog 2048)
- Log des paquets suspects (Martians)
- Forwarding activé pour compatibilité VPN/containers

**Mémoire & Exploitation :**
- `kernel.randomize_va_space = 2` — ASLR maximum
- `fs.suid_dumpable = 0` — Désactive les core dumps SUID (évite les fuites de secrets)
- `kernel.dmesg_restrict = 1` — `dmesg` réservé à root
- `kernel.kptr_restrict = 2` — Cache les pointeurs kernel dans `/proc`
- `fs.protected_hardlinks/symlinks = 1` — Bloque les techniques de privilege escalation via liens

### SELinux
- Vérifie l'état au runtime
- Force `SELINUX=enforcing` dans `/etc/selinux/config` si non configuré
- Contexte SELinux ajusté automatiquement pour le port SSH personnalisé

### Défense Réseau
| Élément | Détail |
|---|---|
| **Zone par défaut** | `drop` — les paquets non autorisés sont silencieusement ignorés (pas de RST, invisible aux scanners) |
| **Port SSH** | Seul port explicitement ouvert |
| **Rate-limit SSH** | Max 10 nouvelles connexions/minute par IP (firewall, en amont de Fail2Ban) |
| **Masquerade** | Activé par défaut (compatibilité Docker/VPN futur) |
| **Fail2Ban** | Mode agressif, ban 1h, max 3 tentatives en 10 min |

### Audit & Surveillance
**Auditd — Règles surveillées :**
- `/etc/passwd`, `/etc/shadow`, `/etc/group` (modifications d'identité)
- `/etc/sudoers` et `/etc/sudoers.d/` (escalade de privilèges)
- `/etc/ssh/sshd_config` (modifications de config SSH)
- Tous les crontabs (`/etc/cron.*`, `/var/spool/cron`) — détection de persistance
- **Toutes les exécutions avec `euid=0`** (`execve` root) — détection lateral movement

**AIDE :**
- Base d'intégrité initialisée à l'installation (`aide --init`)
- Cron hebdomadaire automatique (lundi 3h00) → log dans `/var/log/aide_check.log`

**RKHunter + Lynis :**
- RKHunter mis à jour et prêt
- Lynis installé pour les audits ponctuels de conformité (`sudo lynis audit system`)

### Environnement Administrateur
- Arsenal CLI : `btop`, `ncdu`, `tree`, `git`, `vim`, `wget`, `curl`, `net-tools`, `bind-utils`
- Prompt Bash coloré (user, host, path)
- Historique étendu (10 000 lignes, horodaté, sans doublons)
- **Aliases :**

```bash
alias update    # dnf update -y
alias ll        # ls détaillé + couleurs
alias ports     # netstat -tulanp
alias myip      # curl ifconfig.me
alias sys       # btop
alias firewall  # firewall-cmd --list-all
alias checksec  # rkhunter --check
alias audit     # lynis audit system
alias aidechk   # aide --check
```

## Installation

> ⚠️ **Prérequis :** Installation fraîche de Rocky Linux 9 / RHEL 9. Ne pas exécuter sur un serveur en production sans revue préalable du code.

```bash
# 1. Télécharger
curl -O https://raw.githubusercontent.com/4b75726169736859/CITADEL/main/citadel_setup.sh

# 2. Rendre exécutable
chmod +x citadel_setup.sh

# 3. Lancer (en root)
./citadel_setup.sh

# 3b. Mode simulation (aucune modification)
./citadel_setup.sh --dry-run
```

### Assistant interactif

Le script vous demandera :

1. Créer un nouvel utilisateur ou élever un existant
2. Nom de l'utilisateur admin
3. Votre clé SSH publique *(optionnel — désactive l'auth par mot de passe si fournie)*
4. Port SSH personnalisé (1025–65535)
5. Hostname de la machine


## Actions Post-Installation

> ⚠️ **Ne fermez pas votre session actuelle avant d'avoir testé la connexion.**

```bash
# Depuis un NOUVEAU terminal sur votre poste local
ssh -p VOTRE_PORT VOTRE_USER@IP_DU_SERVEUR

# Si la connexion fonctionne, finalisez depuis la session d'origine
systemctl restart sshd && reboot
```


## Commandes de référence post-déploiement

```bash
# Audit de conformité complet
sudo lynis audit system

# Vérifier l'intégrité des fichiers (AIDE)
sudo aide --check

# Consulter les exécutions root auditées
sudo ausearch -k root_exec

# Status Fail2Ban
sudo fail2ban-client status sshd

# Débloquer une IP bannie
sudo fail2ban-client set sshd unbanip <IP>

# Voir les règles firewall actives
sudo firewall-cmd --list-all --zone=drop
```

## Compatibilité

| Critère | Valeur |
|---|---|
| **OS** | Rocky Linux 9, AlmaLinux 9, RHEL 9 |
| **Architecture** | x86_64 |
| **Environnement** | VPS (OVH, Hetzner, AWS, DigitalOcean…), Bare Metal, VM |


## Avertissement

Ce script modifie profondément la configuration système, réseau et de sécurité. Testez-le dans un environnement de staging avant tout déploiement en production. L'auteur décline toute responsabilité en cas de perte d'accès ou de dysfonctionnement suite à une utilisation incorrecte.


*Project Citadel — by [4b75726169736859](https://github.com/4b75726169736859)*