# CITADEL - v3.0

> **Ultra Hardening Framework - Rocky Linux 9 / RHEL 9 / AlmaLinux 9**

##  CHANGELOG v3.0 (vs v2.0 ):
>SÉCURITÉ
>+ SSH: algorithmes crypto modernes uniquement (ChaCha20/AES-GCM/ed25519)
>+ SSH: bannière légale + AllowUsers strict + MaxStartups + TCPKeepAlive
>+ Kernel: SMEP/SMAP/KPTI/Spectre mitigations via sysctl
>+ Kernel: désactivation modules dangereux (usb-storage, firewire, cramfs...)
>+ PAM: faillock, umask 027, su restreint au groupe wheel
>+ Sudo: logfile dédié, timeout 5 min, NOPASSWD interdit
>+ Auditd: 30+ règles (CIS Level 2, PCI-DSS, STIG)
>+ Syslog: forwarding vers fichier sécurisé + rotation
>+ GRUB: mot de passe hash bcrypt + timeout 3s
>+ Chronyd: NTP sécurisé multi-sources
>+ Systemd: services inutiles désactivés (38 services)
>+ Réseau: IPv6 désactivé sauf si explicitement demandé
>+ /tmp: monté noexec,nosuid,nodev
>+ /proc: hidepid=2 (isolation des processus)
>+ Sécurisation /etc/sysconfig/network scripts
>+ ClamAV installé + scan quotidien
>+ Tripwire/AIDE: baseline + vérif hebdo + alertes
>+ rkhunter: check quotidien + mise à jour
#
>MONITORING & LOGS
>+ MOTD enrichi: CPU, RAM, disque, derniers logins, IP
>+ Journald: persistent storage + compression
>+ Logwatch: rapport quotidien par email
>+ Rapport HTML post-install généré localement
>+ Colorisation complète des outputs
#
>UX & ROBUSTESSE
>+ Menu interactif multi-phases avec progression
>+ --dry-run amélioré (preview complet)
>+ --check-only: audit sans modification
>+ --restore: restauration depuis backup
>+ Backup automatique de TOUS les fichiers modifiés
>+ Détection distro/version automatique
>+ Validation stricte de tous les inputs (regex + range)
>+ Gestion d'erreurs: rollback automatique sur échec critique
>+ Idempotence totale (relançable sans casse)
>+ Rapport final JSON + HTML + texte
>+ Estimation durée + barre de progression ASCII

## Présentation

**Project CITADEL** est un tools de hardening Bash pour Rocky Linux 9, RHEL 9 et AlmaLinux 9. En une seule exécution interactive, il transforme une installation minimale en serveur de production durci, auditable et conforme aux standards **CIS Benchmark Level 2**, **PCI-DSS** et **STIG**.

La v3.0 est une réécriture complète :

- nftables natif
- crypto SSH moderne uniquement
- 35+ règles auditd
- ClamAV, AIDE enrichi
- sysctl étendu avec mitigations Spectre/Meltdown
- montages sécurisés

et bien plus.


## Démarrage rapide

```bash
# 1. Télécharger
curl -O https://raw.githubusercontent.com/4b75726169736859/CITADEL/main/citadel.sh

# 2. Rendre exécutable
chmod +x citadel.sh

# 3. Simuler sans modifier le système
sudo ./citadel.sh --dry-run

# 4. Déployer
sudo ./citadel.sh
```


## Options

| Option | Description |
|---|---|
| *(aucune)* | Hardening complet interactif |
| `--dry-run` | Simulation complète - aucune modification appliquée |
| `--check-only` | Audit du système avec score de sécurité - aucune modification |
| `--restore` | Restaure tous les fichiers depuis les backups CITADEL |
| `--enable-ipv6` | Conserve IPv6 activé (désactivé par défaut) |
| `--verbose` | Affiche chaque commande exécutée |
| `--help` | Affiche l'aide |


## Ce que fait CITADEL

### Système & Maintenance

| Élément | Détail |
|---|---|
| Pré-checks | Détection distro/version, espace disque, RAM, connectivité |
| Dépôts | CRB + EPEL activés automatiquement |
| Mise à jour | Full upgrade + `dnf-automatic` (security only, email si configuré) |
| Swap | Création automatique 2 Go si absent |
| Backup | Sauvegarde horodatée de **tous** les fichiers modifiés avant toute action |
| Lock file | Prévention des exécutions parallèles |
| Idempotence | Relançable sans casser une configuration existante |


### Hardening Noyau

**Sysctl (CIS Level 2) :**
- ASLR maximum (`kernel.randomize_va_space = 2`)
- BPF non-privilégié désactivé (`kernel.unprivileged_bpf_disabled = 1`)
- BPF JIT hardening (`net.core.bpf_jit_harden = 2`)
- Yama ptrace scope (`kernel.yama.ptrace_scope = 1`)
- `kernel.kptr_restrict = 2` - pointeurs kernel masqués dans `/proc`
- `kernel.dmesg_restrict = 1` - `dmesg` réservé à root
- `kernel.perf_event_paranoid = 3` - info-leak via perf bloqué
- Core dumps désactivés (`fs.suid_dumpable = 0`, `kernel.core_pattern = |/bin/false`)
- Hardlinks/symlinks protégés + fifos/regular protégés
- Anti-spoofing, anti-MITM, anti-SYN Flood, log des paquets Martiens
- TCP timestamps désactivés (fingerprinting)
- `kernel.sysrq = 4` (reboot sécurisé uniquement)

**Mitigations CPU (GRUB) :**
`pti=on spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off`

**Modules désactivés (~25) :**
- Systèmes de fichiers inutiles : `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `squashfs`
- Protocoles legacy : `dccp`, `sctp`, `rds`, `tipc`, `ax25`, `x25`, `atm`, `appletalk`, `ipx`...
- Hardware non nécessaire : `usb-storage`, `firewire-*`, `bluetooth`, `bnep`


### Montages Sécurisés

| Point de montage | Options |
|---|---|
| `/tmp` | `tmpfs`, `noexec`, `nosuid`, `nodev`, `size=1G` |
| `/dev/shm` | `noexec`, `nosuid`, `nodev` |
| `/proc` | `hidepid=2` - chaque utilisateur ne voit que ses propres processus |


### SELinux

- Forcé en mode `Enforcing` + type `targeted`
- Boolean `deny_ptrace` activé
- Booleans dangereux désactivés (`httpd_execmem`, etc.)
- Contexte SELinux ajusté pour le port SSH personnalisé via `semanage`


### Utilisateurs & Authentification

**PAM / pwquality :**
- Longueur minimale : 14 caractères
- 4 types de caractères obligatoires (maj, min, chiffre, spécial)
- Faillock : verrouillage après 5 échecs, déverrouillage après 30 minutes
- `umask 027` appliqué globalement
- `su` restreint au groupe `wheel`
- Timeout sessions inactives : 10 minutes (`TMOUT=600` en `readonly`)
- Comptes système inutilisés verrouillés (`games`, `news`, `uucp`...)

**Sudo :**
- Log de toutes les commandes (`/var/log/sudo.log`)
- Timeout d'authentification : 5 minutes
- TTY obligatoire (bloque l'exécution depuis des scripts non interactifs)
- Variables d'environnement dangereuses purgées (`LD_PRELOAD`, `LD_LIBRARY_PATH`...)
- `visudo -c` vérifié avant application


### SSH Fortress

| Paramètre | Valeur |
|---|---|
| `Port` | Configurable (1025–65535, validé) |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` si clé fournie |
| `MaxAuthTries` | `3` |
| `MaxStartups` | `3:50:10` |
| `LoginGraceTime` | `30s` |
| `ClientAliveInterval` | `300` (kick après 10 min d'inactivité) |
| `X11Forwarding` | `no` |
| `AllowTcpForwarding` | `no` |
| `AllowAgentForwarding` | `no` |
| `PermitTunnel` | `no` |
| `Compression` | `no` |

**Crypto moderne uniquement :**
- Échanges de clés : `curve25519-sha256`, `ecdh-sha2-nistp521`, `diffie-hellman-group18-sha512`
- Chiffrements : `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`, `aes256-ctr`
- MACs : `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm`
- Clés hôtes régénérées : DSA et ECDSA supprimés, ed25519 + RSA 4096 uniquement

**Extras :**
- Bannière légale pre-auth (`/etc/ssh/citadel-banner`)
- MOTD dynamique post-auth : hostname, date, uptime, RAM, disque, IP, sessions, alerte MAJ
- `sshd -t` validé avant tout redémarrage - restauration automatique si config invalide


### Firewall - nftables

Remplacement de `firewalld` par **nftables natif** pour plus de granularité et de performance.

- **Policy par défaut : `drop`** - tout paquet non matché est ignoré silencieusement
- Seul le port SSH configuré est ouvert
- **Rate-limit SSH** : set dynamique nftables, max 5 nouvelles connexions/minute/IP
- **Set `banned_ips`** : blocage manuel ou automatique d'adresses IP
- ICMP limité à 5 paquets/seconde (anti-flood)
- Règles persistantes au reboot via `systemctl enable nftables`

**Fail2Ban :**
- Backend `nftables-multiport`
- Ban SSH : 24 heures, mode agressif, max 3 tentatives en 1 heure


### Auditd - 35+ règles (CIS L2 / PCI-DSS / STIG)

| Catégorie | Fichiers/Appels surveillés |
|---|---|
| Identité | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `nsswitch.conf` |
| Authentification | `faillog`, `lastlog`, `wtmp`, `btmp`, `faillock/` |
| Sudo & privilèges | `/etc/sudoers`, `setuid`, `setgid`, `setresuid`, `setresgid` |
| SSH | `/etc/ssh/sshd_config`, `/root/.ssh/` |
| Crontabs | Tous les répertoires `cron.*`, `/var/spool/cron`, `anacrontab` |
| Démarrage | `/etc/rc.d/`, `/etc/systemd/system/`, `/usr/lib/systemd/` |
| Modules noyau | `insmod`, `rmmod`, `modprobe`, `init_module`, `delete_module` |
| Appels dangereux | `ptrace`, `chmod` setuid/setgid, `chown`, `unlink`, `rename` |
| Exécutions root | `execve` avec `euid=0` (b32 + b64) |
| Réseau | `socket`, `bind`, `connect` |
| Config système | `pam.d/`, `security/`, `audit/`, `resolv.conf`, `ld.so.conf` |

Les règles sont rendues **immuables** (`-e 2`) - un reboot est requis pour les modifier.


### Services Désactivés (~22)

`avahi-daemon`, `cups`, `bluetooth`, `rpcbind`, `nfs-server`, `vsftpd`, `telnet`, `tftp`, `xinetd`, `snmpd`, `sendmail`, `wpa_supplicant`, `ModemManager`, `libvirtd`, `geoclue`, `iscsid`...


### IDS & Antivirus

**AIDE :**
- Surveillance complète de `/bin`, `/sbin`, `/usr`, `/etc`, `/boot` avec SHA256 + SHA512 + SELinux context + ACL
- Vérification hebdomadaire automatique (lundi 3h00)
- Mise à jour mensuelle de la base (1er du mois 4h00)

**rkhunter :**
- Mise à jour des signatures à l'installation
- Check quotidien automatique (2h30) avec rapport sur les anomalies uniquement

**ClamAV :**
- Mise à jour des définitions 2x par jour
- Scan quotidien de `/home`, `/tmp`, `/var/tmp` (1h00)


### Journaux & Monitoring

**Journald :**
- Stockage persistant, compressé, scellé (`Seal=yes`)
- Rétention 1 an, rotation à 50 Mo par fichier, max 500 Mo total
- `Audit=yes`

**Logwatch :**
- Rapport HTML quotidien à 7h00 envoyé par email (si configuré)

**NTP (Chrony) :**
- Sources multiples : `fr.pool.ntp.org` (x3) + Cloudflare NTS + Google
- Authentification activée, accès restreint à localhost


### Environnement Administrateur

```bash
# Monitoring
alias sys        # btop
alias io         # iotop
alias mem        # free -h
alias disk       # df -h

# Réseau & sécurité
alias ports      # ss -tulnp
alias connections  # connexions établies
alias fw         # nft list ruleset
alias f2b-ssh    # fail2ban-client status sshd

# Logs
alias auth-log   # tail -f /var/log/secure
alias audit-log  # tail -f /var/log/audit/audit.log

# Audits rapides
alias checksec   # rkhunter --check
alias audit      # lynis audit system
alias aide-check # aide --check
alias cve-check  # dnf updateinfo list security
```

Historique Bash : 50 000 lignes, horodaté, sans doublons, sauvegardé après chaque commande. Umask 027, core dumps désactivés, timeout shell 10 minutes.


## Mode `--check-only`

Lance un audit rapide (25 vérifications) sans modifier le système et affiche un score :

```
  ✓ SELinux en mode Enforcing
  ✓ Fail2Ban actif
  ✓ ASLR activé (=2)
  ✓ BPF non-privilégié désactivé
  ✓ Yama ptrace scope >= 1
  ✗ Base AIDE existante
  ...

  Score CITADEL : 23/25 (92%)
  Excellent ! Le système est bien sécurisé.
```


## Rapport final

À chaque exécution, CITADEL génère un rapport complet dans `/var/log/citadel_reports/` :
- Récapitulatif de tous les paramètres appliqués
- Liste des fichiers modifiés et leurs backups
- Compteur de modifications / avertissements / erreurs
- Commandes post-installation à exécuter


## Actions post-installation

> ⚠️ **Ne fermez pas votre session actuelle avant d'avoir testé SSH.**

```bash
# Depuis un NOUVEAU terminal
ssh -p VOTRE_PORT VOTRE_USER@IP_DU_SERVEUR

# Si OK - rebooter pour appliquer tous les changements
sudo reboot

# Après reboot - vérifier SELinux
getenforce

# Audit de conformité complet
sudo lynis audit system
```


## Commandes de référence

```bash
# Audit
sudo lynis audit system
sudo aide --check
sudo rkhunter --check --sk
sudo ausearch -k root_exec | tail -50

# Firewall
sudo nft list ruleset
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <IP>

# Logs
sudo journalctl -u sshd -f
sudo tail -f /var/log/secure
sudo tail -f /var/log/audit/audit.log

# Mises à jour sécurité
sudo dnf updateinfo list security
sudo dnf update --security -y

# Restaurer les fichiers originaux
sudo ./citadel.sh --restore
```


## Compatibilité

| Critère | Valeur |
|---|---|
| OS | Rocky Linux 9, AlmaLinux 9, RHEL 9 |
| Architecture | x86_64 |
| Environnement | VPS (OVH, Hetzner, AWS, DigitalOcean...), Bare Metal, VM |
| Standards | CIS Benchmark Level 2, PCI-DSS, STIG |


## Avertissement

Ce script modifie profondément la configuration système, réseau et de sécurité. Testez-le dans un environnement de staging avant tout déploiement en production. L'auteur décline toute responsabilité en cas de perte d'accès ou de dysfonctionnement suite à une utilisation incorrecte.


*Project CITADEL v3.0 - by [4b75726169736859](https://github.com/4b75726169736859)*
