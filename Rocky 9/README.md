# CITADEL - v4.0

> **Ultra Hardening Framework - Rocky Linux 9 / RHEL 9 / AlmaLinux 9**

## CHANGELOG v4.0 (vs v3.0)

### Nouvelles phases de hardening (+11)

> **USB & accès physique**
> + USBGuard : whitelist des périphériques USB présents à l'install, blocage des nouveaux branchements (anti-BadUSB / rubber-ducky)
> + IOMMU forcé (Intel/AMD) au boot - mitigation DMA attacks via Thunderbolt/FireWire
> + Désactivation de kdump (crash dumps = secrets mémoire en clair)

> **Traçabilité totale**
> + Process accounting (psacct) : toutes les commandes exécutées sont historisées (`lastcomm`, `sa`)
> + Session recording optionnel via **tlog** : toutes les sessions des comptes wheel sont enregistrées dans journald, rejouables (`--enable-tlog`)
> + PAM tty_audit : audit des TTY pour root et l'admin

> **Intégrité & immuabilité**
> + `chattr +i` sur les fichiers critiques (passwd, shadow, sudoers, sshd_config, sysctl, pwquality…)
> + Wrapper `citadel-edit` pour éditer un fichier immuable sans avoir à faire le `chattr -i / +i` manuellement
> + Vérification de signature des modules noyau (`module.sig_enforce=1`)
> + Kernel lockdown mode `integrity` activé via cmdline (`--no-lockdown` pour désactiver)

> **Réseau renforcé**
> + Firewall nftables **IPv4 + IPv6 séparés** (deux tables distinctes, policy DROP sur les deux)
> + DNS over TLS via systemd-resolved - Cloudflare (1.1.1.1) + Quad9 (9.9.9.9) + DNSSEC strict
> + Port-knocking optionnel (knockd, séquence aléatoire générée) via `--enable-knockd`
> + Whitelist d'IP admin dans le firewall (bypass rate-limit SSH)
> + Règles anti-spoofing IPv6 strictes + ICMPv6 filtré

> **Systemd sandboxing**
> + Drop-ins hardening sur sshd, auditd, chronyd, fail2ban, nftables
> + `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`
> + Score `systemd-analyze security` visiblement amélioré post-install

> **Conformité & audit**
> + Intégration OpenSCAP : scan automatique post-install selon le profil choisi (CIS / ANSSI BP-028 / STIG)
> + Scan mensuel planifié (cron, rapport HTML mensuel dans `/var/log/citadel_reports/`)
> + Bannières légales sur /etc/issue, issue.net et motd (références Loi Godfrain art. 323-1)
> + Nouvelles règles auditd : mount/umount, time_change, access_denied, rename, renameat → **~50 règles au total** (vs 35 en v3)

> **Sauvegarde & reprise**
> + Snapshot LVM automatique avant installation (si root est sur LVM et VG ≥ 2 Go libres)
> + State DB (`/etc/citadel/state.db`) : chaque modification est tracée pour permettre un revert fin
> + Mode `--uninstall` : annule toutes les modifications CITADEL en replaçant les backups, en retirant les `chattr +i`, en nettoyant les drop-ins systemd et en retirant les cron.d
> + Mode `--self-test` : suite de tests unitaires (syntaxe bash, fonctions critiques, binaires requis, validation nftables stub)

### Nouveaux modes & options

> + `--compliance=cis|anssi|stig` - profil de conformité (active automatiquement les mitigations L1TF/MDS et `nosmt` pour anssi/stig)
> + `--phases=base,ssh,firewall` - exécution sélective, exécuter seulement certaines phases (ex. relancer juste le firewall après un changement)
> + `--uninstall` - désinstallation complète basée sur la state DB
> + `--self-test` - tests unitaires avant déploiement
> + `--enable-tlog` - session recording pour les comptes wheel
> + `--enable-knockd` - port-knocking SSH
> + `--no-usbguard` - désactive USBGuard (utile en container)
> + `--no-lockdown` - désactive kernel lockdown (utile sur matériel qui nécessite des drivers non signés)
> + `--skip-snapshot` - ne crée pas le snapshot LVM

### UX

> + Estimation de durée par phase affichée avant la confirmation finale
> + Progression globale avec numéro de phase (`[23/26]`) dans chaque section
> + Rapport triple désormais : **TXT + JSON (parsable) + HTML stylé** (dégradés, cards, badges, responsive)
> + `--check-only` étendu à **~60 vérifications** (vs 25 en v3), groupées par catégorie : kernel, network, auth, services, files, audit - chaque catégorie a son score
> + Lynis est désormais exécuté automatiquement après l'install et son rapport est inclus dans le rapport final

### Corrections de bugs v3

> + `systemctl list-unit-files` + `grep` : le `&>/dev/null` du milieu cassait le pipe → remplacé par une fonction `svc_exists()` propre
> + nftables rate-limit SSH : la syntaxe `set + add + timeout` était invalide → corrigée via `meter` (règle en une seule passe)
> + `Defaults !shell_noesc` dans sudoers : option inexistante → retirée
> + `Defaults log_year, loglinelen=0` dans sudoers : syntaxe douteuse → retirée
> + `sed 's/emit_via = stdio/emit_via = stdio/'` dans dnf-automatic : no-op → corrigé pour basculer en `email` si `ADMIN_EMAIL` défini
> + MOTD : `dnf check-update --security` était appelé à chaque login (plusieurs secondes de lag + hit repo inutile) → remplacé par lecture du journal local + statut fail2ban
> + SSH host key regen : heredoc `<<< y` bancal → remplacé par un check `[ ! -f ]` avant ssh-keygen
> + Restauration SSH config : glob dans guillemets pouvait ne rien matcher → utilisation de `ls -t | head -1`
> + faillock : ajout manquant de `even_deny_root` + `root_unlock_time` (sinon root peut bruteforce indéfiniment)
> + `/proc hidepid=2` → `hidepid=invisible` (nom canonique moderne, Linux 5.8+)
> + Gestion du lock file : détection des locks orphelins (PID mort) avec nettoyage automatique

## Présentation

**Project CITADEL** est un framework de hardening Bash pour Rocky Linux 9, RHEL 9 et AlmaLinux 9. En une exécution interactive, il transforme une installation minimale en un serveur de production durci, auditable, conforme **CIS Benchmark Level 2**, **ANSSI BP-028**, **PCI-DSS** et **STIG**.

La v4.0 pousse encore plus loin :

- Firewall **nftables dual-stack** (v4 + v6), DNS over TLS, port-knocking optionnel
- Protection physique : USBGuard, IOMMU, kdump off
- Immuabilité : `chattr +i` sur les fichiers critiques + wrapper d'édition
- Systemd hardening : drop-ins sandbox sur les démons critiques
- Scan OpenSCAP automatique avec profil CIS/ANSSI/STIG
- Triple rapport TXT/JSON/HTML + state DB pour désinstallation propre
- **~4000 lignes** de bash propre, 26 phases distinctes, 6 modes d'exécution

## Démarrage rapide

```bash
# Télécharger
curl -O https://raw.githubusercontent.com/4b75726169736859/CITADEL/main/citadel.sh
chmod +x citadel.sh

# Valider l'environnement avant tout
sudo ./citadel.sh --self-test

# Audit du système actuel sans rien modifier
sudo ./citadel.sh --check-only

# Simulation complète
sudo ./citadel.sh --dry-run

# Déploiement réel
sudo ./citadel.sh

# Déploiement avec profil ANSSI + session recording
sudo ./citadel.sh --compliance=anssi --enable-tlog

# Ré-appliquer juste certaines phases (ex. après un changement manuel)
sudo ./citadel.sh --phases=ssh,firewall,auditd
```

## Options

| Option | Description |
|---|---|
| *(aucune)* | Hardening complet interactif |
| `--dry-run` | Simulation complète, aucune modification appliquée |
| `--check-only` | Audit ~60 contrôles avec score par catégorie |
| `--self-test` | Tests unitaires du script (syntaxe, binaires, fonctions) |
| `--restore` | Restauration interactive depuis les backups (tout ou sélection) |
| `--uninstall` | Annule toutes les modifications CITADEL via la state DB |
| `--compliance=<prof>` | Profil de conformité : `cis` (défaut), `anssi`, `stig` |
| `--phases=<csv>` | Exécute uniquement les phases listées (voir liste ci-dessous) |
| `--skip-snapshot` | Ne pas créer de snapshot LVM pré-install |
| `--enable-ipv6` | Conserve IPv6 (firewall IPv6 sera configuré) |
| `--enable-tlog` | Session recording pour wheel (enregistrement dans journald) |
| `--enable-knockd` | Port-knocking SSH (séquence aléatoire générée) |
| `--no-usbguard` | Désactive USBGuard (pertinent en conteneur) |
| `--no-lockdown` | N'active pas kernel lockdown=integrity |
| `--skip-reboot` | N'affiche pas l'avertissement reboot à la fin |
| `--verbose` | Affiche chaque commande exécutée |
| `--help` | Affiche l'aide |

**Phases disponibles pour `--phases=` :**
`base`, `kernel`, `mounts`, `selinux`, `users`, `ssh`, `firewall`, `auditd`, `services`, `aide`, `rkhunter`, `clamav`, `grub`, `syslog`, `userenv`, `usbguard`, `psacct`, `immutable`, `banners`, `cron`, `chage`, `kdump`, `sandbox`, `tlog`, `dns`, `openscap`

## Profils de conformité

| Profil | Comportement |
|---|---|
| `cis` *(défaut)* | CIS Benchmark Level 2 - équilibre sécurité/perf |
| `anssi` | ANSSI BP-028 High - ajoute `l1tf=full,force`, `mds=full,nosmt`, `tsx=off`, `nosmt` (désactive SMT/Hyperthreading, perte perf notable) |
| `stig` | DISA STIG - mêmes mitigations agressives qu'anssi, scan SCAP avec profil stig |

Le profil choisi impacte :
- Les options GRUB (mitigations CPU)
- Le profil OpenSCAP utilisé pour le scan post-install et les scans mensuels
- Certaines règles auditd plus strictes

## Ce que fait CITADEL

### Système & maintenance

| Élément | Détail |
|---|---|
| Pré-checks | Distro/version, espace disque, RAM, connectivité, architecture, virtualisation détectée |
| Snapshot LVM | Automatique si root sur LVM (2 Go réservés, nommé `citadel_pre_<timestamp>`) |
| Dépôts | CRB/PowerTools + EPEL activés |
| Mise à jour | `dnf upgrade -y` + `dnf-automatic` (security uniquement, mail si configuré) |
| Swap | Création 2 Go si absent (`fallocate` + fallback `dd`) |
| Backup | Sauvegarde horodatée de tous les fichiers modifiés avant action |
| Lock | Détection des locks orphelins, anti-exécutions parallèles |
| State DB | `/etc/citadel/state.db` - permet `--uninstall` |
| Idempotence | Relançable sans casser la config existante |

### Hardening noyau

**Sysctl (~60 paramètres - CIS L2 + ANSSI-BP-028) :**

- ASLR max (`kernel.randomize_va_space = 2`), `kptr_restrict = 2`, `dmesg_restrict = 1`
- BPF non-privilégié désactivé + BPF JIT hardening
- Yama ptrace scope 1, perf_event_paranoid 3, kexec_load_disabled 1
- User namespaces non-privilégiés désactivés
- Core dumps off (suid_dumpable 0 + core_pattern vers `/bin/false`)
- Hardlinks/symlinks/fifos/regular protégés
- Anti-spoofing strict (rp_filter), ARP strict, anti-MITM
- TCP hardening : syncookies, rfc1337, timestamps off, tw_reuse, keepalive tuned
- IPv6 désactivé globalement si pas `--enable-ipv6`
- `vm.mmap_min_addr = 65536` (anti null-deref kernel exploit)

**Mitigations CPU (GRUB cmdline) :**

Base : `pti=on spectre_v2=on spec_store_bypass_disable=on init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none lockdown=integrity`

IOMMU auto-détecté (Intel ou AMD) : `intel_iommu=on iommu=force` ou `amd_iommu=on iommu=force`

Profils anssi/stig : ajout de `l1tf=full,force mds=full,nosmt tsx=off nosmt`

**Modules désactivés (~30) :**

- Filesystems inutiles : `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `squashfs`
- Protocoles legacy : `dccp`, `sctp`, `rds`, `tipc`, `ax25`, `x25`, `atm`, `appletalk`, `ipx`, `rose`, `decnet`…
- Hardware non nécessaire : `usb-storage`, `firewire-*`, `bluetooth`, `bnep`, `btusb`, `thunderbolt`

### Montages sécurisés

| Point de montage | Options |
|---|---|
| `/tmp` | `tmpfs`, `noexec`, `nosuid`, `nodev`, `size=1G`, `mode=1777` |
| `/dev/shm` | `noexec`, `nosuid`, `nodev` |
| `/var/tmp` | bind-mount sur `/tmp` (hérite des flags) |
| `/proc` | `hidepid=invisible`, `gid=proc` (admin dans le groupe proc) |

### SELinux

- Mode `Enforcing`, type `targeted`
- Booleans sécurité ON : `deny_ptrace`, `deny_execmem`, `secure_mode_insmod`
- Booleans dangereux OFF : `httpd_execmem`, `httpd_can_network_connect`, `allow_execheap`, `allow_execstack`, `ftp_home_dir`, `mount_anyfile`…
- Port SSH custom ajouté au type `ssh_port_t` via `semanage`
- Si SELinux est `Disabled` au kernel level : `.autorelabel` est créé pour relabel au prochain boot

### Utilisateurs & authentification

**pwquality :**

- Longueur mini 14, 4 classes obligatoires, max 3 répétitions, max 3 séquentiels
- `difok = 7`, `gecoscheck = 1`, `dictcheck = 1`, `enforce_for_root = 1`

**faillock :**

- 5 échecs → lock 30 min, fenêtre 15 min
- `even_deny_root = 1`, `root_unlock_time = 900`
- Activé via `authselect select sssd with-faillock --force`

**login.defs :**

- `UMASK 027`, `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 14`
- `ENCRYPT_METHOD SHA512`, `SHA_CRYPT_MIN_ROUNDS 10000`

**Password aging (chage) :**

Appliqué à tous les utilisateurs humains (UID ≥ 1000) : `-M 90 -m 7 -W 14 -I 30`

**PAM :**

- `su` restreint au groupe wheel (`pam_wheel.so use_uid`)
- `pam_tty_audit` pour root + admin (trace toutes les commandes TTY)
- Timeout shell 10 min via `readonly TMOUT=600` dans `/etc/profile.d/`
- Comptes système inutilisés verrouillés : `games`, `news`, `uucp`, `operator`, `gopher`, `ftp`, `halt`, `shutdown`, `sync`

**Sudo :**

- Log output + input (I/O logging dans `/var/log/sudo-io/`)
- Timeout 5 min, `requiretty`, `use_pty`, `lecture="always"`
- Variables d'environnement purgées : `LD_LIBRARY_PATH`, `LD_PRELOAD`, `PERL5LIB`, `PERL5OPT`, `PYTHONPATH`
- `secure_path` verrouillé
- Validation `visudo -cf` avant mise en place (rollback sinon)

**Cron & at :**

- `/etc/cron.allow` + `/etc/at.allow` restreints à root + admin
- `/etc/cron.deny` + `/etc/at.deny` supprimés (inutiles avec .allow)
- Permissions `0600` sur crontab, `0700` sur cron.{hourly,daily,weekly,monthly,d}

### SSH Fortress

| Paramètre | Valeur |
|---|---|
| `Port` | Configurable (1025–65535, validation + check port libre) |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` si clé fournie |
| `KbdInteractiveAuthentication` | `no` |
| `MaxAuthTries` | `3` |
| `MaxStartups` | `3:50:10` |
| `LoginGraceTime` | `30s` |
| `ClientAliveInterval` | `300` (kick après 10 min) |
| `X11Forwarding` / `AllowTcpForwarding` / `AllowAgentForwarding` | `no` |
| `PermitTunnel` / `GatewayPorts` / `PermitUserRC` | `no` |
| `Compression` | `no` |
| `RekeyLimit` | `512M 1h` |

**Crypto (compatible Mozilla modern + ANSSI - pas de courbes NIST) :**

- KEX : `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`
- Ciphers : `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`
- MACs : `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `umac-128-etm@openssh.com`
- HostKeys : `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256` (DSA/ECDSA supprimés)

**Extras :**

- Bannière légale pré-auth (`/etc/ssh/citadel-banner`, art. 323-1)
- MOTD dynamique post-auth : hostname, date, uptime, load, RAM, disque, IP, sessions, dernière connexion, alerte si >10 fails SSH sur 24h ou si fail2ban a des bannis
- `sshd -t` validé avant redémarrage, rollback automatique du backup si invalide
- `sshd -T` capturé dans `/etc/citadel/sshd-effective.conf` pour audit

### Firewall nftables (dual-stack)

Remplacement complet de firewalld par **nftables natif** avec deux tables séparées.

**Table `inet citadel_filter` (IPv4) :**

- Policy `input: drop`, `forward: drop`, `output: accept`
- Sets dynamiques :
  - `banned_ips` (IPs bannies, timeout 24h, alimenté par fail2ban + manuel)
  - `ssh_scanners` (scanners récents, timeout 10 min)
- Whitelist admin (si IPs fournies) : bypass du rate-limit
- ICMP limité (`5/second burst 10`)
- **Rate-limit SSH via meter** (corrigé de la syntaxe cassée en v3) : 5 nouvelles conn/min/IP, au-delà ajout dans `ssh_scanners` + drop
- Log drop final (`3/minute burst 5`)

**Table `ip6 citadel_filter6` (IPv6, si `--enable-ipv6`) :**

- ICMPv6 filtré (ND, RA, RS, echo, errors) - **critique pour IPv6**
- Rate-limit SSH identique
- Policy DROP

**Fail2ban :**

- Backend `nftables-multiport`
- Jails : `sshd` (ban 24h, aggressive), `sshd-ddos` (ban 10 min), `recidive` (ban 7 jours)
- Mail si `ADMIN_EMAIL` configuré (`action_mwl`)

**Port-knocking (si `--enable-knockd`) :**

- 3 ports aléatoires générés entre 10000-60000
- Séquence sauvegardée dans `/etc/citadel/knock-sequence.txt` (mode 0600)
- Action : ajout de l'IP source à `ssh_allowed` pour 1h

### Auditd - ~50 règles (CIS L2 + PCI-DSS + STIG + ANSSI)

| Catégorie | Fichiers / syscalls surveillés |
|---|---|
| Identité | `passwd`, `shadow`, `group`, `gshadow`, `opasswd`, `nsswitch.conf`, `pam.d/`, `security/` |
| Authentification | `faillog`, `lastlog`, `wtmp`, `btmp`, `faillock/` |
| Sudo & privilèges | `/etc/sudoers`, `/etc/sudoers.d/`, `setuid`, `setgid`, `setresuid`, `setresgid` (b32 + b64) |
| SSH | `/etc/ssh/sshd_config`, `/etc/ssh/`, `/root/.ssh/` |
| Planification | `cron.d/`, `cron.daily/`, `cron.hourly/`, `cron.monthly/`, `cron.weekly/`, `crontab`, `var/spool/cron/`, `anacrontab`, `systemd/system/`, `/usr/lib/systemd/system/` |
| Modules noyau | `insmod`, `rmmod`, `modprobe`, `init_module`, `delete_module`, `finit_module` |
| Syscalls dangereux | `ptrace` (avec filtre sur `a0`), `chmod`/`fchmod` setuid+setgid, `chown`/`fchown` |
| Suppressions user | `unlink`, `unlinkat`, `rename`, `renameat` (détection ransomware / evidence wiping) |
| Exécutions root | `execve` avec `euid=0` (b32 + b64) |
| Réseau | `sethostname`, `setdomainname`, `/etc/hosts`, `resolv.conf`, `network-scripts/`, `NetworkManager/` |
| SELinux | `/etc/selinux/`, `/usr/share/selinux/` |
| ldconfig / LD_PRELOAD | `ld.so.conf`, `ld.so.conf.d/`, `ld.so.preload` |
| Accès refusés | `open`, `openat`, `truncate`, `ftruncate` avec `exit=-EACCES` ou `exit=-EPERM` |
| Montages | `mount`, `umount2` |
| Changements de temps | `adjtimex`, `settimeofday`, `clock_settime`, `/etc/localtime` |

Règles marquées immuables (`-e 2`) - **reboot requis pour les modifier**.

Buffer `-b 32768`, `--backlog_wait_time 60000` pour éviter les pertes sous charge.

### Services désactivés (~25)

`avahi-daemon`, `avahi-daemon.socket`, `cups`, `cups.socket`, `cups-browsed`, `bluetooth`, `postfix`, `rpcbind`, `rpcbind.socket`, `nfs-server`, `rsyncd`, `telnet.socket`, `tftp.socket`, `xinetd`, `ypserv`, `ypbind`, `httpd`, `nginx`, `vsftpd`, `squid`, `snmpd`, `sendmail`, `wpa_supplicant`, `ModemManager`, `libvirtd`, `libvirtd.socket`, `spice-vdagentd`, `geoclue`, `iscsid`, `iscsid.socket`, `multipathd`, `firewalld`, `NetworkManager-wait-online`, `dnsmasq`, `exim`, `named`, `kdump`

Chaque service désactivé est : arrêté → disabled → **masqué** (rendu impossible à démarrer par dépendance accidentelle).

### Systemd service hardening

Drop-ins `/etc/systemd/system/<service>.service.d/citadel-hardening.conf` sur :

- `sshd`, `auditd`, `chronyd`, `fail2ban`, `nftables`

Restrictions appliquées :

```
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
```

Avec ajustements par service (ex. sshd a besoin d'ouvrir des PTY, auditd doit écrire dans /var/log/audit, nftables doit parler à netfilter).

Vérification du score : `systemd-analyze security sshd.service`

### USBGuard

- Policy générée depuis les périphériques connectés au moment de l'install (whitelist)
- `ImplicitPolicyTarget=block`, `InsertedDevicePolicy=apply-policy`
- Audit via `LinuxAudit` backend → logs dans `/var/log/usbguard/usbguard-audit.log`
- Groupe `wheel` autorisé à gérer les règles via IPC
- Désactivable avec `--no-usbguard` (utile en conteneur)

### Process accounting (psacct)

- Démarré et activé au boot
- Historique dans `/var/account/pacct`
- Commandes utiles : `lastcomm` (dernières commandes), `sa` (statistiques), `ac` (temps de connexion)

### Session recording (tlog - optionnel)

- Avec `--enable-tlog`, les membres de wheel (hors root) ont leur shell remplacé par `/usr/bin/tlog-rec-session`
- Sessions enregistrées dans journald (input, output, window)
- Recherche : `journalctl _COMM=tlog-rec-session`
- Lecture d'une session : `tlog-play -r journal -M TLOG_REC=<UUID>`

### DNS hardening

- systemd-resolved activé et configuré
- DNS over TLS : Cloudflare (1.1.1.1#cloudflare-dns.com, 1.0.0.1) + Quad9 (9.9.9.9#dns.quad9.net, 149.112.112.112)
- Fallback : 8.8.8.8 (Google)
- DNSSEC strict, DNSOverTLS strict, cache local actif
- `/etc/resolv.conf` → lien symbolique vers `/run/systemd/resolve/stub-resolv.conf`
- Backup de l'ancien resolv.conf dans `/etc/resolv.conf.pre-citadel`

### Fichiers immuables

`chattr +i` appliqué sur :

- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`
- `/etc/sudoers`
- `/etc/ssh/sshd_config`, `/etc/ssh/citadel-banner`
- `/etc/pam.d/su`, `/etc/pam.d/sudo`
- `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`
- `/etc/sysctl.d/99-citadel.conf`
- `/etc/modprobe.d/citadel-blacklist.conf`

Wrapper `/usr/local/sbin/citadel-edit <file>` pour éditer proprement (retire `+i`, édite, remet `+i`).

### Bannières légales

Déployées sur `/etc/issue` (console), `/etc/issue.net` (distant), `/etc/motd` (post-login) :

> Ce système est la propriété de son exploitant. Son accès est strictement réservé aux personnes explicitement autorisées. Toute connexion et toute action sur ce système sont consignées et peuvent être utilisées à des fins de contrôle, d'audit, de preuve judiciaire ou de poursuites pénales. Art. 323-1 à 323-3 du Code pénal (Loi Godfrain).

### IDS & antivirus

**AIDE :**

- Baseline SHA512 + SELinux context + ACL + xattrs + capabilities sur `/boot`, `/bin`, `/sbin`, `/usr`, `/etc`, `/opt`
- **Check quotidien** (4h, v4 : passé de hebdo à quotidien)
- Update mensuel de la baseline (1er du mois 5h)
- Mail de rapport si `ADMIN_EMAIL` configuré

**rkhunter :**

- Signatures à jour à l'install
- Check quotidien 2h30, `--report-warnings-only`
- Whitelist étendue pour réduire les faux positifs

**ClamAV :**

- Freshclam 2x/jour
- Scan quotidien 1h de `/home`, `/tmp`, `/var/tmp`, `/root` avec exclusion de `/proc`, `/sys`, `/dev`
- Log dans `/var/log/clamav_daily.log`

**OpenSCAP :**

- Scan post-install immédiat avec le profil choisi (`cis` / `anssi_bp28_high` / `stig`)
- Rapport HTML dans `/var/log/citadel_reports/openscap/scan-report.html`
- Scan mensuel planifié (1er du mois 6h)

### Journald & logs

- Stockage persistant (`/var/log/journal/`), compressé, scellé (`Seal=yes`)
- Rétention 1 an, 1 Go max, fichier 100 Mo max
- `ForwardToSyslog=yes`, `Audit=yes`, `ReadKMsg=yes`
- Permissions restrictives : `/var/log/secure` 0640, `/var/log/audit/audit.log` 0600

**Logwatch :**

- Rapport HTML quotidien 7h, par mail si configuré

**Logrotate CITADEL :**

- Rotation hebdo des logs CITADEL (install.log, sudo.log, aide, rkhunter, clamav, freshclam), 12 semaines de rétention

**NTP (chrony) :**

- Sources : `fr.pool.ntp.org` x3 + `time.cloudflare.com` en **NTS** (Network Time Security) + `time.nist.gov`
- `port 0` et `cmdport 0` : pas de service NTP exposé

### Environnement administrateur

**Historique bash :**

- 100 000 lignes, horodaté, sans doublons, flush après chaque commande
- Sauvegarde automatique du fichier d'historique

**Prompt :**

- Rouge vif pour root, vert pour user
- Affiche la branche git si on est dans un repo
- Exit code du dernier process affiché si ≠ 0

**Aliases (~60) :**

```bash
# Monitoring
sys        # btop
io         # iotop
mem        # free -h
disk       # df -hT
dush       # du -sh * | sort -rh | head -20

# Réseau & sécurité
ports      # ss -tulnp
conns      # connexions établies
myip       # curl ifconfig.me
fw         # nft list ruleset
fw-save    # nft list ruleset > /tmp/nft-<ts>.rules
f2b-ssh    # fail2ban-client status sshd
f2b-banned # IPs bannies
f2b-unban  # unban interactif

# Logs
logs       # journalctl -f
logs-boot  # journalctl -b
logs-ssh   # journalctl -u sshd -f
logs-auth  # tail -f /var/log/secure
logs-audit # tail -f /var/log/audit/audit.log
logs-sudo  # tail -f /var/log/sudo.log

# Security quick-audits
sec-check    # rkhunter --check --sk
sec-audit    # lynis audit system
sec-aide     # aide --check
sec-selinux  # sestatus && getenforce
sec-listening # ss -tulnp4
sec-cve      # dnf updateinfo list security
sec-fails    # lastb -10
sec-logins   # last -10
sec-who      # w + who --ips
sec-sudo     # ausearch -ts today -k sudoers
sec-root     # ausearch -ts today -k root_exec

# CITADEL
citadel         # lance /usr/local/sbin/citadel.sh
citadel-status  # --check-only
citadel-audit   # lynis + log daté
citadel-report  # liste des rapports

# Fonctions
extract <archive>  # détecte et extrait tous formats (tar/zip/7z/rar/xz/bz2/gz)
pskill <pattern>   # trouve + kill interactif
ssl-check <host:port>  # certificat SSL d'un host
```

## Mode `--check-only`

Audit lecture seule, **~60 vérifications** groupées en 6 catégories avec scores individuels :

```
─── Noyau & sysctl ───
  ✓ ASLR = 2
  ✓ kptr_restrict = 2
  ✓ BPF non-privilégié bloqué
  ...

─── Réseau ───
  ✓ rp_filter strict
  ✓ TCP syncookies actifs
  ✓ nftables policy DROP
  ...

─── Authentification ───
  ✓ SSH port non-standard
  ✓ PermitRootLogin no
  ✓ pwquality minlen >= 14
  ...

─── Services & démons ───
  ✓ SELinux Enforcing
  ✓ auditd actif
  ✓ usbguard actif
  ...

─── Fichiers & permissions ───
  ✓ /tmp noexec
  ✓ /etc/shadow immuable
  ...

─── Audit & détection ───
  ✓ Règles auditd chargées
  ✓ Audit immutable mode
  ...

═══════════════════════════════════════════════════════════════
  Score global CITADEL : 57/60 (95%)

  KERNEL     :  93% (14/15)
  NETWORK    : 100% (12/12)
  AUTH       :  92% (12/13)
  SERVICES   : 100% (10/10)
  FILES      : 100% (9/9)
  AUDIT      : 100% (10/10)

  ✓  Système correctement durci.
```

## Rapports

À chaque exécution, CITADEL génère dans `/var/log/citadel_reports/` :

- **`citadel_report_<ts>.txt`** - récapitulatif texte complet (config appliquée, modifications, backups, actions post-install, commandes utiles)
- **`citadel_report_<ts>.json`** - parsable pour automatisation / intégration SIEM
- **`citadel_report_<ts>.html`** - rapport HTML stylé (dégradés sombres, cards, tableaux, badges colorés par statut)
- **`openscap/scan-report.html`** - rapport OpenSCAP du scan post-install

## Désinstallation

```bash
sudo ./citadel.sh --uninstall
```

- Lit `/etc/citadel/state.db`
- Retire les `chattr +i` sur les fichiers protégés
- Restaure tous les backups dans l'ordre (plus récent en premier)
- Supprime les fichiers créés par CITADEL (sudoers.d, sysctl.d, cron.d, drop-ins systemd, nftables, etc.)
- Nettoie les entrées GRUB CITADEL et régénère grub.cfg
- Propose de réactiver firewalld
- Le répertoire `/etc/citadel/` et les backups sont **conservés** (pour un éventuel re-rollback)
- Reboot fortement recommandé après

## Actions post-installation

> ⚠️ **Ne fermez pas votre session actuelle avant d'avoir testé SSH depuis une autre.**

```bash
# Depuis un NOUVEAU terminal - vérifier que SSH fonctionne
ssh -p <PORT> <USER>@<IP>

# Si OK - rebooter (nécessaire pour GRUB, /proc, SELinux relabel si fait)
sudo reboot

# Post-reboot - vérifier l'état
getenforce                       # doit dire Enforcing
sudo citadel-status              # audit rapide
sudo lynis audit system          # audit de conformité complet
sudo systemd-analyze security    # score de hardening des services
```

## Commandes de référence

```bash
# Audit
sudo citadel-status                         # check-only rapide
sudo lynis audit system                     # audit complet
sudo aide --check                           # intégrité fichiers
sudo rkhunter --check --sk                  # rootkits
sudo oscap xccdf eval --profile cis ...     # SCAP compliance
sudo ausearch -k root_exec | tail -50       # exécutions root
sudo lastcomm                               # dernières commandes (psacct)
sudo sa                                     # stats commandes par user

# Firewall
sudo nft list ruleset
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <IP>

# USB
sudo usbguard list-devices
sudo usbguard allow-device <id>

# Logs
sudo journalctl -u sshd -f
sudo tail -f /var/log/secure
sudo tail -f /var/log/audit/audit.log
sudo journalctl _COMM=tlog-rec-session      # sessions enregistrées

# Fichiers immuables
lsattr /etc/shadow                          # vérifier +i
sudo citadel-edit /etc/ssh/sshd_config      # éditer proprement

# Mises à jour sécurité
sudo dnf updateinfo list security
sudo dnf update --security -y

# Restaurer / désinstaller
sudo ./citadel.sh --restore
sudo ./citadel.sh --uninstall
```

## Compatibilité

| Critère | Valeur |
|---|---|
| OS | Rocky Linux 9, AlmaLinux 9, RHEL 9 (Oracle Linux 9 expérimental) |
| Architecture | x86_64, aarch64 (testé x86_64) |
| Environnement | VPS (OVH, Hetzner, AWS, DigitalOcean, Scaleway…), Bare Metal, VM KVM/VMware, conteneur (avec `--no-usbguard --no-lockdown`) |
| Standards | CIS Benchmark Level 2, ANSSI BP-028, PCI-DSS, STIG |
| Taille | ~4000 lignes bash / 26 phases / 6 modes d'exécution |

## Avertissement

Ce script modifie profondément la configuration système, réseau, noyau et de sécurité. Un certain nombre de modifications sont **immuables** par défaut (règles auditd, `chattr +i`) et nécessitent un reboot pour être annulées.

**Testez en environnement de staging avant tout déploiement en production.** Utilisez `--dry-run` puis `--check-only` avant la première installation réelle. Conservez toujours une session SSH ouverte et un accès console de secours pendant la première exécution.

L'auteur décline toute responsabilité en cas de perte d'accès, d'indisponibilité ou de dysfonctionnement suite à une utilisation incorrecte.


*Project CITADEL v4.0 - by [4b75726169736859](https://github.com/4b75726169736859)*