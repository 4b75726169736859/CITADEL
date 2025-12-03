# Project Vanguard: Rocky Linux 9 Hardening Suite

![Platform](https://img.shields.io/badge/Platform-Rocky%20Linux%209-green)
![Bash](https://img.shields.io/badge/Language-Bash-blue)
![Security](https://img.shields.io/badge/Security-Hardened-red)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

**Vanguard** est un script de déploiement et de sécurisation automatisé pour serveurs RHEL 9 / Rocky Linux. Il transforme une installation minimale (type VPS OVH) en un serveur de production sécurisé, auditable et prêt pour la conteneurisation.

## Fonctionnalités Clés

### Sécurité & Hardening
* **SSH Blindé :** Port personnalisé, Root login désactivé, Bannière légale, SELinux context aware.
* **Défense Active :** Fail2Ban (Bantime 24h), Firewalld configuré (Zones strictes).
* **Intrusion Detection :** AIDE (File Integrity), RKHunter, Auditd (Règles strictes).
* **Kernel Tuning :** Protection contre IP Spoofing, MITM, SYN Flood, ICMP Redirects.

### Optimisation Docker
* Chargement préventif des modules noyau (`overlay`, `br_netfilter`, `iptable_nat`).
* Correction automatique du conflit Firewalld/Docker (Masquerading activé).
* Paramétrage `sysctl` pour le forwarding IPv4.

### Système & Qualité de Vie
* **Dépôts :** Activation automatique CRB (CodeReady Builder) et EPEL.
* **Gestion Swap :** Création automatique de Swap file (2Go) pour éviter l'OOM Killer.
* **Maintenance :** `dnf-automatic` configuré pour les mises à jour de sécurité.
* **UX :** Prompt Bash personnalisé, Alias admin, Outils pré-installés (`btop`, `ncdu`, `tree`).

## Installation

```bash
# 1. Télécharger le script
wget [https://raw.githubusercontent.com/TON_USER/TON_REPO/main/vanguard_setup.sh](https://raw.githubusercontent.com/TON_USER/TON_REPO/main/vanguard_setup.sh)

# 2. Rendre exécutable
chmod +x vanguard_setup.sh

# 3. Lancer en root
./vanguard_setup.sh
