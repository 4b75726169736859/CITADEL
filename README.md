# Project Citadel

**Project Citadel** est une suite d'automatisation en Bash conçue pour le durcissement (hardening) et la préparation de serveurs Rocky Linux 9 et RHEL 9.

Ce script transforme une installation minimale en un serveur de production sécurisé, auditable et optimisé pour le réseau. Il prépare également le système pour une éventuelle conteneurisation future (Docker/Podman) ou des services VPN en configurant le noyau et le pare-feu en amont, sans installer de paquets superflus.

## Objectifs

L'objectif de Citadel est de fournir un socle de base universel et sécurisé pour tout type de déploiement (Web, Base de données, Applicatif) sur des infrastructures VPS (OVH, Hetzner, AWS, etc.).

## Fonctionnalités

### 1. Système et Maintenance
* **Identité :** Configuration du hostname et de la timezone (Europe/Paris).
* **Dépôts :** Activation automatique des dépôts CRB (CodeReady Builder) et EPEL pour l'accès aux outils d'administration avancés.
* **Mises à jour :** Mise à jour complète du système et configuration de `dnf-automatic` pour l'application automatique des correctifs de sécurité.
* **Swap :** Détection et création intelligente d'un fichier Swap de 2 Go si aucun swap n'est présent (protection contre l'OOM Killer).

### 2. Contrôle d'Accès et Identité
* **Gestion Utilisateur :** Assistant interactif pour la création d'un administrateur dédié ou l'élévation d'un utilisateur existant.
* **Privilèges :** Configuration du groupe `wheel` pour l'accès sudo.

### 3. Sécurisation SSH (Hardening)
* **Port :** Changement du port d'écoute par défaut (configurable).
* **Root :** Désactivation totale de la connexion directe en root (`PermitRootLogin no`).
* **Paramètres :** Désactivation du X11 Forwarding, limitation des tentatives d'authentification (`MaxAuthTries 3`).
* **Légal :** Mise en place d'une bannière de connexion légale (`/etc/issue.net`).
* **SELinux :** Configuration automatique du contexte SELinux pour autoriser le port SSH personnalisé.

### 4. Défense Réseau et Noyau
* **Firewalld :**
    * Suppression des services inutiles (cockpit, dhcpv6-client).
    * Ouverture exclusive du port SSH personnalisé.
    * Activation du `masquerading` (NAT) par défaut pour assurer la compatibilité future avec Docker, Podman ou des VPN.
* **Kernel Tuning (sysctl) :**
    * Protection contre l'IP Spoofing et le Source Routing.
    * Protection contre les attaques SYN Flood (TCP Hardening).
    * Ignorance des redirections ICMP (prévention MITM).
    * Log des paquets suspects (Martians).
* **Modules Noyau :** Chargement préventif des modules de filtrage et de pont (`br_netfilter`, `overlay`, `iptable_nat`) pour éviter les conflits lors d'installations futures de conteneurs.

### 5. Détection d'Intrusion et Audit
* **Fail2Ban :** Installation et configuration en mode agressif sur le port SSH personnalisé.
* **Auditd :** Activation du service d'audit du noyau avec des règles de surveillance sur les fichiers critiques (`/etc/passwd`, `/etc/shadow`, config SSH).
* **Intégrité des fichiers :** Installation et initialisation de AIDE (Advanced Intrusion Detection Environment) et RKHunter.

### 6. Environnement Administrateur
* Installation d'un arsenal d'outils CLI : `htop`, `btop`, `ncdu`, `tree`, `git`, `vim`, `wget`, `curl`, `net-tools`.
* Configuration d'un prompt Bash informatif (Utilisateur, Hôte, Branche Git).
* Ajout d'alias de maintenance (`update`, `checksec`, `firewall`, `ports`).

## Installation

Ce script doit être exécuté sur une installation fraîche ("Fresh Install") de Rocky Linux 9 ou RHEL 9.

1. **Télécharger le script :**
   ```bash
   curl -O [https://raw.githubusercontent.com/4b75726169736859/CITADEL/main/citadel_setup.sh](https://raw.githubusercontent.com/4b75726169736859/CITADEL/main/citadel_setup.sh)
    ````

2.  **Rendre le script exécutable :**

    ```bash
    chmod +x citadel_setup.sh
    ```

3.  **Lancer l'installation (en root) :**

    ```bash
    ./citadel_setup.sh
    ```

4.  **Suivre l'assistant interactif :**
    Le script vous demandera :

      * Si vous souhaitez créer un nouvel utilisateur administrateur.
      * Le port SSH à utiliser.
      * Le nom d'hôte (hostname) de la machine.

## Actions Post-Installation

Une fois le script terminé, il est impératif de suivre ces étapes avant de fermer votre session actuelle :

1.  Ouvrez un **nouveau terminal** sur votre poste local.
2.  Testez la connexion avec le nouvel utilisateur et le nouveau port :
    ```bash
    ssh -p VOTRE_PORT VOTRE_USER@IP_DU_SERVEUR
    ```
3.  Si la connexion fonctionne, finalisez l'installation en redémarrant le service SSH ou le serveur depuis la session originale :
    ```bash
    systemctl restart sshd
    # ou
    reboot
    ```

## Compatibilité

  * **OS Supportés :** Rocky Linux 9, AlmaLinux 9, Red Hat Enterprise Linux 9.
  * **Architecture :** x86\_64.
  * **Environnement :** VPS (OVH, DigitalOcean, etc.), Bare Metal, VM.

## Avertissement

Ce script modifie profondément la configuration système et réseau. Ne l'exécutez pas sur un serveur en production hébergeant déjà des services actifs sans avoir effectué une revue complète du code et des sauvegardes préalables.
