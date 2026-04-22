# SOC-Hardening Framework

**Framework PowerShell de durcissement Windows - ANSSI BP-028 · CIS Benchmark L2 · Microsoft Security Baselines**

> Version : `1.4.2` | Compatibilité : Windows 10 1809+ / Windows 11 21H2+ / Windows Server 2019+  
> Prérequis : PowerShell 5.1+ · Droits Administrateur local


## Sommaire

1. [Présentation](#présentation)
2. [Périmètre de couverture](#périmètre-de-couverture)
3. [Architecture du script](#architecture-du-script)
4. [Paramètres](#paramètres)
5. [Modes d'exécution](#modes-dexécution)
6. [Profils](#profils)
7. [Modules](#modules)
8. [Logging & Traçabilité](#logging--traçabilité)
9. [Rollback](#rollback)
10. [Déploiement GPO / RMM](#déploiement-gpo--rmm)
11. [Exemples d'utilisation](#exemples-dutilisation)
12. [Limites connues](#limites-connues)
13. [Références](#références)


## Présentation

`SOC-Hardening.ps1` est un script monolithique orienté MSSP, conçu pour durcir des parcs Windows hétérogènes dans des contextes multi-clients. Il couvre l'ensemble de la chaîne de hardening recommandée par l'ANSSI, le CIS et Microsoft, en s'appuyant sur des principes d'ingénierie défensive :

- **Idempotence** : chaque contrôle lit la valeur existante avant écriture et l'ignore si elle est déjà conforme. Réduit le bruit EDR sur les re-exécutions planifiées (GPO, RMM).
- **Logging triple canal** : Observateur d'événements (source `SOC-Hardening`) + CSV horodaté + console colorisée.
- **Rollback natif** : export de chaque clé de registre avant première modification, restauration complète depuis le Run-ID.
- **Contextualisation automatique** : détection de l'édition Windows, de la présence de VBS/TPM, du statut de jonction de domaine et Azure AD. Les contrôles non applicables sont marqués `NotApplicable` sans erreur.


## Périmètre de couverture

| Domaine | Contrôles principaux |
|---|---|
| **Surface réseau** | LLMNR, NBT-NS, mDNS, SMBv1, signature SMB, TCP/IP (redirections ICMP, WPAD, Teredo/6to4/ISATAP), Firewall 3 profils |
| **Protection des identifiants** | LSA PPL / PPLBoot, WDigest, LM Hash, LmCompatibilityLevel 5, NTLM audit + restrictions, Kerberos AES-only, Credential Guard, cache d'identifiants |
| **Application Control** | AppLocker (Exe/Msi/Script/Dll) en mode Audit, squelette WDAC |
| **Services & Télémétrie** | Xbox, Fax, RetailDemo, RemoteRegistry, SharedAccess, DiagTrack, 8 tâches planifiées CEIP, Cortana, Advertising ID, Spooler conditionnel + mitigation PrintNightmare |
| **Exploit Protection** | NX AlwaysOn, ASLR BottomUp/HighEntropy/ForceRelocate, SEHOP, CFG/StrictCFG (système + per-process : Edge, Chrome, Firefox, Acrobat, Office) |
| **Defender ASR** | 16 règles (13 Block / 3 Audit), PUA Protection, Cloud Block Level High, Network Protection, Controlled Folder Access Audit, exclusions techniciens réseau |
| **UAC** | EnableLUA, ConsentPromptBehaviorAdmin=2, Secure Desktop, FilterAdministratorToken, SecureUIAPaths, Virtualisation |
| **Audit Policy** | 32 sous-catégories auditpol, Security Event Log 192 Mo, ScriptBlock Logging, Module Logging, Transcription PowerShell, ProcessCreation avec cmdline |
| **Comptes** | Complexité mdp, âge max 60j, lockout 10 essais, renommage RID 500, désactivation Guest, bannière légale ANSSI R42, inactivité 900s |


## Architecture du script

```
SOC-Hardening.ps1
│
├── Région CONFIGURATION GLOBALE     → constantes, enums SOCResult / SOCSeverity
├── Région BANNIERE                  → Show-SOCBanner (désactivable via -NoBanner)
├── Région INFRASTRUCTURE LOGGING    → Initialize-SOCLogging, Write-SOCLog
├── Région PRE-FLIGHT                → Test-SOCPrerequisites
├── Région DETECTION                 → Get-SOCSystemContext
├── Région HELPERS                   → Backup-SOCRegistryKey, Set-SOCRegistryValue,
│                                      New-SOCRestorePoint
├── Région MODULE NETWORK            → Disable-SOCLegacyNetworkProtocols,
│                                      Set-SOCTCPIPHardening, Set-SOCFirewallHardening
├── Région MODULE CREDENTIALS        → Set-SOCCredentialHardening
├── Région MODULE APPCONTROL         → Set-SOCAppLockerAudit, Set-SOCWDACAuditMode
├── Région MODULE SERVICES           → Disable-SOCUnusedServices,
│                                      Set-SOCPrintNightmareMitigation,
│                                      Disable-SOCTelemetry
├── Région MODULE EXPLOITGUARD       → Set-SOCExploitGuard
├── Région MODULE DEFENDER           → Set-SOCDefenderASR
├── Région MODULE UAC                → Set-SOCUACHardening
├── Région MODULE AUDIT              → Set-SOCAuditPolicy
├── Région MODULE ACCOUNT            → Set-SOCAccountPolicy
├── Région ORCHESTRATEUR             → Invoke-SOCHardening, Invoke-SOCRollback
├── Région MENU INTERACTIF           → Show-SOCMenu
└── Région POINT D'ENTREE            → Start-SOCMain
```


## Paramètres

| Paramètre | Type | Défaut | Description |
|---|---|---|---|
| `-Mode` | `string` | `Interactive` | Mode d'exécution (voir section dédiée) |
| `-Profile` | `string` | `Workstation` | Profil cible : `Technician`, `Workstation`, `Kiosk` |
| `-Modules` | `string[]` | `All` | Liste des modules à appliquer |
| `-SkipRestorePoint` | `switch` | - | Désactive la création du point de restauration |
| `-LogPath` | `string` | `C:\ProgramData\SOC-Hardening\Logs` | Répertoire des logs CSV |
| `-BackupPath` | `string` | `C:\ProgramData\SOC-Hardening\Backups` | Répertoire des exports de registre |
| `-NoBanner` | `switch` | - | Supprime la bannière d'entête (utile en RMM) |


## Modes d'exécution

### `Audit`
Passe `-WhatIf` à tous les modules. **Aucun changement** n'est appliqué. Génère un CSV complet des actions qui *seraient* effectuées. Idéal pour une analyse de conformité pré-déploiement.

```powershell
.\SOC-Hardening.ps1 -Mode Audit -Profile Workstation
```

### `Enforce`
Application effective des contrôles. Crée un point de restauration système et exporte les clés de registre concernées avant chaque première modification.

```powershell
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation
```

### `Rollback`
Réimporte tous les fichiers `.reg` générés lors du dernier `Run-ID`. Restaure l'état exact du registre avant l'exécution. **Ne restaure pas les changements hors registre** (services, auditpol, règles pare-feu).

```powershell
.\SOC-Hardening.ps1 -Mode Rollback
```

### `Interactive`
Lance un menu CLI guidé permettant de choisir le mode, les modules et de consulter le contexte système détecté.


## Profils

### `Technician`
Destiné aux postes techniciens réseau / SOC disposant d'outils d'administration et de diagnostic. Applique des exclusions **ASR-only** (via `-AttackSurfaceReductionOnlyExclusions`) pour les outils suivants - ces processus restent intégralement scannés par Defender mais ne déclenchent plus les règles ASR qui les bloqueraient en contexte opérationnel :

`Wireshark` · `Nmap` · `PuTTY` · `WinSCP` · `PsExec` · `Process Monitor` · `iperf3` · `Advanced IP Scanner` · `tftp.exe`

Cache d'identifiants conservé à 10 entrées (vs 4 en Workstation) pour permettre la mobilité sur sites sans connectivité DC.

### `Workstation`
Profil bureautique standard. Aucune exclusion outillage, cache d'identifiants réduit à 4 entrées.

### `Kiosk`
Profil restreint maximal. Les 3 règles ASR en mode Audit sont promues en mode Block. Tolérance zéro sur les exclusions.


## Modules

Les modules peuvent être sélectionnés individuellement via `-Modules` :

| Module | Valeur | Contenu principal |
|---|---|---|
| Réseau | `Network` | LLMNR, NBT-NS, mDNS, SMBv1, TCP/IP stack, Firewall |
| Identifiants | `Credentials` | LSA PPL, WDigest, NTLM, Kerberos, Credential Guard |
| Contrôle applicatif | `AppControl` | AppLocker Audit, WDAC squelette |
| Services | `Services` | Services inutiles, télémétrie, Spooler + PrintNightmare |
| Exploit Protection | `ExploitGuard` | ASLR, DEP/NX, CFG, SEHOP, mitigations per-process |
| Defender ASR | `Defender` | 16 règles ASR, PUA, Network Protection, Cloud Block |
| UAC | `UAC` | Politique UAC renforcée |
| Audit | `Audit` | auditpol 32 sous-catégories, PowerShell logging, Event Logs |
| Pare-feu | `Firewall` | Inclus dans `Network` (aussi appelable seul) |
| Comptes | - | Inclus dans `Enforce` global |


## Logging & Traçabilité

Chaque exécution génère un **Run-ID** (GUID court 12 caractères) qui préfixe tous les artefacts du run.

### Event Log
- **Source** : `SOC-Hardening` (créée automatiquement au premier lancement)
- **Canal** : `Application`
- **Niveaux** : Information / Warning / Error / Critical (alignés sur `SOCSeverity`)
- **Event IDs** : plage 1000–9999 documentée dans les fonctions de chaque module

### CSV de traçabilité
```
C:\ProgramData\SOC-Hardening\Logs\<RunID>_<timestamp>.csv
```
Colonnes : `Timestamp · Severity · Module · Result · EventId · Message · Details`

Le répertoire `Logs` est protégé par une ACL restrictive : écriture réservée au compte `SYSTEM` et aux membres de `Administrators`, lecture pour les opérateurs SOC.

### Backups registre
```
C:\ProgramData\SOC-Hardening\Backups\<RunID>\<module>_<clé>.reg
```
Un export par clé modifiée, généré **une seule fois par Run-ID** (idempotence des sauvegardes).


## Rollback

Le rollback restaure uniquement les **clés de registre** sauvegardées lors du dernier Run-ID. Il ne couvre pas :
- Les changements `auditpol` (réinitialiser manuellement via `auditpol /clear`)
- Les règles pare-feu (réinitialiser via `netsh advfirewall reset`)
- Les politiques de groupe locales (`gpedit.msc`)
- Le statut des services (réactiver manuellement)

Pour un rollback complet, utiliser le **point de restauration système** créé automatiquement avant chaque run `Enforce` (sauf `-SkipRestorePoint`).

```powershell
.\SOC-Hardening.ps1 -Mode Rollback
# Restaure les clés .reg du dernier Run-ID détecté dans BackupPath
```


## Déploiement GPO / RMM

### Via GPO (script de démarrage ordinateur)

```
Paramètres recommandés en GPO :
  -Mode Enforce -Profile Workstation -NoBanner -SkipRestorePoint
```

> Désactiver le point de restauration en GPO évite les erreurs liées à la limite Windows d'un seul point de restauration par 24h.

### Via RMM (Intune / N-able / NinjaOne / Atera)

Le script est auto-contenu, sans dépendance externe. Déployer comme script PowerShell avec les droits `SYSTEM` ou `Local Administrator`. Récupérer le CSV de log depuis `C:\ProgramData\SOC-Hardening\Logs` pour intégration dans la CMDB ou le SIEM.

**Ligne de commande type RMM :**
```powershell
powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "SOC-Hardening.ps1" -Mode Enforce -Profile Workstation -NoBanner -SkipRestorePoint
```

**Vérification de conformité post-déploiement :**
```powershell
powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "SOC-Hardening.ps1" -Mode Audit -NoBanner
# Récupérer le CSV - toutes les lignes doivent avoir Result = Skipped (= déjà conforme)
```


## Exemples d'utilisation

```powershell
# Simulation complète profil technicien - zéro écriture
.\SOC-Hardening.ps1 -Mode Audit -Profile Technician

# Hardening ciblé : réseau + identifiants uniquement
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation -Modules Network,Credentials

# Hardening complet poste bureautique
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation

# Hardening poste borne / kiosque
.\SOC-Hardening.ps1 -Mode Enforce -Profile Kiosk -NoBanner -SkipRestorePoint

# Restauration depuis le dernier snapshot registre
.\SOC-Hardening.ps1 -Mode Rollback

# Aide détaillée
Get-Help .\SOC-Hardening.ps1 -Detailed
```

## Limites connues

| Limite | Détail |
|---|---|
| **Credential Guard** | Requiert VBS + IOMMU + Secure Boot. Non applicable sur édition Home ou VM sans imbrication. |
| **WDAC Enforcement** | Le module WDAC déploie uniquement un squelette en mode Audit. Le passage en Enforcement nécessite une politique signée et un déploiement via MDM ou GPO dédié. |
| **AppLocker** | Requiert l'édition Enterprise ou Education pour l'enforcement effectif. En Pro, les règles sont chargées mais non appliquées par le moteur. |
| **Rollback partiel** | Le rollback couvre uniquement le registre. Les changements `auditpol`, services et pare-feu nécessitent une restauration manuelle ou via le point de restauration système. |
| **Spooler** | La désactivation est conditionnelle : si une imprimante est détectée, le service est conservé avec la mitigation PrintNightmare appliquée. |
| **Point de restauration** | Windows limite la création à un point de restauration par tranche de 24h. Le script contourne cette limite via le contournement documenté du seuil RPGlobalInterval. |


## Références

| Référentiel | Document |
|---|---|
| ANSSI | [BP-028 - Recommandations de configuration d'un système Windows](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/) |
| CIS | CIS Microsoft Windows 10/11 Enterprise Benchmark v2.x - Level 2 + BitLocker |
| Microsoft | [MS Security Baselines - Windows 11 23H2/24H2 + Server 2022](https://www.microsoft.com/en-us/download/details.aspx?id=55319) |
| NIST | [SP 800-53 rev5 - contrôles AC, AU, CM, IA, SC, SI](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| MITRE ATT&CK | Techniques couvertes : T1003, T1021, T1047, T1055, T1059, T1078, T1110, T1134, T1218, T1548, T1557, T1562 |

*SOC Team - Usage interne MSSP. Ne pas distribuer sans validation sécurité.*
