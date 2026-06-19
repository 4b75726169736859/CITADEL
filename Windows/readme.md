# SOC-Hardening Framework

**Windows Hardening PowerShell Framework - ANSSI BP-028 · CIS Benchmark L2 · Microsoft Security Baselines**

> Version : `1.4.2` | Compatibility : Windows 10 1809+ / Windows 11 21H2+ / Windows Server 2019+
> Prerequisites : PowerShell 5.1+ · Local Administrator rights

## Table of Contents

1. [Overview](https://www.google.com/search?q=%23overview)
2. [Coverage Scope](https://www.google.com/search?q=%23coverage-scope)
3. [Script Architecture](https://www.google.com/search?q=%23script-architecture)
4. [Parameters](https://www.google.com/search?q=%23parameters)
5. [Execution Modes](https://www.google.com/search?q=%23execution-modes)
6. [Profiles](https://www.google.com/search?q=%23profiles)
7. [Modules](https://www.google.com/search?q=%23modules)
8. [Logging & Traceability](https://www.google.com/search?q=%23logging--traceability)
9. [Rollback](https://www.google.com/search?q=%23rollback)
10. [GPO / RMM Deployment](https://www.google.com/search?q=%23gpo--rmm-deployment)
11. [Usage Examples](https://www.google.com/search?q=%23usage-examples)
12. [Known Limitations](https://www.google.com/search?q=%23known-limitations)
13. [References](https://www.google.com/search?q=%23references)

## Overview

`SOC-Hardening.ps1` is a monolithic MSSP-oriented script designed to harden heterogeneous Windows fleets in multi-client contexts. It covers the entire hardening chain recommended by ANSSI, CIS, and Microsoft, based on defensive engineering principles:

* **Idempotence** : Each check reads the existing value before writing and ignores it if it is already compliant. Reduces EDR noise on scheduled re-executions (GPO, RMM).
* **Triple-channel logging** : Event Viewer (source `SOC-Hardening`) + timestamped CSV + colorized console.
* **Native Rollback** : Export of each registry key before the first modification, full restoration from the Run-ID.
* **Automatic Contextualization** : Detection of Windows edition, presence of VBS/TPM, domain join status, and Azure AD. Non-applicable checks are marked `NotApplicable` without errors.

## Coverage Scope

| Domain | Key Controls |
| --- | --- |
| **Network Surface** | LLMNR, NBT-NS, mDNS, SMBv1, SMB signing, TCP/IP (ICMP redirects, WPAD, Teredo/6to4/ISATAP), Firewall 3 profiles |
| **Credential Protection** | LSA PPL / PPLBoot, WDigest, LM Hash, LmCompatibilityLevel 5, NTLM audit + restrictions, Kerberos AES-only, Credential Guard, credential cache |
| **Application Control** | AppLocker (Exe/Msi/Script/Dll) in Audit mode, WDAC skeleton |
| **Services & Telemetry** | Xbox, Fax, RetailDemo, RemoteRegistry, SharedAccess, DiagTrack, 8 CEIP scheduled tasks, Cortana, Advertising ID, Conditional Spooler + PrintNightmare mitigation |
| **Exploit Protection** | NX AlwaysOn, ASLR BottomUp/HighEntropy/ForceRelocate, SEHOP, CFG/StrictCFG (system + per-process: Edge, Chrome, Firefox, Acrobat, Office) |
| **Defender ASR** | 16 rules (13 Block / 3 Audit), PUA Protection, Cloud Block Level High, Network Protection, Controlled Folder Access Audit, network technician exclusions |
| **UAC** | EnableLUA, ConsentPromptBehaviorAdmin=2, Secure Desktop, FilterAdministratorToken, SecureUIAPaths, Virtualization |
| **Audit Policy** | 32 auditpol subcategories, Security Event Log 192 MB, ScriptBlock Logging, Module Logging, PowerShell Transcription, ProcessCreation with cmdline |
| **Accounts** | Password complexity, 60-day max age, 10-attempt lockout, RID 500 renaming, Guest deactivation, ANSSI R42 legal banner, 900s inactivity |

## Script Architecture

```
SOC-Hardening.ps1
│
├── GLOBAL CONFIGURATION Region      → constants, SOCResult / SOCSeverity enums
├── BANNER Region                    → Show-SOCBanner (disablable via -NoBanner)
├── INFRASTRUCTURE LOGGING Region    → Initialize-SOCLogging, Write-SOCLog
├── PRE-FLIGHT Region                → Test-SOCPrerequisites
├── DETECTION Region                 → Get-SOCSystemContext
├── HELPERS Region                   → Backup-SOCRegistryKey, Set-SOCRegistryValue,
│                                      New-SOCRestorePoint
├── MODULE NETWORK Region            → Disable-SOCLegacyNetworkProtocols,
│                                      Set-SOCTCPIPHardening, Set-SOCFirewallHardening
├── MODULE CREDENTIALS Region        → Set-SOCCredentialHardening
├── MODULE APPCONTROL Region         → Set-SOCAppLockerAudit, Set-SOCWDACAuditMode
├── MODULE SERVICES Region           → Disable-SOCUnusedServices,
│                                      Set-SOCPrintNightmareMitigation,
│                                      Disable-SOCTelemetry
├── MODULE EXPLOITGUARD Region       → Set-SOCExploitGuard
├── MODULE DEFENDER Region           → Set-SOCDefenderASR
├── MODULE UAC Region                → Set-SOCUACHardening
├── MODULE AUDIT Region              → Set-SOCAuditPolicy
├── MODULE ACCOUNT Region            → Set-SOCAccountPolicy
├── ORCHESTRATOR Region              → Invoke-SOCHardening, Invoke-SOCRollback
├── INTERACTIVE MENU Region          → Show-SOCMenu
└── ENTRY POINT Region               → Start-SOCMain

```

## Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-Mode` | `string` | `Interactive` | Execution mode (see dedicated section) |
| `-Profile` | `string` | `Workstation` | Target profile: `Technician`, `Workstation`, `Kiosk` |
| `-Modules` | `string[]` | `All` | List of modules to apply |
| `-SkipRestorePoint` | `switch` | - | Disables the creation of a system restore point |
| `-LogPath` | `string` | `C:\ProgramData\SOC-Hardening\Logs` | CSV log directory |
| `-BackupPath` | `string` | `C:\ProgramData\SOC-Hardening\Backups` | Registry export directory |
| `-NoBanner` | `switch` | - | Removes the header banner (useful in RMM) |

## Execution Modes

### `Audit`

Passes `-WhatIf` to all modules. **No changes** are applied. Generates a comprehensive CSV of actions that *would* be performed. Ideal for pre-deployment compliance analysis.

```powershell
.\SOC-Hardening.ps1 -Mode Audit -Profile Workstation

```

### `Enforce`

Effective application of controls. Creates a system restore point and exports relevant registry keys before every first modification.

```powershell
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation

```

### `Rollback`

Re-imports all `.reg` files generated during the last `Run-ID`. Restores the exact state of the registry before execution. **Does not restore non-registry changes** (services, auditpol, firewall rules).

```powershell
.\SOC-Hardening.ps1 -Mode Rollback

```

### `Interactive`

Launches a guided CLI menu allowing the selection of the mode, modules, and checking the detected system context.

## Profiles

### `Technician`

Designed for network/SOC technician stations equipped with administration and diagnostic tools. Applies **ASR-only** exclusions (via `-AttackSurfaceReductionOnlyExclusions`) for the following tools - these processes remain fully scanned by Defender but no longer trigger ASR rules that would block them in an operational context:

`Wireshark` · `Nmap` · `PuTTY` · `WinSCP` · `PsExec` · `Process Monitor` · `iperf3` · `Advanced IP Scanner` · `tftp.exe`

Credential cache kept at 10 entries (vs 4 in Workstation) to allow mobility on sites without DC connectivity.

### `Workstation`

Standard office profile. No tool exclusions, credential cache reduced to 4 entries.

### `Kiosk`

Maximum restricted profile. The 3 ASR rules in Audit mode are promoted to Block mode. Zero tolerance for exclusions.

## Modules

Modules can be selected individually via `-Modules`:

| Module | Value | Main Content |
| --- | --- | --- |
| Network | `Network` | LLMNR, NBT-NS, mDNS, SMBv1, TCP/IP stack, Firewall |
| Credentials | `Credentials` | LSA PPL, WDigest, NTLM, Kerberos, Credential Guard |
| App Control | `AppControl` | AppLocker Audit, WDAC skeleton |
| Services | `Services` | Unused services, telemetry, Spooler + PrintNightmare |
| Exploit Protection | `ExploitGuard` | ASLR, DEP/NX, CFG, SEHOP, per-process mitigations |
| Defender ASR | `Defender` | 16 ASR rules, PUA, Network Protection, Cloud Block |
| UAC | `UAC` | Strengthened UAC policy |
| Audit | `Audit` | auditpol 32 subcategories, PowerShell logging, Event Logs |
| Firewall | `Firewall` | Included in `Network` (also callable alone) |
| Accounts | - | Included in global `Enforce` |

## Logging & Traceability

Each execution generates a **Run-ID** (12-character short GUID) that prefixes all artifacts of the run.

### Event Log

* **Source** : `SOC-Hardening` (created automatically upon first launch)
* **Channel** : `Application`
* **Levels** : Information / Warning / Error / Critical (aligned with `SOCSeverity`)
* **Event IDs** : 1000–9999 range documented in each module's functions

### Traceability CSV

```
C:\ProgramData\SOC-Hardening\Logs\<RunID>_<timestamp>.csv

```

Columns : `Timestamp · Severity · Module · Result · EventId · Message · Details`

The `Logs` directory is protected by a restrictive ACL: write access reserved for the `SYSTEM` account and members of `Administrators`, read access for SOC operators.

### Registry Backups

```
C:\ProgramData\SOC-Hardening\Backups\<RunID>\<module>_<key>.reg

```

One export per modified key, generated **only once per Run-ID** (idempotence of backups).

## Rollback

The rollback only restores the **registry keys** backed up during the last Run-ID. It does not cover:

* `auditpol` changes (reset manually via `auditpol /clear`)
* Firewall rules (reset via `netsh advfirewall reset`)
* Local group policies (`gpedit.msc`)
* Service status (reactivate manually)

For a full rollback, use the **system restore point** created automatically before every `Enforce` run (unless `-SkipRestorePoint` is used).

```powershell
.\SOC-Hardening.ps1 -Mode Rollback
# Restores .reg keys from the last Run-ID detected in BackupPath

```

## GPO / RMM Deployment

### Via GPO (Computer Startup Script)

```
Recommended GPO settings:
  -Mode Enforce -Profile Workstation -NoBanner -SkipRestorePoint

```

> Disabling the restore point in GPO prevents errors related to the Windows limit of one restore point per 24h.

### Via RMM (Intune / N-able / NinjaOne / Atera)

The script is self-contained, with no external dependencies. Deploy as a PowerShell script with `SYSTEM` or `Local Administrator` rights. Retrieve the log CSV from `C:\ProgramData\SOC-Hardening\Logs` for integration into the CMDB or SIEM.

**Typical RMM command line:**

```powershell
powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "SOC-Hardening.ps1" -Mode Enforce -Profile Workstation -NoBanner -SkipRestorePoint

```

**Post-deployment compliance verification:**

```powershell
powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "SOC-Hardening.ps1" -Mode Audit -NoBanner
# Retrieve the CSV - all lines must have Result = Skipped (= already compliant)

```

## Usage Examples

```powershell
# Complete technician profile simulation - zero write
.\SOC-Hardening.ps1 -Mode Audit -Profile Technician

# Targeted hardening: network + credentials only
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation -Modules Network,Credentials

# Complete office workstation hardening
.\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation

# Kiosk/terminal hardening
.\SOC-Hardening.ps1 -Mode Enforce -Profile Kiosk -NoBanner -SkipRestorePoint

# Restoration from the last registry snapshot
.\SOC-Hardening.ps1 -Mode Rollback

# Detailed help
Get-Help .\SOC-Hardening.ps1 -Detailed

```

## Known Limitations

| Limitation | Detail |
| --- | --- |
| **Credential Guard** | Requires VBS + IOMMU + Secure Boot. Not applicable on Home edition or VM without nesting. |
| **WDAC Enforcement** | The WDAC module only deploys a skeleton in Audit mode. Moving to Enforcement requires a signed policy and deployment via MDM or dedicated GPO. |
| **AppLocker** | Requires Enterprise or Education edition for effective enforcement. In Pro, rules are loaded but not applied by the engine. |
| **Partial Rollback** | Rollback only covers the registry. `auditpol`, services, and firewall changes require manual restoration or via the system restore point. |
| **Spooler** | Disabling is conditional: if a printer is detected, the service is kept with PrintNightmare mitigation applied. |
| **Restore Point** | Windows limits creation to one restore point per 24h. The script bypasses this limit via the documented RPGlobalInterval threshold workaround. |

## References

| Repository | Document |
| --- | --- |
| ANSSI | [BP-028 - Recommandations de configuration d'un système Windows](https://www.google.com/search?q=https%3A%2F%2Fwww.ssi.gouv.fr%2Fguide%2Frecommandations-de-securite-relatives-a-un-systeme-gnulinux%2F) |
| CIS | CIS Microsoft Windows 10/11 Enterprise Benchmark v2.x - Level 2 + BitLocker |
| Microsoft | [MS Security Baselines - Windows 11 23H2/24H2 + Server 2022](https://www.google.com/search?q=https%3A%2F%2Fwww.microsoft.com%2Fen-us%2Fdownload%2Fdetails.aspx%3Fid%3D55319) |
| NIST | [SP 800-53 rev5 - AC, AU, CM, IA, SC, SI controls](https://www.google.com/search?q=https%3A%2F%2Fcsrc.nist.gov%2Fpublications%2Fdetail%2Fsp%2F800-53%2Frev-5%2Ffinal) |
| MITRE ATT&CK | Covered techniques: T1003, T1021, T1047, T1055, T1059, T1078, T1110, T1134, T1218, T1548, T1557, T1562 |

*SOC Team - Internal MSSP use. Do not distribute without security validation.*