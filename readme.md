# CITADEL: Unified Hardening Framework

## Overview

**CITADEL** is an automated defensive engineering tool suite designed to transform standard installations into high-security environments. This project bundles two powerful monolithic frameworks to harden **Windows** and **Linux (RHEL 9-based)** according to the strictest international standards.

The goal is simple: provide **robust**, **auditable**, and **idempotent** protection for heterogeneous IT fleets.

## Project Architecture

The repository is structured by environment to facilitate targeted deployment:

* **`Rocky 9/`**: The Bash framework for Rocky Linux 9, RHEL 9, and AlmaLinux 9.
* **`Windows/`**: The MSSP-oriented PowerShell framework for Windows 10, 11, and Windows Server.

## Key Capabilities

### CITADEL for Linux (Bash)

A ~4000-line framework optimized for critical environments.

* **Compliance**: Aligned with CIS Benchmark L2, ANSSI BP-028 (High), and STIG.
* **Integrity**: System file immutability via `chattr +i` and a secure editing wrapper.
* **Network**: Dual-stack `nftables` firewall, DNS over TLS, and port-knocking.
* **Monitoring**: Auditd (50+ rules), USBGuard, and session recording (tlog).
* **Modernity**: Systemd sandboxing and CPU mitigations (spectre/l1tf) via GRUB.

### CITADEL for Windows (PowerShell)

A ~2600-line monolithic script designed for fleet management and RMM/GPO deployment.

* **Standards**: ANSSI BP-028, CIS Benchmark L2, and Microsoft Security Baselines.
* **OS Hygiene**: Disabling of legacy protocols (LLMNR, SMBv1), LSA hardening, and Credential Guard.
* **Protection**: Full configuration of 16 Defender ASR rules and Exploit Protection (ASLR, DEP).
* **Traceability**: Triple-channel logging (Event Log, CSV, Console) with a unique Run-ID for every execution.
* **Operational Security**: Native registry rollback and automatic restore point creation.

## Profile Comparison

| Feature | CITADEL (Linux) | CITADEL (Windows) |
| --- | --- | --- |
| **Language** | Bash 4.4+ | PowerShell 5.1+ |
| **Primary Target** | Production Servers | Workstations & Servers |
| **Audit Mode** | `--check-only` (60 points) | `-Mode Audit` (Full CSV) |
| **Idempotence** | Yes (State DB) | Yes (Read before write) |
| **Rollback** | Via LVM Snapshot & State DB | Via Restore Point & .reg |

## Quick Start

### Linux

```bash
sudo ./citadel.sh --compliance=anssi --enable-tlog

```

### Windows

```powershell
.\citadel.ps1 -Mode Enforce -Profile Workstation

```

## License & Liability

This framework is intended for internal MSSP use and experienced system administrators. System hardening is a critical operation: always test these scripts in a staging environment before applying them to production.

**Project CITADEL** - *Because "Default" is not a security policy.*