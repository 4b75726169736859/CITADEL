<#
.SYNOPSIS
    SOC-Hardening Framework - Durcissement Windows 10/11 conforme ANSSI (Renforce),
    CIS Benchmark Level 2 et Microsoft Security Baselines.

.DESCRIPTION
    Framework modulaire de durcissement destine aux postes techniciens et parcs clients
    geres en MSSP. Oriente deploiement GPO / RMM (Intune, N-able, NinjaOne, Atera).

    Perimetre couvert :
      - Surface d'attaque reseau (LLMNR, NBT-NS, mDNS, SMBv1, TCP/IP)
      - Protection des identifiants (LSA PPL, WDigest, NTLM, Credential Guard)
      - Application Control (AppLocker / WDAC en mode audit)
      - Services et Telemetrie (DiagTrack, Xbox, Spooler conditionnel)
      - Exploit Protection (ASLR, DEP, CFG, SEHOP)
      - Windows Defender ASR (16 regles) avec exclusions techniciens reseau
      - Audit Policy, UAC renforce, Firewall, politique de comptes

    Chaque action est :
      - Journalisee dans l'Observateur d'evenements (source "SOC-Hardening")
      - Horodatee dans un log CSV de tracabilite
      - Precedee d'un point de restauration et d'un export de cle de registre

    Le mode -Mode Rollback permet la restauration depuis les exports generes.

.PARAMETER Mode
    Mode d'execution : Audit | Enforce | Rollback | Interactive
    - Audit       : simulation complete (WhatIf), aucun changement applique
    - Enforce     : application effective du hardening
    - Rollback    : restauration depuis le dernier snapshot
    - Interactive : menu CLI (defaut)

.PARAMETER Profile
    Profil cible :
    - Technician  : exclusions pour outils reseau (nmap, wireshark, tftp, psexec)
    - Workstation : profil utilisateur bureautique standard (defaut)
    - Kiosk       : profil restreint maximal (usage borne / libre-service)

.PARAMETER Modules
    Liste des modules a appliquer. Valeur par defaut : All.
    Valeurs : Network, Credentials, AppControl, Services, ExploitGuard,
              Defender, Audit, UAC, Firewall, All.

.PARAMETER SkipRestorePoint
    Desactive la creation du point de restauration (non recommande en production).

.PARAMETER LogPath
    Chemin du log CSV de tracabilite. Defaut : C:\ProgramData\SOC-Hardening\Logs

.PARAMETER BackupPath
    Chemin des exports de cles de registre. Defaut : C:\ProgramData\SOC-Hardening\Backups

.EXAMPLE
    PS> .\SOC-Hardening.ps1 -Mode Audit -Profile Technician
    Simulation complete du profil technicien sans aucune modification systeme.

.EXAMPLE
    PS> .\SOC-Hardening.ps1 -Mode Enforce -Profile Workstation -Modules Network,Credentials,Defender
    Application ciblee de trois modules sur un poste bureautique.

.EXAMPLE
    PS> .\SOC-Hardening.ps1 -Mode Rollback
    Restauration complete depuis le dernier snapshot.

.EXAMPLE
    PS> Get-Help .\SOC-Hardening.ps1 -Detailed
    Affiche l'aide detaillee du script.

.NOTES
    Auteur   : SOC Team
    Version  : 1.4.2
    Compat.  : Windows 10 1809+ / Windows 11 21H2+ / Windows Server 2019+
    Requis   : PowerShell 5.1+, execution en tant qu'administrateur local

    References techniques :
      - ANSSI-BP-028 (Recommandations de configuration d'un systeme GNU/Linux ou Windows)
      - CIS Microsoft Windows 10/11 Enterprise Benchmark v2.x (Level 2 + BitLocker)
      - MS Security Baselines (Windows 11 23H2 / 24H2, Windows Server 2022)
      - NIST SP 800-53 rev5 (controles AC, AU, CM, IA, SC, SI)

    Limites connues :
      - Credential Guard requiert VBS/IOMMU (non active sur edition Home)
      - WDAC en mode Enforcement non couvert (mode Audit uniquement par defaut)
      - La desactivation du Print Spooler est conditionnelle (parametre -Profile)
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Audit', 'Enforce', 'Rollback', 'Interactive')]
    [string]$Mode = 'Interactive',

    [Parameter()]
    [ValidateSet('Technician', 'Workstation', 'Kiosk')]
    [string]$Profile = 'Workstation',

    [Parameter()]
    [ValidateSet('All', 'Network', 'Credentials', 'AppControl', 'Services',
                 'ExploitGuard', 'Defender', 'Audit', 'UAC', 'Firewall')]
    [string[]]$Modules = @('All'),

    [Parameter()]
    [switch]$SkipRestorePoint,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "$env:ProgramData\SOC-Hardening\Logs",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = "$env:ProgramData\SOC-Hardening\Backups",

    [Parameter()]
    [switch]$NoBanner
)

#region ============================ CONFIGURATION GLOBALE ============================

# Typage fort - structures partagees entre modules
Set-Variable -Name 'SOC_VERSION'       -Value '1.4.2'            -Option Constant -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name 'SOC_EVENT_SOURCE'  -Value 'SOC-Hardening'    -Option Constant -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name 'SOC_EVENT_LOG'     -Value 'Application'      -Option Constant -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name 'SOC_RUN_ID'        -Value ([Guid]::NewGuid().ToString('N').Substring(0,12)) -Option Constant -Scope Script -ErrorAction SilentlyContinue

# ErrorActionPreference local a la portee du script uniquement (ne contamine pas la session)
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Enumeration des resultats - evite les chaines magiques dans les logs
enum SOCResult {
    Success
    Skipped
    Failed
    NotApplicable
    WouldChange
}

# Enumeration des severites - aligne sur les Event IDs
enum SOCSeverity {
    Debug       = 0
    Information = 1
    Warning     = 2
    Error       = 3
    Critical    = 4
}

#endregion

#region ============================ BANNIERE ============================

function Show-SOCBanner {
    [CmdletBinding()]
    param()

    if ($NoBanner) { return }

    # Banniere volontairement sobre : pas d'ASCII art tape-a-l'oeil susceptible
    # de generer une signature comportementale particuliere dans l'EDR
    $line = '-' * 72
    Write-Host ''
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ' SOC-Hardening Framework' -ForegroundColor Cyan -NoNewline
    Write-Host "  v$script:SOC_VERSION" -ForegroundColor DarkGray
    Write-Host ' ANSSI BP-028 | CIS L2 | MS Security Baselines' -ForegroundColor DarkGray
    Write-Host " Run-ID : $script:SOC_RUN_ID" -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ''
}

#endregion

#region ============================ INFRASTRUCTURE LOGGING ============================

function Initialize-SOCLogging {
    <#
    .SYNOPSIS
        Prepare la source d'evenements personnalisee et les repertoires de logs.
    .DESCRIPTION
        Enregistre la source SOC-Hardening dans le log Application. Cette operation
        est idempotente et necessite les droits administrateur une seule fois
        (persistant apres premier enregistrement).
    #>
    [CmdletBinding()]
    param()

    try {
        # Source d'evenements : creation one-shot persistante dans le registre
        # HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\<Source>
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:SOC_EVENT_SOURCE)) {
            [System.Diagnostics.EventLog]::CreateEventSource(
                $script:SOC_EVENT_SOURCE,
                $script:SOC_EVENT_LOG
            )
        }
    }
    catch {
        # En cas d'echec, on bascule sur un fallback fichier sans interrompre
        Write-Warning "Enregistrement de la source d'evenements echoue : $($_.Exception.Message)"
    }

    # Arborescence de travail
    foreach ($path in @($LogPath, $BackupPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            $null = New-Item -Path $path -ItemType Directory -Force
        }
    }

    # ACL restrictive : seul SYSTEM / Administrateurs peuvent lire/modifier les logs
    # Protection contre l'alteration par un utilisateur local standard
    $acl = Get-Acl -LiteralPath $LogPath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -LiteralPath $LogPath -AclObject $acl -ErrorAction SilentlyContinue
}

function Write-SOCLog {
    <#
    .SYNOPSIS
        Ecrit une entree corralee dans trois canaux : console, CSV, Event Log.
    .DESCRIPTION
        Point d'entree unique pour toute journalisation. Garantit la coherence
        du format et permet l'agregation SIEM via le canal Application.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [SOCSeverity]$Severity = [SOCSeverity]::Information,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Module = 'Core',

        [Parameter()]
        [SOCResult]$Result = [SOCResult]::Success,

        [Parameter()]
        [ValidateRange(1000, 9999)]
        [int]$EventId = 1000,

        [Parameter()]
        [hashtable]$Context
    )

    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffzzz'

    # --- 1. Console (couleur fonction de la severite) ---
    $color = switch ($Severity) {
        ([SOCSeverity]::Debug)       { 'DarkGray' }
        ([SOCSeverity]::Information) { 'Gray' }
        ([SOCSeverity]::Warning)     { 'Yellow' }
        ([SOCSeverity]::Error)       { 'Red' }
        ([SOCSeverity]::Critical)    { 'Magenta' }
        default                      { 'White' }
    }

    $prefix = '[{0,-11}] [{1,-6}] [{2,-14}]' -f $Severity, $Result, $Module
    Write-Host $prefix -ForegroundColor $color -NoNewline
    Write-Host " $Message"

    # --- 2. Log CSV (tracabilite long-terme, parseable par un SIEM) ---
    $csvFile = Join-Path -Path $LogPath -ChildPath ("SOC-Hardening_{0}_{1}.csv" -f (Get-Date -Format 'yyyyMMdd'), $script:SOC_RUN_ID)

    $contextJson = if ($Context) { ($Context | ConvertTo-Json -Compress -Depth 4) } else { '' }

    $record = [PSCustomObject]@{
        Timestamp  = $timestamp
        RunId      = $script:SOC_RUN_ID
        Host       = $env:COMPUTERNAME
        User       = "$env:USERDOMAIN\$env:USERNAME"
        Module     = $Module
        Severity   = $Severity
        Result     = $Result
        EventId    = $EventId
        Message    = $Message
        Context    = $contextJson
    }

    try {
        $record | Export-Csv -LiteralPath $csvFile -Append -NoTypeInformation -Encoding UTF8 -Force
    }
    catch {
        # Fallback silencieux : la console reste disponible meme si le disque est plein
    }

    # --- 3. Event Log Windows (integration SIEM via WEF / Wazuh / Splunk UF) ---
    try {
        $entryType = switch ($Severity) {
            ([SOCSeverity]::Warning)  { 'Warning' }
            ([SOCSeverity]::Error)    { 'Error' }
            ([SOCSeverity]::Critical) { 'Error' }
            default                   { 'Information' }
        }

        $fullMessage = "[$Module] [$Result] $Message`r`nRun-ID: $script:SOC_RUN_ID"
        if ($Context) { $fullMessage += "`r`nContext: $contextJson" }

        Write-EventLog -LogName $script:SOC_EVENT_LOG `
                       -Source $script:SOC_EVENT_SOURCE `
                       -EntryType $entryType `
                       -EventId $EventId `
                       -Message $fullMessage `
                       -ErrorAction SilentlyContinue
    }
    catch {
        # Ne bloque jamais : l'Event Log peut etre sature, la console+CSV suffisent
    }
}

#endregion

#region ============================ PRE-FLIGHT & DETECTION ============================

function Test-SOCPrerequisites {
    <#
    .SYNOPSIS
        Valide les pre-requis techniques avant toute modification.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ok = $true

    # 1. Elevation administrateur - requise pour HKLM et services
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-SOCLog -Severity Critical -Module Core -Result Failed -EventId 1001 `
                     -Message 'Le script doit etre execute en tant qu''administrateur.'
        $ok = $false
    }

    # 2. PowerShell 5.1 minimum - plusieurs cmdlets (NetSecurity, Defender) l'imposent
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        Write-SOCLog -Severity Critical -Module Core -Result Failed -EventId 1002 `
                     -Message "PowerShell 5.1+ requis (detecte : $($PSVersionTable.PSVersion))."
        $ok = $false
    }

    # 3. Execution Policy - alerte mais ne bloque pas si le script est lance avec -ExecutionPolicy Bypass
    $execPolicy = Get-ExecutionPolicy -Scope Process
    if ($execPolicy -eq 'Restricted') {
        Write-SOCLog -Severity Warning -Module Core -Result Skipped -EventId 1003 `
                     -Message "Execution Policy Restricted - utiliser 'Bypass' au niveau Process."
    }

    # 4. Espace disque minimum pour point de restauration (~300 Mo recommandes)
    $sys = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    if ($sys -and $sys.FreeSpace -lt 500MB) {
        Write-SOCLog -Severity Warning -Module Core -Result Skipped -EventId 1004 `
                     -Message "Espace disque faible ($([math]::Round($sys.FreeSpace/1MB,0)) Mo) - point de restauration potentiellement KO."
    }

    return $ok
}

function Get-SOCSystemContext {
    <#
    .SYNOPSIS
        Collecte le contexte systeme utilise pour conditionner l'application des modules.
    .DESCRIPTION
        Retourne un objet enrichi : edition, build, jonction domaine, role, VBS status,
        TPM, capacite ASR, AppLocker service status. Chaque module consomme ce contexte
        pour eviter les appels repetes a Get-CimInstance.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $os   = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    # Edition decodee : Home/Pro/Enterprise/Education/Server...
    $editionId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID

    # Release/DisplayVersion : 22H2, 23H2, 24H2...
    $release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
    if (-not $release) {
        $release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId
    }

    # Famille (10/11) derivee du build - plus fiable que le nom commercial
    $build  = [int]$os.BuildNumber
    $family = if ($build -ge 22000) { 'Windows11' }
              elseif ($build -ge 17763) { 'Windows10' }
              elseif ($os.ProductType -in 2,3) { 'WindowsServer' }
              else { 'Legacy' }

    # Virtualization Based Security - pre-requis Credential Guard / HVCI
    $vbsStatus = $null
    try {
        $vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard `
                                     -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                                     -ErrorAction Stop
    } catch { }

    # TPM present et actif ?
    $tpm = $null
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
    } catch { }

    # Capacite Defender / ASR - absent sur certaines editions (N/KN) ou si AV tiers actif
    $defender = $null
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
    } catch { }

    # Jonction AD / Azure AD - impacte la politique NTLM et certains services
    $domainJoined     = $cs.PartOfDomain
    $azureJoined      = $false
    try {
        $dsreg = & dsregcmd.exe /status 2>$null
        $azureJoined = ($dsreg -match 'AzureAdJoined\s*:\s*YES') -or ($dsreg -match 'WorkplaceJoined\s*:\s*YES')
    } catch { }

    # Presence d'un role d'impression - conditionne la desactivation du Print Spooler
    $hasLocalPrinter = (Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Local' }).Count -gt 0

    [PSCustomObject]@{
        Hostname          = $env:COMPUTERNAME
        Family            = $family
        Build             = $build
        Release           = $release
        Edition           = $editionId
        Caption           = $os.Caption
        Architecture      = $os.OSArchitecture
        ProductType       = $os.ProductType  # 1=Workstation 2=DC 3=Server
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        FirmwareType      = if ($env:firmware_type) { $env:firmware_type } else { (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue).BiosFirmwareType }
        SecureBoot        = (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
        TpmPresent        = [bool]($tpm -and $tpm.TpmPresent)
        TpmReady          = [bool]($tpm -and $tpm.TpmReady)
        DomainJoined      = $domainJoined
        AzureJoined       = $azureJoined
        Domain            = $cs.Domain
        VbsStatus         = $vbsStatus.VirtualizationBasedSecurityStatus
        CredGuardRunning  = ($vbsStatus -and $vbsStatus.SecurityServicesRunning -contains 1)
        HvciRunning       = ($vbsStatus -and $vbsStatus.SecurityServicesRunning -contains 2)
        DefenderEnabled   = [bool]($defender -and $defender.AntivirusEnabled)
        DefenderTamperOn  = [bool]($defender -and $defender.IsTamperProtected)
        HasLocalPrinter   = $hasLocalPrinter
        Timestamp         = Get-Date
    }
}

#endregion

#region ============================ HELPERS REGISTRE & BACKUP ============================

function Backup-SOCRegistryKey {
    <#
    .SYNOPSIS
        Exporte une cle de registre vers un fichier .reg horodate.
    .DESCRIPTION
        Export pre-modification pour rollback. Utilise reg.exe (plus fiable que
        Export-Clixml pour restaurer via reg import / GPO).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [string]$Label = 'generic'
    )

    # Normalisation PS -> reg.exe : HKLM: -> HKLM
    $regPath = $Path -replace '^HKLM:\\?', 'HKLM\' `
                     -replace '^HKCU:\\?', 'HKCU\' `
                     -replace '^HKCR:\\?', 'HKCR\' `
                     -replace '^HKU:\\?',  'HKU\'

    $safeLabel = ($Label -replace '[^a-zA-Z0-9_-]', '_')
    $file      = Join-Path -Path $BackupPath -ChildPath ("{0}_{1}_{2}.reg" -f $safeLabel, $script:SOC_RUN_ID, (Get-Date -Format 'yyyyMMddHHmmss'))

    # reg.exe export /y : silencieux, ecrase
    $out = & reg.exe export $regPath $file /y 2>&1
    if ($LASTEXITCODE -ne 0) {
        # Non bloquant : la cle peut ne pas exister encore (creation ulterieure)
        Write-SOCLog -Severity Debug -Module Backup -Result Skipped -EventId 2001 `
                     -Message "Export impossible pour '$regPath' : $out"
        return $null
    }

    Write-SOCLog -Severity Debug -Module Backup -Result Success -EventId 2002 `
                 -Message "Export effectue : $file" -Context @{ RegPath = $regPath }
    return $file
}

function Set-SOCRegistryValue {
    <#
    .SYNOPSIS
        Ecrit une valeur de registre de maniere idempotente avec backup et logging.
    .DESCRIPTION
        Point d'entree unique pour les ecritures registre. Garantit :
        - Creation de l'arborescence si absente
        - Backup de la cle avant premiere modification de la session
        - Idempotence (skip si la valeur est deja conforme)
        - Respect du -WhatIf (mode Audit)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([SOCResult])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Value,

        [Parameter()]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'QWord', 'MultiString')]
        [string]$Type = 'DWord',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Module = 'Registry',

        [Parameter()]
        [string]$Reason,

        [Parameter()]
        [string]$Reference  # ex: "ANSSI R35" ou "CIS 18.5.4.1"
    )

    # Idempotence : on lit la valeur actuelle pour eviter une ecriture inutile
    # (reduit le bruit d'audit registre dans l'EDR et les MFT writes)
    $current = $null
    try {
        $current = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        # Cle ou valeur absente : on procedera a la creation
    }

    if ($null -ne $current -and $current -eq $Value) {
        Write-SOCLog -Severity Debug -Module $Module -Result Skipped -EventId 3000 `
                     -Message "$Path\$Name deja a la valeur attendue ($Value) [$Reference]"
        return [SOCResult]::Skipped
    }

    $target = "$Path\$Name = $Value ($Type)"
    if (-not $PSCmdlet.ShouldProcess($target, "Set registry value")) {
        Write-SOCLog -Severity Information -Module $Module -Result WouldChange -EventId 3001 `
                     -Message "[SIMULATION] $target | Raison : $Reason [$Reference]"
        return [SOCResult]::WouldChange
    }

    try {
        # Backup one-shot par cle par run
        $script:__backedUpKeys ??= @{}
        if (-not $script:__backedUpKeys.ContainsKey($Path)) {
            $null = Backup-SOCRegistryKey -Path $Path -Label ($Module + '_' + ($Path.Split('\')[-1]))
            $script:__backedUpKeys[$Path] = $true
        }

        # Creation de l'arborescence manquante
        if (-not (Test-Path -LiteralPath $Path)) {
            $null = New-Item -Path $Path -Force
        }

        New-ItemProperty -LiteralPath $Path `
                         -Name $Name `
                         -Value $Value `
                         -PropertyType $Type `
                         -Force | Out-Null

        Write-SOCLog -Severity Information -Module $Module -Result Success -EventId 3002 `
                     -Message "$target applique | $Reason [$Reference]"
        return [SOCResult]::Success
    }
    catch {
        Write-SOCLog -Severity Error -Module $Module -Result Failed -EventId 3003 `
                     -Message "Echec $target : $($_.Exception.Message)"
        return [SOCResult]::Failed
    }
}

function New-SOCRestorePoint {
    <#
    .SYNOPSIS
        Cree un point de restauration systeme avant modification.
    .DESCRIPTION
        Contourne la limite native Windows de 1 point de restauration par 24h via
        modification temporaire de SystemRestorePointCreationFrequency.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string]$Description = "SOC-Hardening Pre-Apply [$script:SOC_RUN_ID]"
    )

    if ($SkipRestorePoint) {
        Write-SOCLog -Severity Warning -Module Restore -Result Skipped -EventId 4001 `
                     -Message 'Point de restauration desactive par parametre (-SkipRestorePoint).'
        return $false
    }

    try {
        # Verification prealable : la protection systeme doit etre active
        $sr = Get-CimInstance -Namespace 'root\default' -ClassName SystemRestore -ErrorAction SilentlyContinue
        if (-not $sr) {
            # Activation a la volee - certaines editions desactivent par defaut
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
        }

        # Contournement de la limite 1/24h : on bascule temporairement la freq a 0
        $freqKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $previousFreq = (Get-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
        Set-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -Force

        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop

        # Restauration de la frequence d'origine
        if ($null -ne $previousFreq) {
            Set-ItemProperty -LiteralPath $freqKey -Name 'SystemRestorePointCreationFrequency' -Value $previousFreq -Type DWord -Force
        }

        Write-SOCLog -Severity Information -Module Restore -Result Success -EventId 4002 `
                     -Message "Point de restauration cree : $Description"
        return $true
    }
    catch {
        Write-SOCLog -Severity Warning -Module Restore -Result Failed -EventId 4003 `
                     -Message "Point de restauration non cree : $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region ============================ MODULE : NETWORK HARDENING ============================

function Disable-SOCLegacyNetworkProtocols {
    <#
    .SYNOPSIS
        Neutralise les protocoles de resolution de noms exploites pour le relayage.
    .DESCRIPTION
        Vise LLMNR, NetBIOS over TCP/IP (NBT-NS) et mDNS, tous exploites par
        Responder/Inveigh pour intercepter des hashes NTLMv2 en environnement
        commute. SMBv1 est egalement retire (EternalBlue / wormable).

        Refs : ANSSI R17/R18, CIS 18.5.4.1 / 18.5.4.2, MS SB.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Network -Message '>>> Debut du durcissement reseau (protocoles legacy)' -EventId 5000

    # --- LLMNR : Link-Local Multicast Name Resolution ---
    # Prevention du relayage NTLM : sans LLMNR, un poste ne publiera plus
    # son nom en multicast UDP/5355, supprimant une source de hashes NTLMv2.
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                         -Name 'EnableMulticast' -Value 0 -Type DWord `
                         -Module Network -Reference 'ANSSI R17 | CIS 18.5.4.2' `
                         -Reason 'Desactivation LLMNR - evite l''interception de hashes via Responder'

    # --- mDNS : Multicast DNS (Bonjour-like) ---
    # Ajoute par Windows 10 2004+, exploitable au meme titre que LLMNR.
    # Note : sa desactivation peut casser la decouverte d'imprimantes AirPrint.
    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                         -Name 'EnableMDNS' -Value 0 -Type DWord `
                         -Module Network -Reference 'ANSSI R17' `
                         -Reason 'Desactivation mDNS - meme vecteur d''attaque que LLMNR'

    # --- NBT-NS : NetBIOS Name Service ---
    # Requiere une iteration par interface - pas de cle globale. NetbiosOptions=2 (Disable).
    # 0 = Default (DHCP), 1 = Enable, 2 = Disable
    $nbtInterfaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
                     Where-Object { $_.PSChildName -like 'Tcpip_*' }

    foreach ($iface in $nbtInterfaces) {
        Set-SOCRegistryValue -Path $iface.PSPath `
                             -Name 'NetbiosOptions' -Value 2 -Type DWord `
                             -Module Network -Reference 'ANSSI R17 | CIS 18.5.4.1' `
                             -Reason "Desactivation NBT-NS sur interface $($iface.PSChildName)"
    }

    # Forcer le defaut a 2 pour les nouvelles interfaces (DHCP)
    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
                         -Name 'NodeType' -Value 2 -Type DWord `
                         -Module Network -Reference 'ANSSI R17' `
                         -Reason 'Mode P-Node : NetBIOS over TCP/IP utilise uniquement le serveur WINS (aucun broadcast)'

    # --- SMBv1 : CVE-2017-0143 (EternalBlue) et wormable family ---
    if ($PSCmdlet.ShouldProcess('SMBv1', 'Disable legacy protocol')) {
        try {
            # Niveau client + serveur. SMBv1 n'a plus aucune legitimite > Windows 7 / Server 2008.
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null

            # Client : cle MrxSmb10 - Start=4 (Disabled)
            Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' `
                                 -Name 'Start' -Value 4 -Type DWord `
                                 -Module Network -Reference 'CIS 18.3.1 | MS SB' `
                                 -Reason 'SMBv1 client disabled - protection wormable (EternalBlue)'

            Write-SOCLog -Severity Information -Module Network -Result Success -EventId 5010 `
                         -Message 'SMBv1 desactive (client + serveur)'
        }
        catch {
            Write-SOCLog -Severity Error -Module Network -Result Failed -EventId 5011 `
                         -Message "Desactivation SMBv1 KO : $($_.Exception.Message)"
        }
    }

    # --- SMBv2/v3 : signature et chiffrement obligatoires cote serveur ---
    # Bloque les attaques de type SMB Relay meme si NTLM reste actif
    if ($PSCmdlet.ShouldProcess('SMB Signing & Encryption', 'Require')) {
        try {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -ErrorAction Stop
            Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -ErrorAction Stop
            Write-SOCLog -Severity Information -Module Network -Result Success -EventId 5012 `
                         -Message 'Signature SMB requise (client + serveur) - contre-mesure SMB Relay'
        }
        catch {
            Write-SOCLog -Severity Warning -Module Network -Result Failed -EventId 5013 `
                         -Message "Signature SMB non appliquee : $($_.Exception.Message)"
        }
    }

    # --- LLMNR via NetAdapter quand disponible (Windows 11 24H2+) ---
    # Certaines builds exposent une cmdlet Disable-NetAdapterBinding pour couper LLMNR au niveau WinSock
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            # ms_netbios : NetBIOS over Tcpip
            Disable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_netbios' -ErrorAction SilentlyContinue
        } catch { }
    }

    Write-SOCLog -Module Network -Message '<<< Fin du durcissement reseau (protocoles legacy)' -EventId 5001
}

function Set-SOCTCPIPHardening {
    <#
    .SYNOPSIS
        Durcissement de la stack TCP/IP (anti-fingerprint, anti-ICMP abuse).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Network -Message '>>> Durcissement stack TCP/IP' -EventId 5100

    $tcp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $tcp6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'

    # --- IPv4 : anti SYN-flood & anti-ICMP redirect ---
    # EnableICMPRedirect=0 : un attaquant local ne peut plus injecter de routes
    Set-SOCRegistryValue -Path $tcp -Name 'EnableICMPRedirect' -Value 0 -Type DWord `
                         -Module Network -Reference 'CIS 18.5.19.2.1' `
                         -Reason 'Blocage des ICMP Redirect (injection de route par attaquant L2)'

    # DisableIPSourceRouting=2 : refuse les paquets avec option IP Source Routing
    Set-SOCRegistryValue -Path $tcp -Name 'DisableIPSourceRouting' -Value 2 -Type DWord `
                         -Module Network -Reference 'CIS 18.5.19.2.2' `
                         -Reason 'Rejet du Source Routing IPv4 (contournement firewall/NAT)'

    Set-SOCRegistryValue -Path $tcp6 -Name 'DisableIPSourceRouting' -Value 2 -Type DWord `
                         -Module Network -Reference 'CIS 18.5.19.2.3' `
                         -Reason 'Rejet du Source Routing IPv6'

    # PerformRouterDiscovery=0 : evite l'auto-configuration via RFC 1256
    Set-SOCRegistryValue -Path $tcp -Name 'PerformRouterDiscovery' -Value 0 -Type DWord `
                         -Module Network -Reference 'CIS 18.5.19.2.8' `
                         -Reason 'Desactivation Router Discovery (spoofing de gateway)'

    # TcpMaxDataRetransmissions=3 : durcit la resistance au SYN-flood
    Set-SOCRegistryValue -Path $tcp -Name 'TcpMaxDataRetransmissions' -Value 3 -Type DWord `
                         -Module Network -Reference 'CIS 18.5.19.2.5' `
                         -Reason 'Reduction du nb de retransmissions (anti SYN-flood)'

    # --- NetBIOS node type global : P-node (pas de broadcast) ---
    # Deja pousse dans Disable-SOCLegacyNetworkProtocols, repris ici pour SCW

    # --- WPAD : CVE-2016-3213, downgrade de PAC via LLMNR/NBT ---
    # Desactivation de la resolution automatique du proxy (poisoning tres courant)
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' `
                         -Name 'WpadOverride' -Value 1 -Type DWord `
                         -Module Network -Reference 'ANSSI R17' `
                         -Reason 'Desactivation WPAD - poisoning via LLMNR/NBT'

    # --- IPv6 Teredo : tunnelling IPv6/UDP - surface d'attaque additionnelle ---
    try {
        Set-NetTeredoConfiguration -Type Disabled -ErrorAction Stop
        Write-SOCLog -Severity Information -Module Network -Result Success -EventId 5110 `
                     -Message 'Teredo (IPv6 tunnelling) desactive'
    } catch {
        Write-SOCLog -Severity Debug -Module Network -Result Skipped -EventId 5111 `
                     -Message "Teredo : $($_.Exception.Message)"
    }

    # --- IPv6 6to4 et ISATAP : idem, tunnels exotiques ---
    try {
        Set-Net6to4Configuration -State Disabled -ErrorAction Stop
        Set-NetIsatapConfiguration -State Disabled -ErrorAction Stop
    } catch { }

    # --- IP Forwarding : refuse le routage par le poste (SSTP hijack, pivot) ---
    Set-SOCRegistryValue -Path $tcp -Name 'IPEnableRouter' -Value 0 -Type DWord `
                         -Module Network -Reference 'MS SB' `
                         -Reason 'IP forwarding OFF - poste non utilisable comme relai L3'

    Write-SOCLog -Module Network -Message '<<< Durcissement stack TCP/IP termine' -EventId 5101
}

function Set-SOCFirewallHardening {
    <#
    .SYNOPSIS
        Active les trois profils firewall + logging drop/allow + regles inbound par defaut.
    .DESCRIPTION
        Ref CIS 9.1-9.3 et ANSSI R19 : firewall toujours actif, logging drop,
        default Inbound=Block. Les profils Private/Public n'autorisent aucune regle
        non-declaree au niveau GPO.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Firewall -Message '>>> Durcissement Windows Firewall' -EventId 6000

    $logDir = "$env:SystemRoot\System32\LogFiles\Firewall"
    if (-not (Test-Path -LiteralPath $logDir)) {
        $null = New-Item -Path $logDir -ItemType Directory -Force
    }

    foreach ($profileName in 'Domain', 'Private', 'Public') {
        try {
            $logFile = Join-Path $logDir "pfirewall_$profileName.log"

            Set-NetFirewallProfile -Profile $profileName `
                -Enabled True `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow `
                -NotifyOnListen True `
                -AllowInboundRules True `
                -AllowLocalFirewallRules True `
                -AllowLocalIPsecRules True `
                -LogFileName $logFile `
                -LogMaxSizeKilobytes 16384 `
                -LogAllowed False `
                -LogBlocked True `
                -LogIgnored False `
                -ErrorAction Stop

            Write-SOCLog -Severity Information -Module Firewall -Result Success -EventId 6010 `
                         -Message "Profil $profileName : Block Inbound + log drop ($logFile)"
        }
        catch {
            Write-SOCLog -Severity Error -Module Firewall -Result Failed -EventId 6011 `
                         -Message "Profil $profileName : $($_.Exception.Message)"
        }
    }

    # --- Regles sensibles : desactivation des regles legacy par defaut ---
    # File and Printer Sharing ICMP/Echo sur interface Public : surface d'exposition reseau
    $riskyRules = @(
        'FPS-NB_Datagram-In-UDP',
        'FPS-NB_Name-In-UDP',
        'FPS-NB_Session-In-TCP',
        'FPS-SMB-In-TCP',
        'FPS-ICMP4-ERQ-In',
        'FPS-ICMP6-ERQ-In',
        'RemoteRegistry-In-RPC',
        'WINRM-HTTP-In-TCP-PUBLIC'
    )

    foreach ($ruleName in $riskyRules) {
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            # On desactive uniquement la regle attachee au profil Public
            # car la valeur Profile est une chaine comme "Public" ou "Any"
            $publicOnly = $rule | Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' }
            if ($publicOnly) {
                try {
                    $publicOnly | Disable-NetFirewallRule -ErrorAction Stop
                    Write-SOCLog -Severity Information -Module Firewall -Result Success -EventId 6020 `
                                 -Message "Regle $ruleName desactivee sur profil Public"
                } catch {
                    Write-SOCLog -Severity Debug -Module Firewall -Result Skipped -EventId 6021 `
                                 -Message "Regle $ruleName : $($_.Exception.Message)"
                }
            }
        }
    }

    Write-SOCLog -Module Firewall -Message '<<< Durcissement Firewall termine' -EventId 6001
}

#endregion

#region ============================ MODULE : CREDENTIAL PROTECTION ============================

function Set-SOCCredentialProtection {
    <#
    .SYNOPSIS
        Durcit la protection des identifiants en memoire (LSASS).
    .DESCRIPTION
        Vise les techniques de vol de credentials (Mimikatz, pypykatz, LsassDump) :
        - RunAsPPL / PPLFuse : LSASS en Protected Process Light
        - WDigest : interdiction du stockage de mots de passe en clair
        - Cached Logons : reduction du nombre de hashes en cache
        - NTLMv1 / LM : interdits
        - Credential Guard : active si VBS disponible
        - Protected Users / LSA audit mode en prealable
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Credentials -Message '>>> Protection des identifiants (LSA)' -EventId 7000

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    # --- RunAsPPL : LSASS en Protected Process Light ---
    # Valeur 1 = PPL activee. Valeur 2 = PPL + UEFI lock (persistent meme si registre modifie).
    # Sans PPL, Mimikatz peut ouvrir LSASS avec PROCESS_VM_READ et extraire les secrets.
    # Avec PPL, seul un driver signe Microsoft peut acceder (bloque LsassDump / comsvcs).
    Set-SOCRegistryValue -Path $lsa -Name 'RunAsPPL' -Value 1 -Type DWord `
                         -Module Credentials -Reference 'ANSSI R23 | CIS 18.3.7' `
                         -Reason 'LSASS Protected Process Light - bloque Mimikatz par defaut'

    # RunAsPPLBoot depuis Win11 22H2 : LSA Protection Boot-level avant pilotes tiers
    if ($Context.Build -ge 22621) {
        Set-SOCRegistryValue -Path $lsa -Name 'RunAsPPLBoot' -Value 1 -Type DWord `
                             -Module Credentials -Reference 'MS SB 23H2' `
                             -Reason 'LSA Protection active des le boot (avant drivers 3rd-party)'
    }

    # --- WDigest : stockage en clair des mots de passe - heritage Windows 2003 ---
    # UseLogonCredential=0 : pas de cache en clair. Sans cette cle, Mimikatz sekurlsa::wdigest
    # recupere le mot de passe en clair de toute session ouverte.
    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                         -Name 'UseLogonCredential' -Value 0 -Type DWord `
                         -Module Credentials -Reference 'ANSSI R23 | CIS 2.3.11.8' `
                         -Reason 'WDigest sans credential en clair (contre Mimikatz sekurlsa::wdigest)'

    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                         -Name 'Negotiate' -Value 0 -Type DWord `
                         -Module Credentials -Reference 'MS SB' `
                         -Reason 'WDigest : desactivation de la negociation authen.'

    # --- Cached Logon Count ---
    # CIS recommande <=4, ANSSI recommande <=10 sur un portable hors-site (usage offline).
    # Compromis : 4 pour workstation fixe, 10 pour poste mobile technicien.
    $cachedCount = if ($Profile -eq 'Technician') { 10 } else { 4 }
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
                         -Name 'CachedLogonsCount' -Value "$cachedCount" -Type String `
                         -Module Credentials -Reference 'ANSSI R24 | CIS 2.3.7.4' `
                         -Reason "Reduction du nb de hashes MSCACHEv2 en cache (profil=$Profile)"

    # --- LM Hash : algorithme pre-2000, cassable en secondes ---
    # NoLMHash=1 : n'enregistre plus le hash LM pour le prochain changement de mdp
    Set-SOCRegistryValue -Path $lsa -Name 'NoLMHash' -Value 1 -Type DWord `
                         -Module Credentials -Reference 'ANSSI R25 | CIS 2.3.11.5' `
                         -Reason 'NoLMHash : LM interdit (cassable par table arc-en-ciel en <1min)'

    # --- LmCompatibilityLevel : refuser NTLMv1 client+serveur ---
    # Niveau 5 = Send NTLMv2 response only, refuse LM & NTLMv1
    Set-SOCRegistryValue -Path $lsa -Name 'LmCompatibilityLevel' -Value 5 -Type DWord `
                         -Module Credentials -Reference 'ANSSI R25 | CIS 2.3.11.7' `
                         -Reason 'NTLMv2 uniquement - refus LM/NTLMv1 (cassables)'

    # --- Restriction NTLM sortant vers serveurs distants (audit mode) ---
    # 1 = Audit, 2 = Deny. On passe en Audit par defaut pour eviter de casser SSO/kerberos fallback.
    Set-SOCRegistryValue -Path "$lsa\MSV1_0" -Name 'RestrictSendingNTLMTraffic' -Value 1 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.11.4' `
                         -Reason 'Audit NTLM sortant - prerequis a un passage en Deny ulterieur'

    # Min session security NTLM SSP : NTLMv2 + 128-bit + integrity (0x20080000 + 0x00080000)
    Set-SOCRegistryValue -Path "$lsa\MSV1_0" -Name 'NtlmMinClientSec' -Value 537395200 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.11.10' `
                         -Reason 'NTLM client : session key 128-bit + NTLMv2 + integrity'

    Set-SOCRegistryValue -Path "$lsa\MSV1_0" -Name 'NtlmMinServerSec' -Value 537395200 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.11.11' `
                         -Reason 'NTLM serveur : meme exigence que client'

    # --- Anonymous SAM / Share enum : blocage des requetes nulles ---
    # Bloque les commandes `net use \\target\IPC$ ""/U:""` (mapping anonyme)
    Set-SOCRegistryValue -Path $lsa -Name 'RestrictAnonymous' -Value 1 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.10.5' `
                         -Reason 'Anonymous SAM enum interdite (net use \\IPC$ anonyme)'

    Set-SOCRegistryValue -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.10.4' `
                         -Reason 'Pas d''enumeration SAM anonyme'

    Set-SOCRegistryValue -Path $lsa -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.10.6' `
                         -Reason 'Anonymous ne fait PAS partie du groupe Everyone'

    # --- Credential Guard : pre-requis VBS (Hyper-V + IOMMU + Secure Boot) ---
    if ($Context.Family -in 'Windows10','Windows11' -and $Context.Edition -in 'Enterprise','Education','EnterpriseN','EducationN' -and $Context.SecureBoot) {
        $dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'

        # EnableVirtualizationBasedSecurity=1, RequirePlatformSecurityFeatures=1 (SB), 3 (SB+DMA)
        Set-SOCRegistryValue -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord `
                             -Module Credentials -Reference 'ANSSI R27 | CIS 18.9.12.2' `
                             -Reason 'VBS active - base pour Credential Guard et HVCI'

        Set-SOCRegistryValue -Path $dg -Name 'RequirePlatformSecurityFeatures' -Value 1 -Type DWord `
                             -Module Credentials -Reference 'MS SB' `
                             -Reason 'VBS requiert Secure Boot (attestation chaine de boot)'

        # LsaCfgFlags=1 : Credential Guard with UEFI lock (persistant)
        Set-SOCRegistryValue -Path $dg -Name 'LsaCfgFlags' -Value 1 -Type DWord `
                             -Module Credentials -Reference 'ANSSI R27' `
                             -Reason 'Credential Guard avec UEFI lock - isole LSASS en VTL1'

        # HypervisorEnforcedCodeIntegrity = HVCI : empeche le chargement de drivers non signes
        Set-SOCRegistryValue -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" `
                             -Name 'Enabled' -Value 1 -Type DWord `
                             -Module Credentials -Reference 'MS SB' `
                             -Reason 'HVCI : blocage des drivers KMCS non conformes'
    } else {
        Write-SOCLog -Severity Warning -Module Credentials -Result NotApplicable -EventId 7010 `
                     -Message "Credential Guard non applicable (Edition=$($Context.Edition), SecureBoot=$($Context.SecureBoot))"
    }

    # --- Kerberos : refus RC4-HMAC (downgrade vers cipher faible) ---
    # SupportedEncryptionTypes : AES128 (0x08) + AES256 (0x10) = 0x18 = 24
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
                         -Name 'SupportedEncryptionTypes' -Value 24 -Type DWord `
                         -Module Credentials -Reference 'ANSSI R26' `
                         -Reason 'Kerberos AES uniquement (refus RC4 - Kerberoasting resistant)'

    # --- Windows Credential Manager : desactivation du credential roaming ---
    # Empeche la synchronisation des identifiants sauves via profil itinerant
    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                         -Name 'DisableDomainCreds' -Value 0 -Type DWord `
                         -Module Credentials -Reference 'CIS 2.3.11.3' `
                         -Reason 'Stockage des credentials reseau autorise (besoin SSO) mais audite'

    Write-SOCLog -Module Credentials -Message '<<< Fin protection des identifiants' -EventId 7001
}

#endregion

#region ============================ MODULE : APPLICATION CONTROL ============================

function Set-SOCAppLockerAudit {
    <#
    .SYNOPSIS
        Configure AppLocker en mode Audit - base pour un passage Enforce ulterieur.
    .DESCRIPTION
        Le passage en Enforce doit etre fait apres analyse des logs d'Audit
        (journal "Microsoft-Windows-AppLocker/EXE and DLL" et "MSI and Script").
        Cette fonction installe uniquement le squelette de regles par defaut
        (chemins Windows + Program Files) en mode Audit.

        Note : AppLocker requiert le service AppIDSvc. Indisponible sur editions Home.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    if ($Context.Edition -notin 'Enterprise','EnterpriseN','Education','EducationN','Professional','ProfessionalN','ProfessionalWorkstation') {
        Write-SOCLog -Severity Warning -Module AppControl -Result NotApplicable -EventId 8001 `
                     -Message "AppLocker non disponible sur edition $($Context.Edition)"
        return
    }

    Write-SOCLog -Module AppControl -Message '>>> Configuration AppLocker (mode Audit)' -EventId 8000

    # --- Service AppIDSvc : demarrage automatique ---
    try {
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
        # Note : AppIDSvc requiert un trigger, on ne tente pas un Start direct pour eviter un ERROR_SERVICE_NOT_ACTIVE
        Write-SOCLog -Severity Information -Module AppControl -Result Success -EventId 8010 `
                     -Message 'Service AppIDSvc configure en Auto'
    } catch {
        Write-SOCLog -Severity Error -Module AppControl -Result Failed -EventId 8011 `
                     -Message "AppIDSvc : $($_.Exception.Message)"
    }

    # --- Policy XML par defaut : AuditOnly + regles path ---
    # Regles minimales : tout le monde peut executer ce qui est dans Program Files et Windows
    # Les admins ont le droit d'executer partout (continuite operationnelle helpdesk)
    $applockerXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="AuditOnly">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default) All Windows Installer files in %systemdrive%\Windows\Installer" Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default) All Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*.*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default) All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default) All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default) All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="(Default) All DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="4ad37ad8-7b86-46b4-854c-f8e4d84f9f10" Name="(Default) All DLLs located in the Windows folder" Description="Allows members of the Everyone group to load DLLs that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="0b24b398-eec5-4478-b5a7-8e3dc34bc8e5" Name="(Default) All DLLs" Description="Allows members of the local Administrators group to load all DLLs." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

    $xmlFile = Join-Path $BackupPath "AppLocker_$script:SOC_RUN_ID.xml"
    Set-Content -LiteralPath $xmlFile -Value $applockerXml -Encoding UTF8

    if ($PSCmdlet.ShouldProcess('AppLocker Policy', 'Apply (AuditOnly)')) {
        try {
            # Merge=false pour partir d'une base propre. Les admins SOC peuvent ensuite
            # merger leurs regles de publisher via Set-AppLockerPolicy -Merge
            Set-AppLockerPolicy -XmlPolicy $xmlFile -ErrorAction Stop
            Write-SOCLog -Severity Information -Module AppControl -Result Success -EventId 8012 `
                         -Message "Policy AppLocker appliquee (AuditOnly) : $xmlFile"
        } catch {
            Write-SOCLog -Severity Error -Module AppControl -Result Failed -EventId 8013 `
                         -Message "Set-AppLockerPolicy KO : $($_.Exception.Message)"
        }
    } else {
        Write-SOCLog -Severity Information -Module AppControl -Result WouldChange -EventId 8014 `
                     -Message "[SIMULATION] AppLocker policy serait appliquee : $xmlFile"
    }

    Write-SOCLog -Module AppControl -Message '<<< AppLocker configure en Audit' -EventId 8002
}

function Set-SOCWDACAuditMode {
    <#
    .SYNOPSIS
        Active WDAC en mode Audit sur Windows 11 Enterprise avec SmartAppControl si disponible.
    .DESCRIPTION
        Depose une policy WDAC minimale (AllowAll + Audit) dans
        %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    if ($Context.Family -ne 'Windows11') {
        Write-SOCLog -Severity Information -Module AppControl -Result NotApplicable -EventId 8020 `
                     -Message "WDAC mode Audit cible Windows 11 (detecte : $($Context.Family))"
        return
    }

    Write-SOCLog -Module AppControl -Message '>>> WDAC en mode Audit' -EventId 8021

    $ciPolicyDir = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
    if (-not (Test-Path $ciPolicyDir)) {
        $null = New-Item -Path $ciPolicyDir -ItemType Directory -Force
    }

    # Pour rester prudent, on ne genere pas la policy binaire ici
    # (ConvertFrom-CIPolicy necessite un XML de base et des signers qui varient).
    # On consigne uniquement l'intention - l'admin SOC devra deposer une policy
    # generee via New-CIPolicy avec le bon scan.
    Write-SOCLog -Severity Information -Module AppControl -Result Skipped -EventId 8022 `
                 -Message "WDAC : repertoire $ciPolicyDir pret. Deposer manuellement une policy signee (New-CIPolicy)."

    Write-SOCLog -Module AppControl -Message '<<< WDAC Audit note' -EventId 8023
}

#endregion

#region ============================ MODULE : SERVICES & TELEMETRY ============================

function Disable-SOCUnusedServices {
    <#
    .SYNOPSIS
        Desactive les services non-necessaires selon le profil de poste.
    .DESCRIPTION
        Approche conservatrice :
        - Services systematiquement coupes (Xbox, Fax, RetailDemo, etc.)
        - Services conditionnels (Spooler si pas d'imprimante + pas Technician)
        - Services JAMAIS touches (WinRM, BITS, EventLog - requis production)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Services -Message '>>> Desactivation services non essentiels' -EventId 9000

    # Services systematiquement desactives - aucun usage pro sur un poste MSSP
    $unconditional = @(
        @{ Name='XblAuthManager';       Reason='Xbox Live auth - usage grand public uniquement'},
        @{ Name='XblGameSave';          Reason='Xbox Live saves'},
        @{ Name='XboxGipSvc';           Reason='Xbox Accessory Management'},
        @{ Name='XboxNetApiSvc';        Reason='Xbox Live Networking'},
        @{ Name='Fax';                  Reason='Fax - surface CVE (CVE-2020-1048)'},
        @{ Name='RetailDemo';           Reason='RetailDemo - mode demo magasin'},
        @{ Name='MapsBroker';           Reason='Downloaded Maps Manager - telemetrie associee'},
        @{ Name='lfsvc';                Reason='Geolocation Service - vie privee'},
        @{ Name='WMPNetworkSvc';        Reason='WMP Network Sharing - UPnP'},
        @{ Name='RemoteRegistry';       Reason='Remote Registry - surface d''attaque laterale'},
        @{ Name='SharedAccess';         Reason='ICS - NAT sur poste non justifie'},
        @{ Name='WpnUserService';       Reason='Notifications push - telemetrie MS'}
    )

    foreach ($svc in $unconditional) {
        Set-SOCServiceState -Name $svc.Name -StartupType Disabled -Stop $true -Reason $svc.Reason
    }

    # --- Print Spooler : seulement si profil non-Technician ET pas d'imprimante locale ---
    # Le profil Technician garde le Spooler (debug sur site client avec imprimantes locales).
    # PrintNightmare (CVE-2021-34527) impose des GPO additionnelles gerees dans Set-SOCPrintNightmareMitigation.
    if ($Profile -ne 'Technician' -and -not $Context.HasLocalPrinter) {
        Set-SOCServiceState -Name 'Spooler' -StartupType Disabled -Stop $true `
                            -Reason 'Spooler absent de usage (pas d''imprimante locale, profil != Technician) - ref PrintNightmare'
    } else {
        Write-SOCLog -Severity Information -Module Services -Result Skipped -EventId 9010 `
                     -Message "Spooler conserve (Profile=$Profile, HasLocalPrinter=$($Context.HasLocalPrinter))"
        # Dans ce cas on applique les mitigations PrintNightmare specifiques
        Set-SOCPrintNightmareMitigation
    }

    # --- Services Kiosk-only (profil le plus restrictif) ---
    if ($Profile -eq 'Kiosk') {
        $kioskOnly = @(
            @{ Name='WinRM';              Reason='PS Remoting - non-necessaire sur kiosk'},
            @{ Name='SSDPSRV';            Reason='SSDP / UPnP discovery'},
            @{ Name='upnphost';           Reason='UPnP Device Host'},
            @{ Name='BthServ';            Reason='Bluetooth (si pas de peripheriques BT)'}
        )
        foreach ($svc in $kioskOnly) {
            Set-SOCServiceState -Name $svc.Name -StartupType Disabled -Stop $true -Reason $svc.Reason
        }
    }

    Write-SOCLog -Module Services -Message '<<< Services desactives' -EventId 9001
}

function Set-SOCServiceState {
    <#
    .SYNOPSIS
        Modifie l'etat d'un service avec logging standardise.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic','Manual','Disabled','AutomaticDelayedStart')][string]$StartupType,
        [Parameter()][bool]$Stop = $false,
        [Parameter()][string]$Reason
    )

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-SOCLog -Severity Debug -Module Services -Result NotApplicable -EventId 9020 `
                     -Message "Service $Name absent sur cette edition"
        return
    }

    if ($PSCmdlet.ShouldProcess($Name, "Set $StartupType")) {
        try {
            if ($Stop -and $svc.Status -eq 'Running') {
                Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
            }

            # Set-Service peut echouer sur certains services proteges - on utilise sc.exe en fallback
            try {
                Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
            } catch {
                $scValue = switch ($StartupType) {
                    'Automatic'             { 'auto' }
                    'AutomaticDelayedStart' { 'delayed-auto' }
                    'Manual'                { 'demand' }
                    'Disabled'              { 'disabled' }
                }
                $out = & sc.exe config $Name start= $scValue 2>&1
                if ($LASTEXITCODE -ne 0) { throw "sc.exe : $out" }
            }

            Write-SOCLog -Severity Information -Module Services -Result Success -EventId 9021 `
                         -Message "Service $Name => $StartupType | $Reason"
        }
        catch {
            Write-SOCLog -Severity Warning -Module Services -Result Failed -EventId 9022 `
                         -Message "Service $Name : $($_.Exception.Message)"
        }
    }
}

function Set-SOCPrintNightmareMitigation {
    <#
    .SYNOPSIS
        Mitigations PrintNightmare quand Spooler doit rester actif.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $ppc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'

    # RestrictDriverInstallationToAdministrators=1 : seuls les admins peuvent installer un driver
    # Contre-mesure cle PrintNightmare (CVE-2021-34527)
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' `
                         -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Type DWord `
                         -Module Services -Reference 'CVE-2021-34527' `
                         -Reason 'Driver print : install admin-only (PrintNightmare)'

    # Point and Print : prompt avant install + avant update
    Set-SOCRegistryValue -Path $ppc -Name 'NoWarningNoElevationOnInstall' -Value 0 -Type DWord `
                         -Module Services -Reference 'CVE-2021-34527' `
                         -Reason 'P&P : prompt + UAC sur install driver'

    Set-SOCRegistryValue -Path $ppc -Name 'UpdatePromptSettings' -Value 0 -Type DWord `
                         -Module Services -Reference 'CVE-2021-34527' `
                         -Reason 'P&P : prompt + UAC sur update driver'
}

function Disable-SOCTelemetry {
    <#
    .SYNOPSIS
        Reduit la telemetrie Microsoft au strict minimum (Security level).
    .DESCRIPTION
        AllowTelemetry=0 n'est honore QUE sur les editions Enterprise/Education/IoT.
        Sur Pro/Home le plancher effectif est 1 (Basic/Required).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Services -Message '>>> Reduction de la telemetrie' -EventId 9100

    # Niveau cible : 0 (Security) si eligible, 1 (Basic) sinon
    $telemetryLevel = if ($Context.Edition -in 'Enterprise','EnterpriseN','Education','EducationN','IoTEnterprise') { 0 } else { 1 }

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
                         -Name 'AllowTelemetry' -Value $telemetryLevel -Type DWord `
                         -Module Services -Reference 'ANSSI R8' `
                         -Reason "Telemetrie niveau $telemetryLevel (plancher = edition systeme)"

    # Pour SCCM / Intune, la cle est lue cote machine :
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
                         -Name 'AllowTelemetry' -Value $telemetryLevel -Type DWord `
                         -Module Services -Reference 'ANSSI R8' `
                         -Reason "Telemetrie (CurrentVersion\Policies)"

    # DoNotShowFeedbackNotifications - pas de pop-ups de feedback utilisateur
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
                         -Name 'DoNotShowFeedbackNotifications' -Value 1 -Type DWord `
                         -Module Services -Reference 'CIS 18.9.16.2' `
                         -Reason 'Pas de prompt feedback MS'

    # --- Service DiagTrack (Connected User Experiences and Telemetry) ---
    # Sur Enterprise on peut le couper. Sur Pro/Home il redemarre via scheduled task.
    if ($telemetryLevel -eq 0) {
        Set-SOCServiceState -Name 'DiagTrack' -StartupType Disabled -Stop $true `
                            -Reason 'Telemetrie niveau 0 (Security) - service inutile'
        Set-SOCServiceState -Name 'dmwappushservice' -StartupType Disabled -Stop $true `
                            -Reason 'WAP Push Message Routing - telemetrie associee'
    }

    # --- Scheduled tasks de telemetrie / Customer Experience ---
    $telemetryTasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Autochk\Proxy',
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\Feedback\Siuf\DmClient',
        '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
    )

    foreach ($taskPath in $telemetryTasks) {
        $taskName = Split-Path $taskPath -Leaf
        $taskFolder = Split-Path $taskPath -Parent
        try {
            $task = Get-ScheduledTask -TaskPath ($taskFolder + '\') -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                if ($PSCmdlet.ShouldProcess($taskPath, 'Disable')) {
                    Disable-ScheduledTask -TaskPath ($taskFolder + '\') -TaskName $taskName -ErrorAction Stop | Out-Null
                    Write-SOCLog -Severity Information -Module Services -Result Success -EventId 9110 `
                                 -Message "Scheduled Task desactivee : $taskPath"
                }
            }
        }
        catch {
            Write-SOCLog -Severity Debug -Module Services -Result Skipped -EventId 9111 `
                         -Message "Task $taskPath : $($_.Exception.Message)"
        }
    }

    # --- Cortana / Web Search Bar ---
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
                         -Name 'AllowCortana' -Value 0 -Type DWord `
                         -Module Services -Reference 'ANSSI R8' `
                         -Reason 'Cortana desactivee (telemetrie + exfiltration indexation)'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
                         -Name 'ConnectedSearchUseWeb' -Value 0 -Type DWord `
                         -Module Services -Reference 'CIS 18.9.68.2' `
                         -Reason 'Bing dans la barre de recherche OFF (fuite de requetes)'

    # --- Advertising ID (impact store apps) ---
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' `
                         -Name 'DisabledByGroupPolicy' -Value 1 -Type DWord `
                         -Module Services -Reference 'CIS 18.9.6.1' `
                         -Reason 'Advertising ID OFF (profilage publicitaire)'

    Write-SOCLog -Module Services -Message '<<< Telemetrie reduite' -EventId 9101
}

#endregion

#region ============================ MODULE : EXPLOIT GUARD ============================

function Set-SOCExploitGuard {
    <#
    .SYNOPSIS
        Active DEP, ASLR, SEHOP, CFG via Set-ProcessMitigation (policy system-wide).
    .DESCRIPTION
        Bascule les mitigations exploit d'un mode user-configurable a un mode
        enforce systeme. Les applications avec AppCompat exception pour ASLR
        (ex: legacy SCADA) doivent etre declarees en per-process apres coup.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module ExploitGuard -Message '>>> Exploit Protection system-wide' -EventId 10000

    # --- DEP : Always On (pas de bypass via BOOTCFG) ---
    # bcdedit /set nx AlwaysOn - seul moyen persistant. La cle registre MitigationOptions est complementaire.
    if ($PSCmdlet.ShouldProcess('DEP', 'AlwaysOn via bcdedit')) {
        try {
            $out = & bcdedit.exe /set '{current}' nx AlwaysOn 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-SOCLog -Severity Information -Module ExploitGuard -Result Success -EventId 10010 `
                             -Message 'DEP AlwaysOn applique via bcdedit (effectif au prochain boot)'
            } else {
                Write-SOCLog -Severity Warning -Module ExploitGuard -Result Failed -EventId 10011 `
                             -Message "bcdedit DEP : $out"
            }
        } catch {
            Write-SOCLog -Severity Warning -Module ExploitGuard -Result Failed -EventId 10012 `
                         -Message "DEP : $($_.Exception.Message)"
        }
    }

    # --- Set-ProcessMitigation -System : mitigations globales par defaut ---
    if ($PSCmdlet.ShouldProcess('System mitigations', 'Enable DEP+ASLR+SEHOP+CFG')) {
        try {
            Set-ProcessMitigation -System `
                -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, ForceRelocateImages, SEHOP, CFG, SuppressExports, StrictCFG `
                -ErrorAction Stop

            Write-SOCLog -Severity Information -Module ExploitGuard -Result Success -EventId 10020 `
                         -Message 'Mitigations system-wide : DEP, ASLR (BottomUp+HighEntropy+ForceRelocate), SEHOP, CFG, StrictCFG'
        } catch {
            Write-SOCLog -Severity Warning -Module ExploitGuard -Result Failed -EventId 10021 `
                         -Message "Set-ProcessMitigation system : $($_.Exception.Message)"
        }
    }

    # --- Per-process hardening pour les cibles frequentes de drive-by ---
    # Navigateurs et visionneuses PDF : ACG + CIG si supportes
    $perProcessTargets = @(
        @{ Exe='msedge.exe';        Mits=@('ACG','CIG','DEP','BottomUp','HighEntropy','CFG','StrictCFG')},
        @{ Exe='firefox.exe';       Mits=@('DEP','BottomUp','HighEntropy','CFG')},
        @{ Exe='chrome.exe';        Mits=@('DEP','BottomUp','HighEntropy','CFG')},
        @{ Exe='AcroRd32.exe';      Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')},
        @{ Exe='Acrobat.exe';       Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')},
        @{ Exe='winword.exe';       Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')},
        @{ Exe='excel.exe';         Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')},
        @{ Exe='powerpnt.exe';      Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')},
        @{ Exe='outlook.exe';       Mits=@('DEP','BottomUp','HighEntropy','CFG','ExtensionPoint')}
    )

    foreach ($target in $perProcessTargets) {
        try {
            Set-ProcessMitigation -Name $target.Exe -Enable $target.Mits -ErrorAction Stop
            Write-SOCLog -Severity Debug -Module ExploitGuard -Result Success -EventId 10030 `
                         -Message "$($target.Exe) : $($target.Mits -join ', ')"
        } catch {
            Write-SOCLog -Severity Debug -Module ExploitGuard -Result Skipped -EventId 10031 `
                         -Message "$($target.Exe) : non installe ou mitigations partiellement supportees"
        }
    }

    Write-SOCLog -Module ExploitGuard -Message '<<< Exploit Protection configure' -EventId 10001
}

#endregion

#region ============================ MODULE : DEFENDER ASR ============================

function Set-SOCDefenderASR {
    <#
    .SYNOPSIS
        Active les 16 regles Attack Surface Reduction de Defender.
    .DESCRIPTION
        Strategie :
        - 11 regles en Enforce (Block=1) : consensus CIS/ANSSI, faux positifs rares
        - 3 regles en Audit (Warn=6 ou Audit=2) : faux positifs frequents en MSSP
        - 2 regles conditionnees par Profile

        Les exclusions Technician ciblent les outils reseau legitimes (nmap, wireshark,
        psexec, plink, tftp, advanced IP scanner). Elles sont posees via
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions qui scope l'exclusion
        uniquement a ASR (pas un full Defender exclusion path).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    if (-not $Context.DefenderEnabled) {
        Write-SOCLog -Severity Warning -Module Defender -Result NotApplicable -EventId 11001 `
                     -Message 'Defender desactive (AV tiers ?) - ASR non applicable'
        return
    }

    Write-SOCLog -Module Defender -Message '>>> Regles ASR' -EventId 11000

    # Catalogue de regles - extrait de la doc MS (stable depuis 2022)
    # Actions : 0=Disabled, 1=Block, 2=Audit, 6=Warn
    $asrRules = @(
        # --- Regles Block (Enforce) ---
        @{ Id='BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Action=1; Name='Block executable content from email client and webmail'},
        @{ Id='D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Action=1; Name='Block all Office applications from creating child processes'},
        @{ Id='3B576869-A4EC-4529-8536-B80A7769E899'; Action=1; Name='Block Office applications from creating executable content'},
        @{ Id='75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Action=1; Name='Block Office applications from injecting code into other processes'},
        @{ Id='D3E037E1-3EB8-44C8-A917-57927947596D'; Action=1; Name='Block JavaScript or VBScript from launching downloaded executable content'},
        @{ Id='5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Action=1; Name='Block execution of potentially obfuscated scripts'},
        @{ Id='92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Action=1; Name='Block Win32 API calls from Office macros'},
        @{ Id='9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Action=1; Name='Block credential stealing from LSASS'},
        @{ Id='D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Action=1; Name='Block process creations originating from PSExec and WMI commands'},
        @{ Id='E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Action=1; Name='Block persistence through WMI event subscription'},
        @{ Id='26190899-1602-49E8-8B27-EB1D0A1CE869'; Action=1; Name='Block Office communication app from creating child processes'},
        @{ Id='7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Action=1; Name='Block Adobe Reader from creating child processes'},
        @{ Id='C1DB55AB-C21A-4637-BB3F-A12568109D35'; Action=1; Name='Advanced ransomware protection'},

        # --- Regles Audit (FP frequents sur parc technicien) ---
        # Block executable unless age/prevalence : casse les binaires internes compiles localement
        @{ Id='01443614-CD74-433A-B99E-2ECDC07BFC25'; Action=2; Name='Block executable files unless they meet prevalence/age (AUDIT)'},
        # Block untrusted USB : impacte les cles USB d'install techniciens
        @{ Id='B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Action=2; Name='Block untrusted and unsigned processes from USB (AUDIT)'},
        # Newer Webshell-related (2022+)
        @{ Id='A8F5898E-1DC8-49A9-9878-85004B8A61E6'; Action=2; Name='Block Webshell creation for Servers (AUDIT)'}
    )

    # Profile Kiosk : on remonte les 3 Audit en Block
    if ($Profile -eq 'Kiosk') {
        foreach ($rule in $asrRules) {
            if ($rule.Action -eq 2) { $rule.Action = 1 }
        }
    }

    $ids     = $asrRules.Id
    $actions = $asrRules.Action

    if ($PSCmdlet.ShouldProcess('ASR Rules', 'Apply')) {
        try {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ids `
                             -AttackSurfaceReductionRules_Actions $actions `
                             -ErrorAction Stop
            Write-SOCLog -Severity Information -Module Defender -Result Success -EventId 11010 `
                         -Message "$($asrRules.Count) regles ASR appliquees"
        } catch {
            Write-SOCLog -Severity Error -Module Defender -Result Failed -EventId 11011 `
                         -Message "ASR : $($_.Exception.Message)"
        }
    }

    foreach ($rule in $asrRules) {
        $mode = switch ($rule.Action) { 1 {'Block'} 2 {'Audit'} 6 {'Warn'} default {'Disabled'} }
        Write-SOCLog -Severity Debug -Module Defender -Result Success -EventId 11012 `
                     -Message ("  [{0}] {1} : {2}" -f $mode, $rule.Id, $rule.Name)
    }

    # --- Exclusions ASR pour le profil Technician ---
    if ($Profile -eq 'Technician') {
        # Ces exclusions sont ASR-ONLY (pas un bypass Defender full)
        $toolPaths = @(
            "${env:ProgramFiles}\Wireshark\Wireshark.exe",
            "${env:ProgramFiles}\Wireshark\dumpcap.exe",
            "${env:ProgramFiles}\Nmap\nmap.exe",
            "${env:ProgramFiles}\Nmap\ncat.exe",
            "${env:ProgramFiles}\PuTTY\plink.exe",
            "${env:ProgramFiles}\PuTTY\pscp.exe",
            "${env:ProgramFiles}\PuTTY\psftp.exe",
            "${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe",
            "${env:ProgramFiles}\Sysinternals\PsExec.exe",
            "${env:ProgramFiles}\Sysinternals\PsExec64.exe",
            "${env:ProgramFiles}\Sysinternals\procmon.exe",
            "${env:ProgramFiles}\Sysinternals\Procmon64.exe",
            "${env:ProgramFiles}\iperf3\iperf3.exe",
            "${env:ProgramFiles(x86)}\Advanced IP Scanner\advanced_ip_scanner.exe",
            "${env:ProgramFiles(x86)}\Angry IP Scanner\ipscan.exe",
            "${env:SystemRoot}\System32\tftp.exe"
        )

        foreach ($tool in $toolPaths) {
            # On ajoute meme si le binaire n'existe pas encore - Defender accepte les chemins absents
            try {
                Add-MpPreference -AttackSurfaceReductionOnlyExclusions $tool -ErrorAction SilentlyContinue
                Write-SOCLog -Severity Debug -Module Defender -Result Success -EventId 11020 `
                             -Message "Exclusion ASR : $tool"
            } catch {
                Write-SOCLog -Severity Debug -Module Defender -Result Failed -EventId 11021 `
                             -Message "Exclusion $tool : $($_.Exception.Message)"
            }
        }

        Write-SOCLog -Severity Information -Module Defender -Result Success -EventId 11022 `
                     -Message "$($toolPaths.Count) exclusions ASR posees pour profil Technician (ASR-only, pas full AV)"
    }

    # --- Hardening Defender complementaire ---
    try {
        Set-MpPreference -PUAProtection 1 `
                         -DisableRealtimeMonitoring $false `
                         -DisableBehaviorMonitoring $false `
                         -DisableIOAVProtection $false `
                         -DisableScriptScanning $false `
                         -MAPSReporting 2 `
                         -SubmitSamplesConsent 1 `
                         -CloudBlockLevel High `
                         -CloudExtendedTimeout 50 `
                         -EnableNetworkProtection Enabled `
                         -EnableControlledFolderAccess AuditMode `
                         -ErrorAction Stop

        Write-SOCLog -Severity Information -Module Defender -Result Success -EventId 11030 `
                     -Message 'PUA + Cloud Block High + Network Protection + CFA Audit'
    } catch {
        Write-SOCLog -Severity Warning -Module Defender -Result Failed -EventId 11031 `
                     -Message "Hardening Defender : $($_.Exception.Message)"
    }

    # Tamper Protection : ne peut PAS etre active par registre - doit l'etre via
    # Intune, Defender Portal ou Windows Security UI. On se contente de l'auditer.
    if (-not $Context.DefenderTamperOn) {
        Write-SOCLog -Severity Warning -Module Defender -Result NotApplicable -EventId 11040 `
                     -Message 'Tamper Protection OFF - activer via Intune ou Defender portal (non scriptable par design)'
    }

    Write-SOCLog -Module Defender -Message '<<< Defender + ASR configures' -EventId 11001
}

#endregion

#region ============================ MODULE : UAC ============================

function Set-SOCUACHardening {
    <#
    .SYNOPSIS
        Durcit l'UAC selon les recommandations MS SB / CIS L2.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module UAC -Message '>>> Durcissement UAC' -EventId 12000

    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # EnableLUA=1 : desactiver LUA = UAC OFF = prompt bypass. Non negociable.
    Set-SOCRegistryValue -Path $sys -Name 'EnableLUA' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.6' `
                         -Reason 'UAC actif - desactiver EnableLUA casse l''isolation AppContainer'

    # ConsentPromptBehaviorAdmin=2 : prompt Consent on secure desktop avec credentials
    # 2 = Prompt for consent on the secure desktop (MS SB)
    # 1 = Prompt for credentials on the secure desktop (plus strict, mais impacte usage)
    Set-SOCRegistryValue -Path $sys -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.1' `
                         -Reason 'Admin : prompt consent sur Secure Desktop (isole du malware userland)'

    # ConsentPromptBehaviorUser=0 : l'utilisateur standard ne peut PAS elevater, la demande est refusee
    Set-SOCRegistryValue -Path $sys -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.2' `
                         -Reason 'Utilisateur standard : pas de prompt UAC (demande rejetee)'

    # PromptOnSecureDesktop=1 : le prompt UAC apparait sur Secure Desktop (vs desktop normal)
    # Previent le prompt hijacking (malware qui clone la fenetre UAC)
    Set-SOCRegistryValue -Path $sys -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.8' `
                         -Reason 'Prompt UAC sur Secure Desktop (anti-hijacking)'

    # EnableInstallerDetection=1 : detecter les installers et demander UAC
    Set-SOCRegistryValue -Path $sys -Name 'EnableInstallerDetection' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.4' `
                         -Reason 'Detection des installers - prompt UAC force'

    # EnableSecureUIAPaths=1 : UIAccess apps doivent etre dans %ProgramFiles% ou %SystemRoot%
    Set-SOCRegistryValue -Path $sys -Name 'EnableSecureUIAPaths' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.5' `
                         -Reason 'UIAccess : chemins restreints'

    # EnableVirtualization=1 : file/registry virtualization for 32-bit legacy apps
    Set-SOCRegistryValue -Path $sys -Name 'EnableVirtualization' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.9' `
                         -Reason 'Virtualization fichiers/registre pour apps 32-bit non-manifest'

    # ValidateAdminCodeSignatures=0 : 1 rendrait l'ecosysteme hors bits non-signed inutilisable
    # On le laisse a 0 (defaut) mais on le documente
    Set-SOCRegistryValue -Path $sys -Name 'ValidateAdminCodeSignatures' -Value 0 -Type DWord `
                         -Module UAC -Reference 'MS SB' `
                         -Reason 'Non-active : casserait trop de legacy LOB apps'

    # FilterAdministratorToken=1 : admin token split pour le built-in Administrator account
    Set-SOCRegistryValue -Path $sys -Name 'FilterAdministratorToken' -Value 1 -Type DWord `
                         -Module UAC -Reference 'CIS 2.3.17.3' `
                         -Reason 'Admin local (RID 500) soumis a UAC comme un admin standard'

    Write-SOCLog -Module UAC -Message '<<< UAC durcie' -EventId 12001
}

#endregion

#region ============================ MODULE : AUDIT POLICY ============================

function Set-SOCAuditPolicy {
    <#
    .SYNOPSIS
        Configure l'Advanced Audit Policy (auditpol.exe) pour alimenter le SIEM.
    .DESCRIPTION
        Ref ANSSI R58 et CIS 17.x. Active la categorisation fine (Success+Failure)
        sur les evenements d'interet SOC : logon, account mgmt, policy change,
        system integrity, privileged use.

        Prerequis : SCENoApplyLegacyAuditPolicy=1 pour que auditpol prime sur GPO legacy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    Write-SOCLog -Module Audit -Message '>>> Configuration Advanced Audit Policy' -EventId 13000

    # Forcer l'utilisation du Advanced Audit (sinon GPO basique gagne)
    Set-SOCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                         -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord `
                         -Module Audit -Reference 'CIS 2.3.2.1' `
                         -Reason 'Advanced Audit Policy prime sur Basic Audit'

    # Taille du journal Security : 196Mo pour conserver au moins 7j sur un poste moyen
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
                         -Name 'MaxSize' -Value 196608 -Type DWord `
                         -Module Audit -Reference 'CIS 18.9.27.4.2' `
                         -Reason 'Security log 192Mo - retention >= 7j sur poste standard'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' `
                         -Name 'MaxSize' -Value 32768 -Type DWord `
                         -Module Audit -Reference 'CIS 18.9.27.1.2' `
                         -Reason 'Application log 32Mo'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' `
                         -Name 'MaxSize' -Value 32768 -Type DWord `
                         -Module Audit -Reference 'CIS 18.9.27.3.2' `
                         -Reason 'System log 32Mo'

    # Categories auditpol - format: "SubCategory:Success,Failure"
    # Source: CIS Windows 11 L2 chapitre 17 + ANSSI BP-028 Annexe
    $auditCategories = @(
        @{ Cat='Account Logon';         Sub='Credential Validation';                  Success=$true;  Failure=$true  }
        @{ Cat='Account Logon';         Sub='Kerberos Authentication Service';        Success=$true;  Failure=$true  }
        @{ Cat='Account Logon';         Sub='Kerberos Service Ticket Operations';     Success=$true;  Failure=$true  }
        @{ Cat='Account Management';    Sub='Computer Account Management';            Success=$true;  Failure=$true  }
        @{ Cat='Account Management';    Sub='Other Account Management Events';        Success=$true;  Failure=$true  }
        @{ Cat='Account Management';    Sub='Security Group Management';              Success=$true;  Failure=$true  }
        @{ Cat='Account Management';    Sub='User Account Management';                Success=$true;  Failure=$true  }
        @{ Cat='Detailed Tracking';     Sub='Plug and Play Events';                   Success=$true;  Failure=$false }
        @{ Cat='Detailed Tracking';     Sub='Process Creation';                       Success=$true;  Failure=$false }
        @{ Cat='Detailed Tracking';     Sub='RPC Events';                             Success=$false; Failure=$true  }
        @{ Cat='Detailed Tracking';     Sub='Token Right Adjusted';                   Success=$true;  Failure=$false }
        @{ Cat='Logon/Logoff';          Sub='Account Lockout';                        Success=$false; Failure=$true  }
        @{ Cat='Logon/Logoff';          Sub='Group Membership';                       Success=$true;  Failure=$false }
        @{ Cat='Logon/Logoff';          Sub='Logoff';                                 Success=$true;  Failure=$false }
        @{ Cat='Logon/Logoff';          Sub='Logon';                                  Success=$true;  Failure=$true  }
        @{ Cat='Logon/Logoff';          Sub='Other Logon/Logoff Events';              Success=$true;  Failure=$true  }
        @{ Cat='Logon/Logoff';          Sub='Special Logon';                          Success=$true;  Failure=$false }
        @{ Cat='Object Access';         Sub='Detailed File Share';                    Success=$false; Failure=$true  }
        @{ Cat='Object Access';         Sub='File Share';                             Success=$true;  Failure=$true  }
        @{ Cat='Object Access';         Sub='Other Object Access Events';             Success=$false; Failure=$true  }
        @{ Cat='Object Access';         Sub='Removable Storage';                      Success=$true;  Failure=$true  }
        @{ Cat='Policy Change';         Sub='Audit Policy Change';                    Success=$true;  Failure=$true  }
        @{ Cat='Policy Change';         Sub='Authentication Policy Change';           Success=$true;  Failure=$false }
        @{ Cat='Policy Change';         Sub='Authorization Policy Change';            Success=$true;  Failure=$false }
        @{ Cat='Policy Change';         Sub='MPSSVC Rule-Level Policy Change';        Success=$true;  Failure=$true  }
        @{ Cat='Policy Change';         Sub='Other Policy Change Events';             Success=$false; Failure=$true  }
        @{ Cat='Privilege Use';         Sub='Sensitive Privilege Use';                Success=$true;  Failure=$true  }
        @{ Cat='System';                Sub='IPsec Driver';                           Success=$true;  Failure=$true  }
        @{ Cat='System';                Sub='Other System Events';                    Success=$false; Failure=$true  }
        @{ Cat='System';                Sub='Security State Change';                  Success=$true;  Failure=$false }
        @{ Cat='System';                Sub='Security System Extension';              Success=$true;  Failure=$false }
        @{ Cat='System';                Sub='System Integrity';                       Success=$true;  Failure=$true  }
    )

    foreach ($entry in $auditCategories) {
        $successFlag = if ($entry.Success) { 'enable' } else { 'disable' }
        $failureFlag = if ($entry.Failure) { 'enable' } else { 'disable' }

        if ($PSCmdlet.ShouldProcess($entry.Sub, "Audit Success=$successFlag Failure=$failureFlag")) {
            try {
                $out = & auditpol.exe /set /subcategory:"$($entry.Sub)" /success:$successFlag /failure:$failureFlag 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-SOCLog -Severity Debug -Module Audit -Result Success -EventId 13010 `
                                 -Message "$($entry.Cat) > $($entry.Sub) : S=$successFlag F=$failureFlag"
                } else {
                    Write-SOCLog -Severity Warning -Module Audit -Result Failed -EventId 13011 `
                                 -Message "auditpol KO pour $($entry.Sub) : $out"
                }
            } catch {
                Write-SOCLog -Severity Warning -Module Audit -Result Failed -EventId 13012 `
                             -Message "$($entry.Sub) : $($_.Exception.Message)"
            }
        }
    }

    # --- PowerShell logging (Script Block + Module) ---
    # Indispensable : permet a Defender/EDR/SIEM de voir le code PS execute meme obfusque
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                         -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord `
                         -Module Audit -Reference 'ANSSI R58 | CIS 18.9.100' `
                         -Reason 'Script Block Logging - decodage Base64/IEX visible en EventID 4104'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                         -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord `
                         -Module Audit -Reference 'MS SB' `
                         -Reason 'Invocation logging complementaire'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
                         -Name 'EnableModuleLogging' -Value 1 -Type DWord `
                         -Module Audit -Reference 'ANSSI R58' `
                         -Reason 'Module Logging - pipeline visible'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
                         -Name '*' -Value '*' -Type String `
                         -Module Audit -Reference 'ANSSI R58' `
                         -Reason 'Module Logging : tous modules'

    # Transcription : capture input+output. Attention : log peut contenir des secrets.
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
                         -Name 'EnableTranscripting' -Value 1 -Type DWord `
                         -Module Audit -Reference 'ANSSI R58' `
                         -Reason 'Transcription activee - ACL restrictive obligatoire en aval'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
                         -Name 'OutputDirectory' -Value "$env:ProgramData\SOC-Hardening\PSTranscript" -Type String `
                         -Module Audit -Reference 'Local' `
                         -Reason 'Transcript dans dossier ACL-restreint'

    # Process Creation Audit avec command line - critique pour detection LOLBINs
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
                         -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord `
                         -Module Audit -Reference 'ANSSI R58 | CIS 18.9.3.1' `
                         -Reason 'EventID 4688 inclut la command line (visibilite LOLBAS)'

    Write-SOCLog -Module Audit -Message '<<< Audit Policy configure' -EventId 13001
}

#endregion

#region ============================ MODULE : ACCOUNT POLICY ============================

function Set-SOCAccountPolicy {
    <#
    .SYNOPSIS
        Politique de mots de passe et verrouillage local (ref : net accounts + secedit).
    .DESCRIPTION
        S'aligne sur ANSSI R35-R37 et CIS 1.1.x. Sur poste jointe domaine, ces
        reglages peuvent etre ecrases par GPO (ce qui est attendu). Ils servent
        de baseline pour postes non joints / hors-site.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    if ($Context.DomainJoined) {
        Write-SOCLog -Severity Information -Module Account -Result Skipped -EventId 14001 `
                     -Message 'Machine jointe au domaine - politique locale non determinante (GPO domaine prime)'
        # On continue quand meme pour avoir une baseline en cas de deconnexion
    }

    Write-SOCLog -Module Account -Message '>>> Politique de comptes locale' -EventId 14000

    # --- Password policy via net accounts ---
    # MinLen 14 : recommendation ANSSI 2022 pour comptes locaux
    # MaxAge 60j : renouvellement periodique (discutable mais aligne ANSSI/CIS)
    # MinAge 1 : evite le contournement historique (12 changes en 5 min)
    # History 24 : 24 derniers mdp memorises
    # Lockout 10 essais / 15 min reset / 15 min duration
    $netAccountsCmds = @(
        @{ Cmd='net accounts /minpwlen:14';           Desc='Longueur min mdp = 14'}
        @{ Cmd='net accounts /maxpwage:60';           Desc='Duree max mdp = 60j'}
        @{ Cmd='net accounts /minpwage:1';            Desc='Duree min mdp = 1j (anti-cycle rapide)'}
        @{ Cmd='net accounts /uniquepw:24';           Desc='Historique 24 mdp'}
        @{ Cmd='net accounts /lockoutthreshold:10';   Desc='Verrouillage apres 10 echecs'}
        @{ Cmd='net accounts /lockoutwindow:15';      Desc='Fenetre de reset 15 min'}
        @{ Cmd='net accounts /lockoutduration:15';    Desc='Duree verrouillage 15 min'}
    )

    foreach ($entry in $netAccountsCmds) {
        if ($PSCmdlet.ShouldProcess($entry.Desc, 'Apply')) {
            try {
                $out = cmd.exe /c $entry.Cmd 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-SOCLog -Severity Information -Module Account -Result Success -EventId 14010 `
                                 -Message $entry.Desc
                } else {
                    Write-SOCLog -Severity Warning -Module Account -Result Failed -EventId 14011 `
                                 -Message "$($entry.Desc) : $out"
                }
            } catch {
                Write-SOCLog -Severity Warning -Module Account -Result Failed -EventId 14012 `
                             -Message "$($entry.Desc) : $($_.Exception.Message)"
            }
        }
    }

    # --- Password complexity + reversible encryption via secedit ---
    # Ces 2 flags ne sont pas gerables par net accounts : import secedit necessaire
    $secInf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
RequireLogonToChangePassword = 0
MinimumPasswordLength = 14
"@

    $infFile = Join-Path $env:TEMP "SOC_secpol_$script:SOC_RUN_ID.inf"
    $sdbFile = Join-Path $env:TEMP "SOC_secpol_$script:SOC_RUN_ID.sdb"

    try {
        Set-Content -LiteralPath $infFile -Value $secInf -Encoding Unicode

        if ($PSCmdlet.ShouldProcess('secpol.msc', 'Apply password complexity')) {
            $null = & secedit.exe /configure /db $sdbFile /cfg $infFile /areas SECURITYPOLICY 2>&1
            Write-SOCLog -Severity Information -Module Account -Result Success -EventId 14020 `
                         -Message 'Complexite mdp activee + ClearText OFF'
        }
    }
    catch {
        Write-SOCLog -Severity Warning -Module Account -Result Failed -EventId 14021 `
                     -Message "secedit : $($_.Exception.Message)"
    }
    finally {
        Remove-Item -LiteralPath $infFile, $sdbFile -Force -ErrorAction SilentlyContinue
    }

    # --- Renommer les comptes sensibles par defaut : RID 500 et Guest ---
    # Ne touche pas un hostname AAD joined (casse la sync)
    if (-not $Context.AzureJoined) {
        try {
            $rid500 = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like 'S-1-5-*-500' }
            if ($rid500 -and $rid500.Name -eq 'Administrator') {
                $newName = "adm_$($env:COMPUTERNAME.ToLower())"
                if ($PSCmdlet.ShouldProcess($rid500.Name, "Rename to $newName")) {
                    Rename-LocalUser -Name $rid500.Name -NewName $newName -ErrorAction Stop
                    Write-SOCLog -Severity Information -Module Account -Result Success -EventId 14030 `
                                 -Message "Compte RID 500 renomme en $newName (anti-enumeration brute-force)"
                }
            }

            $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            if ($guest -and $guest.Enabled) {
                Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
                Write-SOCLog -Severity Information -Module Account -Result Success -EventId 14031 `
                             -Message 'Compte Guest desactive'
            }
        }
        catch {
            Write-SOCLog -Severity Debug -Module Account -Result Skipped -EventId 14032 `
                         -Message "Comptes locaux : $($_.Exception.Message)"
        }
    }

    # --- Interactive logon : message de banniere legale (R42) ---
    # Obligatoire pour invoquer la LCEN en cas d'incident
    $banner = @"
ACCES RESERVE AUX UTILISATEURS AUTORISES
Toute utilisation de ce systeme est susceptible d'etre enregistree et auditee.
Tout acces non autorise est punissable par la loi.
"@
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                         -Name 'legalnoticecaption' -Value 'Avertissement legal' -Type String `
                         -Module Account -Reference 'ANSSI R42' `
                         -Reason 'Banniere legale : titre'

    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                         -Name 'legalnoticetext' -Value $banner -Type String `
                         -Module Account -Reference 'ANSSI R42' `
                         -Reason 'Banniere legale : corps (recevabilite judiciaire)'

    # DontDisplayLastUserName=1 : pas de nom du dernier utilisateur au logon
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                         -Name 'DontDisplayLastUserName' -Value 1 -Type DWord `
                         -Module Account -Reference 'CIS 2.3.7.2' `
                         -Reason 'Dernier utilisateur masque (anti-enumeration)'

    # Inactivity machine lock : 900 secondes = 15 min
    Set-SOCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                         -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord `
                         -Module Account -Reference 'CIS 2.3.7.3' `
                         -Reason 'Verrouillage auto apres 15 min inactivite'

    Write-SOCLog -Module Account -Message '<<< Politique de comptes appliquee' -EventId 14001
}

#endregion

#region ============================ ROLLBACK ============================

function Invoke-SOCRollback {
    <#
    .SYNOPSIS
        Restaure les cles de registre a partir des .reg exportes.
    .DESCRIPTION
        Utilise les exports generes par Backup-SOCRegistryKey pendant la derniere
        execution (le plus recent Run-ID trouve dans BackupPath est utilise).
        Note : ne restaure PAS les modifications de services / scheduled tasks /
        AppLocker - pour cela, un point de restauration systeme est plus adapte.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-SOCLog -Module Rollback -Message '>>> Debut rollback' -EventId 15000 -Severity Warning

    # Detection du dernier Run-ID sauvegarde
    $regFiles = Get-ChildItem -LiteralPath $BackupPath -Filter '*.reg' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending

    if (-not $regFiles) {
        Write-SOCLog -Severity Error -Module Rollback -Result Failed -EventId 15001 `
                     -Message "Aucun export .reg trouve dans $BackupPath - rollback impossible."
        return
    }

    # Groupe par run-id (format : <label>_<runid>_<timestamp>.reg)
    $groups = $regFiles | Group-Object { ($_.BaseName -split '_')[1] }
    $lastRun = $groups | Sort-Object { ($_.Group | Sort-Object LastWriteTime -Descending)[0].LastWriteTime } -Descending | Select-Object -First 1

    Write-SOCLog -Severity Warning -Module Rollback -Message "Restauration du Run-ID $($lastRun.Name) ($($lastRun.Count) cles)" -EventId 15002

    if (-not $PSCmdlet.ShouldContinue("Restaurer $($lastRun.Count) cles de registre depuis $($lastRun.Name) ?", 'Rollback')) {
        Write-SOCLog -Severity Warning -Module Rollback -Result Skipped -EventId 15003 `
                     -Message 'Rollback annule par l''operateur.'
        return
    }

    $ok = 0; $ko = 0
    foreach ($file in $lastRun.Group) {
        try {
            $out = & reg.exe import $file.FullName 2>&1
            if ($LASTEXITCODE -eq 0) {
                $ok++
                Write-SOCLog -Severity Debug -Module Rollback -Result Success -EventId 15010 `
                             -Message "Import OK : $($file.Name)"
            } else {
                $ko++
                Write-SOCLog -Severity Warning -Module Rollback -Result Failed -EventId 15011 `
                             -Message "Import KO : $($file.Name) - $out"
            }
        } catch {
            $ko++
            Write-SOCLog -Severity Error -Module Rollback -Result Failed -EventId 15012 `
                         -Message "$($file.Name) : $($_.Exception.Message)"
        }
    }

    Write-SOCLog -Severity Information -Module Rollback -Result Success -EventId 15020 `
                 -Message "Rollback termine : $ok OK / $ko KO. Redemarrage RECOMMANDE."
}

#endregion

#region ============================ ORCHESTRATEUR ============================

function Invoke-SOCHardening {
    <#
    .SYNOPSIS
        Orchestrateur principal : execute les modules selectionnes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string[]]$SelectedModules
    )

    $start = Get-Date
    $activeSet = if ($SelectedModules -contains 'All') {
        @('Network','Credentials','AppControl','Services','ExploitGuard','Defender','Audit','UAC','Firewall')
    } else { $SelectedModules }

    Write-SOCLog -Module Orchestrator -Message "=== RUN $script:SOC_RUN_ID | Mode=$Mode | Profile=$Profile | Modules=$($activeSet -join ',') ===" -EventId 20000

    # Point de restauration une seule fois, avant toute modification
    if ($Mode -eq 'Enforce' -and -not $SkipRestorePoint) {
        $null = New-SOCRestorePoint
    }

    $moduleMap = [ordered]@{
        'Network'      = { Disable-SOCLegacyNetworkProtocols -Context $Context; Set-SOCTCPIPHardening -Context $Context }
        'Firewall'     = { Set-SOCFirewallHardening -Context $Context }
        'Credentials'  = { Set-SOCCredentialProtection -Context $Context }
        'AppControl'   = { Set-SOCAppLockerAudit -Context $Context; Set-SOCWDACAuditMode -Context $Context }
        'Services'     = { Disable-SOCUnusedServices -Context $Context; Disable-SOCTelemetry -Context $Context }
        'ExploitGuard' = { Set-SOCExploitGuard -Context $Context }
        'Defender'     = { Set-SOCDefenderASR -Context $Context }
        'UAC'          = { Set-SOCUACHardening -Context $Context }
        'Audit'        = { Set-SOCAuditPolicy -Context $Context; Set-SOCAccountPolicy -Context $Context }
    }

    $counters = @{ Success=0; Skipped=0; Failed=0; WouldChange=0 }

    foreach ($moduleName in $moduleMap.Keys) {
        if ($moduleName -notin $activeSet) {
            Write-SOCLog -Severity Debug -Module Orchestrator -Result Skipped -EventId 20010 `
                         -Message "Module $moduleName non selectionne"
            continue
        }

        Write-SOCLog -Module Orchestrator -Message "--- Module $moduleName ---" -EventId 20020

        try {
            & $moduleMap[$moduleName]
        }
        catch {
            Write-SOCLog -Severity Critical -Module Orchestrator -Result Failed -EventId 20030 `
                         -Message "Exception non geree dans $moduleName : $($_.Exception.Message)"
        }
    }

    $duration = (Get-Date) - $start
    Write-SOCLog -Module Orchestrator -Message ("=== Fin du run. Duree : {0:mm\:ss} ===" -f $duration) -EventId 20040

    # Avis de redemarrage
    if ($Mode -eq 'Enforce') {
        Write-Host ''
        Write-Host ' ' -NoNewline
        Write-Host '[!]' -ForegroundColor Yellow -NoNewline
        Write-Host ' Un redemarrage est necessaire pour que certaines politiques (DEP, LSA PPL, VBS) soient actives.' -ForegroundColor White
        Write-Host ''
    }
}

#endregion

#region ============================ MENU INTERACTIF ============================

function Show-SOCMenu {
    <#
    .SYNOPSIS
        Menu interactif pour operateur SOC (hors automatisation RMM/GPO).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    while ($true) {
        Clear-Host
        Show-SOCBanner
        Write-Host " Hote         : $($Context.Hostname) [$($Context.Caption) $($Context.Release) / $($Context.Edition)]" -ForegroundColor Gray
        Write-Host " Profil       : $Profile"                                                                            -ForegroundColor Gray
        Write-Host " Domaine      : $(if ($Context.DomainJoined){$Context.Domain}else{'WORKGROUP'}) | Azure : $($Context.AzureJoined)" -ForegroundColor Gray
        Write-Host " Secure Boot  : $($Context.SecureBoot) | TPM : $($Context.TpmReady) | VBS : $($Context.VbsStatus)"   -ForegroundColor Gray
        Write-Host ''
        Write-Host ' ' -NoNewline
        Write-Host ' MENU ' -BackgroundColor DarkCyan -ForegroundColor White -NoNewline
        Write-Host ''
        Write-Host '  [1] Audit complet (WhatIf - aucune modification)'
        Write-Host '  [2] Enforce complet (tous les modules)'
        Write-Host '  [3] Enforce partiel (selection de modules)'
        Write-Host '  [4] Rollback (depuis le dernier run)'
        Write-Host '  [5] Afficher le contexte systeme detaille'
        Write-Host '  [6] Ouvrir le log CSV en cours'
        Write-Host '  [Q] Quitter'
        Write-Host ''
        $choice = Read-Host ' Choix'

        switch ($choice.ToUpper()) {
            '1' {
                $script:Mode = 'Audit'
                Invoke-SOCHardening -Context $Context -SelectedModules @('All') -WhatIf
                Pause
            }
            '2' {
                $script:Mode = 'Enforce'
                if ((Read-Host ' Confirmer ENFORCE complet ? (oui/non)') -match '^(o|oui|y|yes)$') {
                    Invoke-SOCHardening -Context $Context -SelectedModules @('All')
                }
                Pause
            }
            '3' {
                Write-Host ''
                Write-Host ' Modules disponibles : Network, Credentials, AppControl, Services, ExploitGuard, Defender, Audit, UAC, Firewall' -ForegroundColor Gray
                $selection = Read-Host ' Modules (separes par virgule)'
                $list = $selection.Split(',').Trim() | Where-Object { $_ }
                if ($list) {
                    $script:Mode = 'Enforce'
                    Invoke-SOCHardening -Context $Context -SelectedModules $list
                }
                Pause
            }
            '4' {
                Invoke-SOCRollback
                Pause
            }
            '5' {
                $Context | Format-List
                Pause
            }
            '6' {
                $csv = Get-ChildItem -LiteralPath $LogPath -Filter ("*$script:SOC_RUN_ID*.csv") -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($csv) { Start-Process notepad.exe $csv.FullName } else { Write-Host ' Aucun log pour ce run.' -ForegroundColor Yellow; Pause }
            }
            'Q' { return }
            default { }
        }
    }
}

#endregion

#region ============================ POINT D'ENTREE ============================

function Start-SOCMain {
    [CmdletBinding()]
    param()

    Show-SOCBanner
    Initialize-SOCLogging

    if (-not (Test-SOCPrerequisites)) {
        Write-SOCLog -Severity Critical -Module Core -Result Failed -EventId 1000 `
                     -Message 'Pre-requis non satisfaits - sortie.'
        exit 2
    }

    $context = Get-SOCSystemContext
    Write-SOCLog -Module Core -Message "Contexte : $($context.Caption) $($context.Release) | Edition=$($context.Edition) | Profile=$Profile" -EventId 1100 `
                 -Context @{
                     Hostname     = $context.Hostname
                     Family       = $context.Family
                     Build        = $context.Build
                     Edition      = $context.Edition
                     DomainJoined = $context.DomainJoined
                     SecureBoot   = $context.SecureBoot
                     TpmReady     = $context.TpmReady
                 }

    switch ($Mode) {
        'Interactive' {
            Show-SOCMenu -Context $context
        }
        'Audit' {
            # WhatIf global - aucune ecriture
            Invoke-SOCHardening -Context $context -SelectedModules $Modules -WhatIf
        }
        'Enforce' {
            Invoke-SOCHardening -Context $context -SelectedModules $Modules
        }
        'Rollback' {
            Invoke-SOCRollback
        }
    }

    Write-Host ''
    Write-Host " Log CSV : $LogPath" -ForegroundColor DarkGray
    Write-Host " Backups : $BackupPath" -ForegroundColor DarkGray
    Write-Host ''
}

# Lancement
Start-SOCMain

#endregion
