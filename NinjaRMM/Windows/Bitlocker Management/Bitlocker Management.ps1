#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-19-2025
    
    Note:
    06-02-2025: Addressed a sanitization issue that prevented non-os drives from being disabled individually without the OS Drive
    05-28-2025: Address suspend logic and validated 
    05-27-2025: Status (Custom Field, Secure Field) update for all fixed drives, regardless of management as a safety precaution. Zero overriding of keys, etc.
    05-23-2025: Cleanup, big fixes, and consistency, testing
    05-22-2025: Rewrite for multi-volume handling, improved safety, and use case
    05-19-2025: General cleanup improvements
    04-25-2025: Creation and validation testing
#>

<#
.SYNOPSIS
    Manage BitLocker end-to-end across one or more volumes and store in a WYSIWYG custom field (status card) for NinjaRMM.

.DESCRIPTION
    This advanced script can Enable, Suspend or Disable BitLocker on multiple drives
    (or all fixed disks), or individually specified drive(s), manage TPM/recovery-key protectors, store settings in
    the registry for furture reference, and publish both HTML status card(s) and secure recovery key(s) to NinjaRMM custom fields.
    Recovery keys for all processed drives/volumes are stored in a single secure custom field
    in a structured text format (e.g., "Volume: C: - ID: {GUID} | Key: {Key}; Volume: D: - ID: {GUID} | Key: {Key}; ").
    Drive: C: - N/A; Drive: D: - N/A

.PARAMETER ApplyToAllFixedDisk
    Switch. If set, ignores -MountPoint and targets all fixed disk in the system

.PARAMETER MountPoint
    Target specific drive letter(s). Example: C:, D: (or defaults to system drive).

.PARAMETER BitLockerProtection
    Dropdown: Enable, Suspend, or Disable protection (required).

.PARAMETER RecoveryKeyAction
    Dropdown: Ensure, Rotate, or Remove numeric recovery key (required).

.PARAMETER BitlockerEncryptionMethod
    Dropdown: Aes128, Aes256, XtsAes128, or XtsAes256 Bitlocker encryption method (required when enabling; Defaults to XtsAes256).

.PARAMETER BackupToAD
    Switch to backup recovery keys to AD/AAD (Intune).

.PARAMETER SuspensionRebootCount
    Number of reboots to allow for suspended protection (default 1).

.PARAMETER UseUsedSpaceOnly
    Set encryption for used space only. (only valid when enabling from a complete off state)

.PARAMETER SaveLogToDevice
    If specified, logs are saved to <SystemDrive>:\Logs\BitLockerManagement.log on the device.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the Bitlocker status card.
    Defaults to "BitLockerStatusCard" or env:bitLockerStatusFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.
#>

[CmdletBinding()]
param(
    # Drive letter        Ninja Variable Resolution                                                 Fallback
    [string[]]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint -split ',' } else { @((Get-CimInstance Win32_OperatingSystem).SystemDrive) }), # Ninja Script Variable; String
    
    # Dropdown options                                                                             Ninja Variable Resolution                                                    Fallback
    [ValidateSet("Enable", "Suspend", "Disable")]               [string]$BitLockerProtection       = $(if ($env:bitlockerProtection)        { $env:bitlockerProtection }        else { "Enable" }),    # Ninja Script Variable; Dropdown
    [ValidateSet("Ensure", "Rotate", "Remove")]                 [string]$RecoveryKeyAction         = $(if ($env:bitlockerRecoveryKeyAction) { $env:bitlockerRecoveryKeyAction } else { "Ensure" }),    # Ninja Script Variable; Dropdown
    [ValidateSet("Aes128", "Aes256", "XtsAes128", "XtsAes256")] [string]$BitlockerEncryptionMethod = $(if ($env:bitlockerEncryptionMethod)  { $env:bitlockerEncryptionMethod }  else { "XtsAes256" }), # Ninja Script Variable; Dropdown
    
    # Independent switches         Ninja Variable Resolution                                                                      Fallback
    [switch]$UseTpmProtector       = $(if ($env:useBitlockerTpmProtector) { [Convert]::ToBoolean($env:useBitlockerTpmProtector) } else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$AutoUnlockNonOSDrives = $(if ($env:autoUnlockNonOsDrives) { [Convert]::ToBoolean($env:autoUnlockNonOsDrives) }       else { $true }),  # Static - Optional Ninja Script Variable; Checkbox
    [switch]$ApplyToAllFixedDisk   = $(if ($env:applyToAllFixedDisk) { [Convert]::ToBoolean($env:applyToAllFixedDisk) }           else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$UseUsedSpaceOnly      = $(if ($env:encryptUsedspaceonly) { [Convert]::ToBoolean($env:encryptUsedspaceonly) }         else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$BackupToAD            = $(if ($env:bitlockerBackupToAd) { [Convert]::ToBoolean($env:bitlockerBackupToAd) }           else { $false }), # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice       = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }                   else { $false }), # Ninja Script Variable; Checkbox
    [int]$SuspensionRebootCount    = $(if ($env:bitlockerSuspensionRebootCount) { [int]$env:bitlockerSuspensionRebootCount }      else { 1 }),      # Static - Optional Ninja Script Variable; Integer
    
    # Ninja custom field names          Ninja Variable Resolution                                                    Fallback
    [string]$BitLockerStatusFieldName   = $(if ($env:bitLockerStatusFieldName) { $env:bitLockerStatusFieldName }     else { "BitLockerStatusCard" }),  # Static - Optional Ninja Script Variable; String
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }), # Static - Optional Ninja Script Variable; String

    # Registry Information                   Optional Ninja Variable Resolution                                             Fallback
    [string]$BitLockerStateStoragePath       = $(if ($env:bitLockerStateStoragePath) { $env:bitLockerStateStoragePath }     else { "HKLM:\SOFTWARE\BitLockerManagement" }), # Static - Optional Ninja Script Variable; String
    [string]$UsedSpaceOnlyStateValueName     = $(if ($env:usedSpaceOnlyStateValueName) { $env:usedSpaceOnlyStateValueName } else { "UsedSpaceOnly" }),                      # Static - Optional Ninja Script Variable; String
    [string]$InitialSuspensionCountValueName = $(if ($env:suspensionCountValueName) { $env:suspensionCountValueName }       else { "InitialSuspensionCount" }),             # Static - Optional Ninja Script Variable; String
    
    # Card customization options
    [string]$CardTitle = "Bitlocker Status",     # Default title + Volume Letter (added later)
    [string]$CardIcon = "fas fa-shield-alt",     # Default icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default", # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius = "10px",          # Default border radius
    [string]$CardSeparationMargin = "0 8px",     # Default distance between cards
    
    # Special Saftey Variable | Ensures both TPM and Recovery Key protectors are always present (when true). Subsequently prevents recovery key prompt on every boot
    [switch]$PreventKeyPromptOnEveryBoot = $(if ($env:preventKeyPromptOnEveryBoot) { [Convert]::ToBoolean($env:preventKeyPromptOnEveryBoot) } else { $true }) # Static - Optional Ninja Script Variable; Checkbox
)

# =========================================
# BEGIN Block: Initialization & Validation
# =========================================
begin {
    
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`nAdministrator privileges required"
        exit 1
    }
    Write-Host "`nRunning as Administrator"
    
    ##############
    # Validation #
    ##############
    
    Write-Host "`n=== Initialization & Validation ==="
    
    # Helper Function: Called early to check for drive dependencies (e.g., RAID or spanned volumes)
    function Test-DriveDependencies {
        Write-Host "[INFO] Checking for drive dependencies that may affect BitLocker operations"
        try {
            $physicalDisks = Get-PhysicalDisk
            $disks = Get-Disk
            foreach ($disk in $disks) {
                if ($disk.OperationalStatus -eq 'RAID' -or $disk.PartitionStyle -eq 'Unknown') {
                    Write-Host "[WARNING] Detected RAID or non-standard disk configuration on Disk $($disk.Number). BitLocker operations may fail."
                }
                if ($disk.IsBoot -and $disk.NumberOfPartitions -gt 1) {
                    Write-Host "[INFO] Multiple partitions detected on boot disk. Ensure BitLocker is applied to the correct volume."
                }
            }
            $spannedVolumes = Get-Volume | Where-Object { $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' } | 
                Where-Object { (Get-Partition -Volume $_).DiskNumber.Count -gt 1 }
            if ($spannedVolumes) {
                Write-Host "[WARNING] Detected spanned volumes: $($spannedVolumes.DriveLetter -join ', '). BitLocker may not support these configurations."
            }
            Write-Host "[SUCCESS] Drive dependency check completed"
        }
        catch {
            Write-Host "[ERROR] Failed to check drive dependencies: $_"
        }
    }
    # Immediately call drive dependency check ^
    Test-DriveDependencies
    
    # Handle ApplyToAllFixedDisk, otherwise parse MountPoint
    if ($ApplyToAllFixedDisk) {
        Write-Host "[INFO] ApplyToAllFixedDisk is set; retrieving all fixed disks"
        # Ensure OS drive (e.g., C:) is first in the $drives array by assigning it a sort key of 0
        $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
            Sort-Object { if ($_.DriveLetter -eq (Get-CimInstance Win32_OperatingSystem).SystemDrive[0]) { 0 } else { 1 } } |
            Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' }
        if (-not $drives) {
            Write-Host "[ERROR] No fixed disks found on this system"
            exit 1
        }
        Write-Host "[INFO] Found fixed disks: $($drives -join ', ')"
    }
    else {
        # Parse MountPoint for multiple drives
        $mountPoints = $MountPoint -split ',' | ForEach-Object { $_.Trim() }
        $drives = @()
        foreach ($mp in $mountPoints) {
            # Regex to match single letter (e.g., 'C') or letter with colon and optional backslash (e.g., 'C:' or 'C:\')
            if ($mp -match '^[A-Za-z]$' -or $mp -match '^[A-Za-z]:\\?$') {
                # If single letter, append colon; otherwise normalize by replacing trailing backslash with colon
                if ($mp -match '^[A-Za-z]$') {
                    $mp = $mp + ':'
                }
                else {
                    $mp = $mp -replace '\\$', ':'
                }
                # Fixed Disk safety check
                if (Test-Path $mp -PathType Container) {
                    $driveInfo = Get-Volume -DriveLetter $mp[0] -ErrorAction SilentlyContinue
                    if ($driveInfo -and $driveInfo.DriveType -eq 'Fixed') {
                        $drives += $mp
                    }
                    else {
                        Write-Host "[WARNING] MountPoint '$mp' is not a fixed disk; skipping"
                    }
                }
                else {
                    Write-Host "[WARNING] MountPoint '$mp' does not exist or is not a valid volume"
                }
            }
            else {
                # Updated message to reflect that both 'C' and 'C:' are accepted
                Write-Host "[WARNING] Invalid MountPoint format: '$mp'. Must be a drive letter like 'C' or 'C:'"
            }
        }
        if (-not $drives) {
            Write-Host "[ERROR] No valid fixed disks specified in MountPoint"
            exit 1
        }
    }
    
    # Get all fixed drives for reporting (regardless of selection logic)
    $allFixedDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
    Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' }
    Write-Host "[INFO] allFixedDrives populated"
    
    # Validate SuspensionRebootCount
    if ($SuspensionRebootCount -lt 0 -or $SuspensionRebootCount -gt 10) {
        Write-Host "[WARNING] SuspensionRebootCount must be between 0 and 10; setting to 1"
        $SuspensionRebootCount = 1
    }
    
    Write-Host "[SUCCESS] Values loaded:"
    # Dynamic MountPoint message
    if ($ApplyToAllFixedDisk) {
        Write-Host "  - Bitlocker Mount Point(s): Ignored (ApplyToAllFixedDisk is true)"
    }
    else {
        Write-Host "  - Bitlocker Mount Point(s): $($MountPoint -join ', ')"
    }
    Write-Host "  - Protection: $BitLockerProtection"
    Write-Host "  - Recovery Key Action: $RecoveryKeyAction"
    Write-Host "  - Encryption Method: $BitlockerEncryptionMethod"
    Write-Host "  - Use TPM: $UseTpmProtector"
    Write-Host "  - Backup to AD: $BackupToAD"
    Write-Host "  - Prevent Key Prompt On Every Boot: $PreventKeyPromptOnEveryBoot"
    Write-Host "  - Auto Unlock Non-OS Drives: $AutoUnlockNonOSDrives"
    
    # Sanitization Section: Correct impossible or conflicting input combinations with detailed output
    Write-Host "`n=== Section: Sanitization ==="
    
    # PreventKeyPromptOnEveryBoot sanitization
    if ($PreventKeyPromptOnEveryBoot) {
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is ON; checking TPM and Recovery Key requirements"
        if ($BitLockerProtection -in @("Enable", "Suspend")) {
            Write-Host "[INFO] Protection action '$BitLockerProtection' selected; validating protector requirements"
            # Sublogic: if TPM is disabled and BitLocker is Enabled/Suspended, handle based on PreventKeyPromptOnEveryBoot bool
            if (-not $UseTpmProtector) {
                Write-Host "[WARNING] TPM protector enforcement: UseTpmProtector was false, but PreventKeyPromptOnEveryBoot requires TPM for '$BitLockerProtection'. Setting UseTpmProtector to true."
                $UseTpmProtector = $true
            }
            else {
                Write-Host "[INFO] TPM protector enforcement: UseTpmProtector is true, meeting PreventKeyPromptOnEveryBoot requirement"
            }
            # Sublogic: If recovery key was set to remove and BitLocker is Enabled/Suspended, set to Ensure. There will ALWAYS be a BitLocker recovery key when enabled/suspended
            if ($RecoveryKeyAction -eq "Remove") {
                Write-Host "[WARNING] Recovery Key enforcement: RecoveryKeyAction was 'Remove', but PreventKeyPromptOnEveryBoot requires a recovery key for '$BitLockerProtection'. Setting RecoveryKeyAction to 'Ensure'."
                $RecoveryKeyAction = "Ensure"
            }
            else {
                Write-Host "[SUCCESS] Recovery Key enforcement: RecoveryKeyAction is '$RecoveryKeyAction', meeting PreventKeyPromptOnEveryBoot requirement"
            }
        }
        elseif ($BitLockerProtection -eq 'Disable') {
            Write-Host "[INFO] Protection action 'Disable' selected; checking drive selection for safety"
            # Get all BitLocker-enabled volumes
            $bitLockerVolumes = Get-BitLockerVolume | Where-Object { $_.KeyProtector -and $_.VolumeStatus -ne 'FullyDecrypted' } | Select-Object -ExpandProperty MountPoint
            if ($drives -contains $osDrive -and $bitLockerVolumes -contains $osDrive) {
                # If OS drive is included and encrypted, ensure all encrypted drives are disabled for safety
                $drives = ($drives + $bitLockerVolumes) | Select-Object -Unique
                Write-Host "[INFO] Including all BitLocker-enabled volumes for disabling due to OS drive selection and PreventKeyPromptOnEveryBoot being enabled."
            }
            else {
                # Allow disabling of explicitly specified drives, even if OS drive is encrypted but not selected
                Write-Host "[INFO] Proceeding to disable BitLocker on explicitly selected drives ($($drives -join ', ')) as specified."
            }
        }
        else {
            Write-Host "[INFO] Protection action '$BitLockerProtection' selected; no additional TPM or Recovery Key enforcement needed"
        }
    }
    # Sublogic: PreventKeyPromptOnEveryBoot handling when not enabled/true - proper sanitization and handling of states
    else {
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is false; skipping strict TPM and Recovery Key enforcement checks.`nThis may result in BitLocker prompting during EVERY BOOT if you remove the TPM."
        if (-not $UseTpmProtector -and $BitLockerProtection -in @("Enable", "Suspend")) {
            Write-Host "[INFO] UseTpmProtector is false for '$BitLockerProtection'; checking Recovery Key requirement"
            # Sublogic: Always ensure RecoveryKeyAction is ensured when BitLocker is enabled/suspended, regardless of PreventKeyPromptOnEveryBoot state. This ensures recovery key management all of the time
            if ($RecoveryKeyAction -eq "Remove") {
                Write-Host "[WARNING] RecoveryKeyAction was 'Remove', but a recovery key is required without TPM for '$BitLockerProtection'. Setting RecoveryKeyAction to 'Ensure'."
                $RecoveryKeyAction = "Ensure"
            }
            else {
                Write-Host "[SUCCESS] RecoveryKeyAction is '$RecoveryKeyAction', meeting requirement without TPM"
            }
        }
    }
    
    # BitLocker Protection Status sanitization
    if ($BitLockerProtection -eq "Disable") {
        Write-Host "[INFO] Protection action 'Disable' selected; validating possible conflicting settings"
        $BackupToAD = $false # disable AD backup
        if ($RecoveryKeyAction -in @("Ensure", "Rotate")) {
            Write-Host "[WARNING] RecoveryKeyAction was '$RecoveryKeyAction', but 'Disable' only allows 'Remove'. Setting RecoveryKeyAction to 'Remove'."
            $RecoveryKeyAction = "Remove"
        }
        else {
            Write-Host "[SUCCESS] RecoveryKeyAction is '$RecoveryKeyAction', compatible with 'Disable'"
        }
        if ($BackupToAD) {
            Write-Host "[WARNING] BackupToAD was '$BackupToAD', but 'Disable' only allows 'false'. Setting BackupToAD to 'false'."
            # Disable AD backup
            $BackupToAD = $false
        }
        else {
            Write-Host "[SUCCESS] BackupToAD is '$BackupToAD', compatible with 'Disable'"
        }
    }
    
    Write-Host "[SUCCESS] Input sanitization completed successfully"
    
    # Define the OS drive for use throughout the script
    $osDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    
    # Check if OS drive is encrypted or included when enabling BitLocker on non-OS drives
    if ($BitLockerProtection -eq 'Enable') {
        $nonOsDrives = $drives | Where-Object { $_ -ne $osDrive }
        if ($nonOsDrives) {
            # Handle safely with PreventKeyPromptOnEveryBoot
            if ($PreventKeyPromptOnEveryBoot) {
                if ($drives -notcontains $osDrive) {
                    # Set the OS Volume
                    $osVolume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
                    # Quit if there is no OS Drive
                    if (-not $osVolume -or $osVolume.VolumeStatus -ne 'FullyEncrypted') {
                        Write-Host "[ERROR] Cannot enable BitLocker on non-OS drives ($($nonOsDrives -join ', ')) without the OS drive ($osDrive) being encrypted or selected for encryption when PreventKeyPromptOnEveryBoot is enabled."
                        Write-Host "[ERROR] OS drive ($osDrive) must be encrypted or included in the operation to enable BitLocker on non-OS drives when PreventKeyPromptOnEveryBoot is enabled."
                        exit 1
                    }
                    else {
                        Write-Host "[INFO] OS drive ($osDrive) is already fully encrypted; proceeding with non-OS drive enablement."
                    }
                }
                else {
                    Write-Host "[INFO] OS drive ($osDrive) is included in the drives to be encrypted; proceeding."
                }
            }
            # Skip system drive requirement. Will result in key prompting
            else {
                $osVolume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
                if (-not $osVolume -or $osVolume.VolumeStatus -ne 'FullyEncrypted') {
                    Write-Log "WARNING" "Enabling BitLocker on non-OS drives ($($nonOsDrives -join ', ')) without the OS drive ($osDrive) being encrypted. This may affect auto-unlock functionality."
                }
            }
        }
    }
    
    # Initialize collection for recovery keys
    $script:RecoveryKeys = @{}
    
    #######################
    # Helper Functions
    #######################
    
    # Helper function: Create an info card with structured data and icon color
    function Get-NinjaOneInfoCard($Title, $Data, [string]$Icon, [string]$TitleLink, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor = "#000000") {
        [System.Collections.Generic.List[String]]$ItemsHTML = @()
        foreach ($Item in $Data.PSObject.Properties) {
            $ItemsHTML.add('<p ><b >' + $Item.Name + '</b><br />' + $Item.Value + '</p>')
        }
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor -SeparationMargin -$CardSeparationMargin
    }
    
    # Helper function: Generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor, [string]$SeparationMargin) {
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background: $BackgroundGradient; border-radius: $BorderRadius; margin: $SeparationMargin;"
        $OutputHTML.add('<div class="card flex-grow-1' + $(if ($classes) { ' ' + $classes }) + '" style="' + $style + '">')
        if ($Title) {
            $iconHtml = if ($Icon) { '<i class="' + $Icon + '" style="color: ' + $IconColor + ';"></i> ' } else { '' }
            $OutputHTML.add('<div class="card-title-box"><div class="card-title" >' + $iconHtml + $Title + '</div>')
            if ($TitleLink) {
                $OutputHTML.add('<div class="card-link-box"><a href="' + $TitleLink + '" target="_blank" class="card-link" ><i class="fas fa-arrow-up-right-from-square" style="color: #337ab7;"></i></a></div>')
            }
            $OutputHTML.add('</div>')
        }
        $OutputHTML.add('<div class="card-body" >')
        $OutputHTML.add('<p class="card-text" >' + $Body + '</p>')
        $OutputHTML.add('</div></div>')
        return $OutputHTML -join ''
    }
    
    # Helper function: Define logging function for consistent output and optional file logging
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        # Sublogic: Output the log message to the console
        Write-Host "[$Level] $Message"
        
        # Sublogic: Save the log message to a file on the device if enabled
        if ($SaveLogToDevice) {
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            # Use the system drive for logging
            $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $logDir = "$systemDrive\Logs\Bitlocker"
            $logFile = Join-Path $logDir "BitlockerManagement.log"
            
            # Sublogic: Create the log directory if it doesn't exist
            if (-not (Test-Path $logDir)) {
                try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
            }
            
            # Sublogic: Add a daily header to the log file if not already present
            $today = Get-Date -Format 'yyyy-MM-dd'
            $header = "=== $today ==="
            $existingContent = if (Test-Path $logFile) { Get-Content $logFile -Raw } else { "" }
            if (-not $existingContent -or -not ($existingContent -match [regex]::Escape($header))) {
                Add-Content -Path $logFile -Value "`r`n$header"
            }
            
            Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
        }
    }
    
    # Helper function: Refresh drive state
    function Get-VolumeObject {
        try {
            # Sublogic: Retrieve BitLocker volume object and suppress all non-error output
            $global:blv = Get-BitLockerVolume `
                -MountPoint $MountPoint `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue
            # Only log volume state if not already logged for this mount point in this run
            if (-not $script:LastLogContext) { $script:LastLogContext = @{} }
            if (-not $script:LastLogContext.ContainsKey("VolumeState-$MountPoint")) {
                Write-Host "[SUCCESS] Volume state refreshed: ProtectionStatus=$($blv.ProtectionStatus), VolumeStatus=$($blv.VolumeStatus)"
                $script:LastLogContext["VolumeState-$MountPoint"] = $true
            }
        }
        catch {
            Write-Log "ERROR" "No BitLocker volume at ${MountPoint}: $_"
            exit 1
        }
    }
    
    # Helper Function: Safe variable management 
    function Clear-Memory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string[]]$VariableNames
        )
        foreach ($name in $VariableNames) {
            # Null out the variable
            Set-Variable -Name $name -Value $null -Scope Local -ErrorAction SilentlyContinue
            # Remove it entirely
            Clear-Variable -Name $name -Scope Local -ErrorAction SilentlyContinue
        }
        # No Write-Log output for safety
        Write-Host "[INFO] Cleared memory for variables: $($VariableNames -join ', ')"
    }
    
    # Helper function: Detect if BitLocker is awaiting key backup before activation. Usually occurs during first-ever activation.
    function Test-IsKeyBackupRequired {
        param($volume)
        # Sublogic: Suppress logging from nested recovery protector scans
        $script:SuppressRecoveryProtectorScanLog = $true
        $valid = Get-ValidRecoveryProtectors -v $volume
        $script:SuppressRecoveryProtectorScanLog = $false
        
        # Sublogic: Check if volume is fully encrypted with protection off and a recovery protector exists
        if ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 0 -and $valid.Count -gt 0) {
            if (-not $script:LastLogContext) { $script:LastLogContext = @{} }
            if (-not $BackupToAD -and -not $script:LastLogContext.ContainsKey("KeyBackupRequired-$($volume.MountPoint)")) {
                Write-Log "INFO" "BitLocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and/or resuming protection."
                $script:LastLogContext["KeyBackupRequired-$($volume.MountPoint)"] = $true
            }
            return $true
        }
        return $false
    }
    
    # Helper function: Return the list of valid protectors; list
    function Get-ValidRecoveryProtectors {
        param($volume)
        # Log only if not suppressed and not already logged for this drive
        if (-not $script:SuppressRecoveryProtectorScanLog -and -not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
            Write-Log "INFO" "Scanning for valid RecoveryPassword protectors for $($volume.MountPoint)..."
        }
        if (-not $volume.KeyProtector) {
            if (-not $script:SuppressRecoveryProtectorScanLog) {
                Write-Log "WARNING" "No KeyProtector array found on volume $($volume.MountPoint)"
            }
            return @()
        }
        $candidates = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -ieq 'RecoveryPassword' }
        if (-not $candidates) {
            if (-not $script:SuppressRecoveryProtectorScanLog) {
                Write-Log "INFO" "No RecoveryPassword entries found for $($volume.MountPoint)"
            }
            return @()
        }
        $valid = @()
        foreach ($keypair in $candidates) {
            if ($keypair.KeyProtectorId -match '^\{[0-9a-f\-]+\}$') {
                $valid += $keypair
            }
            else {
                if (-not $script:SuppressRecoveryProtectorScanLog) {
                    Write-Log "WARNING" "Ignoring invalid protector ID: $($keypair.KeyProtectorId) for $($volume.MountPoint)"
                }
            }
        }
        if ($valid.Count -gt 0 -and -not $script:SuppressRecoveryProtectorScanLog -and -not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
            Write-Log "INFO" "Found $($valid.Count) valid recovery key protector(s) for $($volume.MountPoint)"
        }
        return $valid
    }
    
    # Helper function: Ensure a recovery key exists (only 1)
    function Ensure-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Ensuring single numeric recovery protector for $($volume.MountPoint)"
        try {
            $maxAttempts = 3
            $attempt = 0
            $existingProtectors = $null
            
            # Check for existing protectors only once at the start
            $script:SuppressRecoveryProtectorScanLog = $true
            $existingProtectors = Get-ValidRecoveryProtectors -volume $volume
            $script:SuppressRecoveryProtectorScanLog = $false
            
            # Handle multiple protectors
            while ($attempt -lt $maxAttempts -and $existingProtectors.Count -gt 1) {
                $latestProtector = $existingProtectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                foreach ($protector in $existingProtectors | Where-Object { $_.KeyProtectorId -ne $latestProtector.KeyProtectorId }) {
                    Remove-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    Write-Log "INFO" "Removed duplicate protector $($protector.KeyProtectorId) for $($volume.MountPoint)"
                }
                # Refresh volume state
                $volume = Get-BitLockerVolume -MountPoint $volume.MountPoint
                $script:SuppressRecoveryProtectorScanLog = $true
                $existingProtectors = Get-ValidRecoveryProtectors -volume $volume
                $script:SuppressRecoveryProtectorScanLog = $false
                $attempt++
            }
            
            if ($existingProtectors.Count -gt 1) {
                Write-Log "ERROR" "Failed to reduce recovery protectors to one after $maxAttempts attempts for $($volume.MountPoint)"
                return
            }
            
            # If one protector exists, confirm it and exit
            if ($existingProtectors.Count -eq 1) {
                if (-not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
                    Write-Log "INFO" "Confirmed 1 valid recovery key protector for $($volume.MountPoint)"
                    $script:LoggedRecoveryFound[$volume.MountPoint] = $true
                }
                return
            }
            
            # Add a new recovery protector if none exist
            $result = Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            $script:NumericProtectorCreated = $true
            Write-Log "SUCCESS" "Numeric recovery protector added for $($volume.MountPoint)"
        }
        catch {
            Write-Log "ERROR" "Failed to ensure recovery key for $($volume.MountPoint): $_"
        }
    }

    # Helper function: If there is an existing recovery password; bool
    function Test-RecoveryPasswordPresent {
        param($volume, [switch]$SuppressLog)
        # Sublogic: Suppress nested recovery protector scan logs
        $script:SuppressRecoveryProtectorScanLog = $true
        $valid = Get-ValidRecoveryProtectors -v $volume
        $script:SuppressRecoveryProtectorScanLog = $false
        
        # Sublogic: Determine if a valid recovery password protector exists and log relevant status
        if ($valid.Count -gt 0) {
            if (-not $SuppressLog -and -not $script:LastLogContext.ContainsKey("RecoveryPresent-$($volume.MountPoint)")) {
                if ($volume.VolumeStatus -eq 'EncryptionInProgress' -or $volume.VolumeStatus -eq 'EncryptionPaused') {
                    Write-Log "INFO" "BitLocker is encrypting (status: $($volume.VolumeStatus))."
                }
                elseif ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 0) {
                    Write-Log "INFO" "BitLocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and/or resuming protection."
                }
                elseif ($volume.ProtectionStatus -eq 'Off') {
                    if ($volume.VolumeStatus -eq 'DecryptionInProgress') {
                        Write-Log "INFO" "BitLocker is decrypting the volume. Please wait until decryption is complete before restarting."
                    }
                    else {
                        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
                        if ($hasTpm) {
                            Write-Log "INFO" "BitLocker is Off with a TPM protector. Resume protection or reboot to finalize."
                        }
                    }
                }
                $script:LastLogContext["RecoveryPresent-$($volume.MountPoint)"] = $true
            }
            return $true
        }
        else {
            if (-not $SuppressLog -and -not $script:LastLogContext.ContainsKey("NoRecoveryPresent-$($volume.MountPoint)")) {
                Write-Log "INFO" "No valid numeric recovery protector found."
                $script:LastLogContext["NoRecoveryPresent-$($volume.MountPoint)"] = $true
            }
            return $false
        }
    }
    
    # Helper function: Rotate recovery key
    function Rotate-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Rotating numeric recovery protector"
        # Sublogic: Remove existing numeric protectors
        Write-Log "INFO" "Removing existing numeric protectors before rotation..."
        $existing = Get-ValidRecoveryProtectors -v $volume
        if (-not $existing) {
            Write-Log "WARNING" "No protectors to rotate; adding a new one"
        }
        else {
            foreach ($keypair in $existing) {
                try {
                    Remove-BitLockerKeyProtector `
                    -MountPoint $volume.MountPoint `
                    -KeyProtectorId $keypair.KeyProtectorId `
                    -ErrorAction Stop `
                    -InformationAction SilentlyContinue | Out-Null
                    Write-Log "INFO" "Removed protector $($keypair.KeyProtectorId)"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove old protector $($keypair.KeyProtectorId): $_"
                }
            }
        }
        # Sublogic: Add a new recovery protector
        try {
            $result = Add-BitLockerKeyProtector `
            -MountPoint $volume.MountPoint `
            -RecoveryPasswordProtector `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue `
            -InformationAction SilentlyContinue | Out-Null
            $script:NumericProtectorCreated = $true
            Write-Log "SUCCESS" "Numeric recovery protector rotated"
        }
        catch {
            Write-Log "ERROR" "Failed to add new protector: $_"
        }
    }
    
    # Helper function: Remove recovery key
    function Remove-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Removing numeric recovery protector(s)"
        
        $existing = Get-ValidRecoveryProtectors -v $volume
        
        # Sublogic: Check if there are any valid recovery protectors to remove
        if (-not $existing -or $existing.Count -eq 0) {
            Write-Log "WARNING" "No valid numeric protectors found; skipping removal"
            return
        }
        
        # Sublogic: Remove each valid recovery protector
        foreach ($keypair in $existing) {
            try {
                Remove-BitLockerKeyProtector `
                  -MountPoint $volume.MountPoint `
                  -KeyProtectorId $keypair.KeyProtectorId `
                  -ErrorAction Stop `
                  -InformationAction SilentlyContinue | Out-Null
                Write-Log "SUCCESS" "Removed protector $($keypair.KeyProtectorId)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $_"
            }
        }
        
        # Sublogic: Verify all protectors were removed
        $remaining = Get-ValidRecoveryProtectors -v $volume
        if ($remaining.Count -eq 0) {
            Write-Log "SUCCESS" "All valid numeric protectors removed"
        }
        else {
            Write-Log "WARNING" "Some protectors may not have been removed"
        }
    }
    
    # Helper function: Remove all existing protectors
    function Remove-AllProtectors {
        param($volume)
        Write-Log "INFO" "Removing all existing key protectors"
        $protectors = $volume.KeyProtector
        if (-not $protectors) {
            Write-Log "INFO" "No protectors found to remove"
            return
        }
        foreach ($keypair in $protectors) {
            try {
                Remove-BitLockerKeyProtector `
                    -MountPoint $volume.MountPoint `
                    -KeyProtectorId $keypair.KeyProtectorId `
                    -ErrorAction Stop `
                    -InformationAction SilentlyContinue | Out-Null
                Write-Log "SUCCESS" "Removed protector $($keypair.KeyProtectorId)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $_"
            }
        }
        Write-Log "SUCCESS" "All protectors removed"
    }
    
    # Helper function: Manage the BitLocker Recovery Key Action selection
    function Invoke-RecoveryAction {
        param(
            [Parameter(Mandatory)]$volume,
            [Parameter(Mandatory)][ValidateSet('Ensure','Rotate','Remove')]$Action,
            [Parameter()][switch]$SuppressLog
        )
        $recoveryPresent = Test-RecoveryPasswordPresent -v $volume -SuppressLog:$SuppressLog
        switch ($Action) {
            'Ensure' {
                if ($script:NumericProtectorCreated) {
                    if (-not $SuppressLog) { Write-Log "INFO" "Protector was just created; skipping Ensure" }
                }
                else {
                    # Ensure only one RecoveryPassword protector by removing extras before adding
                    $existingProtectors = Get-ValidRecoveryProtectors -v $volume
                    if ($existingProtectors.Count -gt 1) {
                        $latestProtector = $existingProtectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                        foreach ($protector in $existingProtectors | Where-Object { $_.KeyProtectorId -ne $latestProtector.KeyProtectorId }) {
                            Remove-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                            Write-Log "INFO" "Removed duplicate protector $($protector.KeyProtectorId) to ensure single protector"
                        }
                    }
                    elseif ($existingProtectors.Count -eq 1) {
                        if (-not $SuppressLog) { Write-Log "WARNING" "Valid recovery key already present; skipping Ensure" }
                        return
                    }
                    Ensure-RecoveryKey -v $volume
                }
            }
            'Rotate' {
                if ($volume.VolumeStatus -ne 'FullyDecrypted') {
                    Rotate-RecoveryKey -v $volume
                }
                else {
                    if (-not $SuppressLog) { Write-Log "ERROR" "Volume is decrypted; cannot Rotate; skipping" }
                }
            }
            'Remove' {
                if ($PreventKeyPromptOnEveryBoot) {
                    Write-Log "WARNING" "Removal of recovery key is disabled when PreventKeyPromptOnEveryBoot is true; skipping"
                }
                elseif ($volume.ProtectionStatus -ne 'Off' -or $volume.VolumeStatus -ne 'FullyDecrypted') {
                    if (-not $SuppressLog) { Write-Log "WARNING" "Cannot remove recovery key when BitLocker is enabled or suspended; skipping" }
                }
                elseif (-not $recoveryPresent) {
                    if (-not $SuppressLog) { Write-Log "WARNING" "No valid recovery key to Remove; skipping" }
                }
                else {
                    Remove-RecoveryKey -v $volume
                }
            }
        }
    }
    
    # Helper function: Save key to AD & AAD if applicable
    function Backup-KeyToAD {
        param($volume)
        Write-Log "INFO" "Determining backup location for recovery key"
        
        # Get BitLocker protectors
        $protectors = Get-ValidRecoveryProtectors -v $volume
        if (-not $protectors) {
            Write-Log "WARNING" "No numeric recovery protectors found; nothing to back up"
            return
        }
        
        # Check join status with dsregcmd.exe
        $DSRegOutput = [PSObject]::New()
        & dsregcmd.exe /status | Where-Object { $_ -match ' : ' } | ForEach-Object {
            $Item = $_.Trim() -split '\s:\s'
            $DSRegOutput | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $Item[1] -ErrorAction SilentlyContinue
        }
        
        # Backup logic based on join status
        if ($DSRegOutput.AzureADJoined -eq 'YES') {
            Write-Log "INFO" "Device is AAD-joined; backing up to AAD"
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AAD"
                try {
                    BackupToAAD-BitLockerKeyProtector `
                        -MountPoint $volume.MountPoint `
                        -KeyProtectorId $keypair.KeyProtectorId `
                        -ErrorAction Stop
                    Write-Log "SUCCESS" "Protector ID $($keypair.KeyProtectorId) backed up to AAD"
                }
                catch {
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AAD: $_"
                }
            }
        }
        elseif ($DSRegOutput.DomainJoined -eq 'YES') {
            Write-Log "INFO" "Device is domain-joined; backing up to AD"
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AD"
                try {
                    Backup-BitLockerKeyProtector `
                        -MountPoint $volume.MountPoint `
                        -KeyProtectorId $keypair.KeyProtectorId `
                        -ErrorAction Stop
                    Write-Log "SUCCESS" "Protector ID $($keypair.KeyProtectorId) backed up to AD"
                }
                catch {
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AD: $_"
                }
            }
        }
        else {
            Write-Log "WARNING" "Device is not joined to AD or AAD; skipping backup"
        }
    }
    
    # Helper function: Check TPM pending status
    function Test-TpmPending {
        param($volume)
        # Sublogic: Determine if a TPM protector is pending based on protection status and presence
        $isOff = ($volume.ProtectionStatus -eq 0)
        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
        if ($isOff -and $hasTpm -and (Test-IsKeyBackupRequired -v $volume)) {
            return $false
        }
        return ($isOff -and $hasTpm)
    }
    
    # Helper function: Validate TPM exists
    function Ensure-TpmProtector {
        param($volume)
        # Check if the volume is the OS drive
        if ($volume.MountPoint -ne $osDrive) {
            Write-Log "WARNING" "TPM protectors can only be used on the OS drive. Skipping for $($volume.MountPoint)"
            return
        }
        Write-Log "INFO" "Ensuring TPM protector exists for $($volume.MountPoint)"
        # Sublogic: Verify TPM availability
        try {
            $tpm = Get-Tpm
            if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
                Write-Log "WARNING" "TPM is not available or not ready; skipping TPM protector addition"
                return
            }
        }
        catch {
            Write-Log "WARNING" "Failed to check TPM status: $_; skipping TPM protector addition"
            return
        }
        # Sublogic: Check if TPM protector already exists
        if ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }) {
            Write-Log "SUCCESS" "TPM protector already present"
            return
        }
        # Sublogic: Add a TPM protector
        try {
            Add-BitLockerKeyProtector `
            -MountPoint $volume.MountPoint `
            -TpmProtector `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue `
            -InformationAction SilentlyContinue | Out-Null
            Write-Log "SUCCESS" "TPM protector added (pending reboot)"
            if ($script:initialProtectionStatus -eq 'Off') {
                Write-Log "INFO" "Requires TPM during enablement (from a complete off state). You may remove later."
            }
        }
        catch {
            Write-Log "ERROR" "Failed to add TPM protector: $_"
        }
    }
    
    # Helper function: Check if TPM is pending a restart or encryption already in progress
    function Check-RestartRequirement {
        param($volume)
        # Sublogic: Check if volume is fully decrypted and protectors are present
        if ($volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
            $hasRecovery = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
            if ($hasTpm -and $hasRecovery) {
                Write-Log "INFO" "BitLocker enabled with TPM and recovery key protectors. No restart required."
            }
            elseif ($hasTpm) {
                Write-Log "WARNING" "Restart required to complete BitLocker setup with TPM."
            }
        }
        elseif ($volume.ProtectionStatus -eq 'On' -and $volume.VolumeStatus -eq 'EncryptionInProgress') {
            Write-Log "INFO" "Restart may be beneficial to speed up encryption process."
        }
        return $null
    }
    
    # Helper function: Validate TPM state and system configuration
    function Validate-BitLockerState {
        param($volume)
        # Sublogic: Check for pending reboots
        $rebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if ($rebootPending) {
            Write-Log "WARNING" "A system reboot is pending, which may affect BitLocker configuration. A reboot is recommended after changes have been made."
        }
        
        # Sublogic: Check TPM status
        try {
            $tpm = Get-Tpm
            if ($tpm.TpmPresent -and !$tpm.TpmReady) {
                Write-Log "WARNING" "TPM is present but not ready. This may cause BitLocker to enter recovery mode during the next boot."
            }
        }
        catch {
            Write-Log "WARNING" "Unable to check TPM status: $_"
        }
        
        # Sublogic: Check for Group Policy settings that may enforce TPM
        $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        if (Test-Path $gpoPath) {
            $useTpm = Get-ItemProperty -Path $gpoPath -Name "UseTPM" -ErrorAction SilentlyContinue
            if ($useTpm -and $useTpm.UseTPM -eq 1 -and !$UseTpmProtector) {
                Write-Log "WARNING" "Group Policy requires TPM protector, but UseTpmProtector is False. This may cause recovery prompt."
            }
        }
        
        # Sublogic: Check protector configuration
        $protectors = $volume.KeyProtector
        if ($protectors.Count -eq 0) {
            Write-Log "WARNING" "No protectors configured for volume. BitLocker will not function until protectors are added."
        }
    }
    
    # Helper function: Collect recovery key for later storage
    function Store-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Collecting recovery key for $($volume.MountPoint)"
        
        # Check if there are no protectors and the volume is fully disabled
        if (-not $volume.KeyProtector -and $volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "INFO" "No protectors and volume is fully disabled; recording 'N/A' for $($volume.MountPoint)"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - N/A"
            return
        }
        
        $maxRetries = 5
        $retryDelay = 2
        $retryCount = 0
        $protectors = $null
        
        # Retry loop to detect the new key
        do {
            Get-VolumeObject  # Refresh volume object each attempt
            $protectors = Get-ValidRecoveryProtectors -v $volume
            if ($protectors) {
                $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                # If there is a valid previous recovery key being rotated, ensure only the new one is stored
                if ($RecoveryKeyAction -eq 'Rotate' -and $script:PreviousRecoveryKey -and $latestProtector.KeyProtectorId -eq $script:PreviousRecoveryKey.KeyProtectorId) {
                    Write-Log "WARNING" "Detected old key ID $($latestProtector.KeyProtectorId) on attempt $($retryCount + 1); waiting for new key"
                }
                else {
                    Write-Log "INFO" "Detected new or current key ID $($latestProtector.KeyProtectorId) on attempt $($retryCount + 1)"
                    break
                }
            }
            else {
                Write-Log "WARNING" "No recovery key protectors detected on attempt $($retryCount + 1); retrying in $retryDelay seconds"
            }
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
        while ($retryCount -lt $maxRetries)
        
        # Store the latest key if available
        if ($protectors) {
            $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
            # Format the key information in a single-line string
            $keyInfo = "$($volume.MountPoint) - Protector ID: $($latestProtector.KeyProtectorId) | Recovery Key: $($latestProtector.RecoveryPassword)"
            Write-Log "INFO" "Collected recovery key for $($volume.MountPoint)"
            # Overwrite the recovery keys collection (no appending)
            $script:RecoveryKeys[$volume.MountPoint] = $keyInfo
            # Clear sensitive param per call
            Clear-Memory -VariableNames "keyInfo"
        }
        else {
            Write-Log "WARNING" "No recovery key protectors found after $maxRetries retries for $($volume.MountPoint); recording 'None'"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - None"
        }
    }

    # Helper function: Retrieve the remaining reboot count for a suspended BitLocker volume
    function Get-RebootCount {
        param (
            [Parameter(Mandatory)][string]$MountPoint
        )
        try {
            # Feed the direct mount point string into the filter
            $driveLetter = $MountPoint
            
            # Retrieve the CIM instance for the specified drive letter
            $volume = Get-CimInstance `
                -Namespace "ROOT/CIMV2/Security/MicrosoftVolumeEncryption" `
                -Class Win32_EncryptableVolume `
                -Filter "DriveLetter='$driveLetter'" -ErrorAction Stop
            
            if ($volume) {
                # Invoke the GetSuspendCount method to get the suspension count
                $result = $volume | Invoke-CimMethod -MethodName "GetSuspendCount" -ErrorAction Stop
                if ($result.ReturnValue -eq 0) {
                    # Return the SuspendCount if the method call was successful
                    Write-Log "INFO" "Drive $MountPoint Reboot Count: $($result.SuspendCount)"
                    return $result.SuspendCount
                }
                else {
                    Write-Log "WARNING" "GetSuspendCount returned non-zero value: $($result.ReturnValue) for $MountPoint"
                    return 0
                }
            }
            else {
                Write-Log "WARNING" "No encryptable volume found for drive letter $driveLetter"
                return $null
            }
        }
        catch {
            Write-Log "ERROR" "Error retrieving suspend count for $(MountPoint): $_"
            return $null
        }
    }
    
    # Helper function: Parse the switch input for state management
    function Get-DesiredProtectionState {
        param($action)
        switch ($action) {
            'Enable'  { return 'Enabled' }
            'Suspend' { return 'Suspended' }
            'Disable' { return 'Disabled' }
            default   { return 'Unknown' }
        }
    }
}

# =========================================
# PROCESS Block: Execute Bitlocker Actions
# =========================================
process {
    Write-Log "INFO" "Starting BitLocker management for all specified drives"
    
    # State management variables (reset for each run)
    $script:NumericProtectorCreated = $false
    $script:LastLogContext = @{}
    $script:LoggedRecoveryFound = @{}
    $script:ProcessedVolumes = @()
    
    Write-Host "`n=== Drive Processing ==="
    # Process each drive
    foreach ($MountPoint in $drives) {
        Write-Log "INFO" "Processing drive $MountPoint"
        
        # Reset per-drive state
        $script:PreviousRecoveryKey = $null
        $script:NumericProtectorCreated = $false
        
        # Update the volume state
        Get-VolumeObject
        $script:initialProtectionStatus = $blv.ProtectionStatus
        
        # Validate BitLocker and TPM state
        Validate-BitLockerState -v $blv
        
        # Evaluate TPM status and restart requirements
        $isTpmPending = $false
        if ($blv.ProtectionStatus -eq 'Off') {
            $isTpmPending = Test-TpmPending -v $blv
            if ($isTpmPending) {
                $restartMessage = Check-RestartRequirement -v $blv
                switch ($BitLockerProtection) {
                    'Enable' {
                        Write-Log "INFO" "TPM is pending, but 'Enable' selected - continuing"
                        if ($restartMessage) { Write-Log "INFO" $restartMessage }
                    }
                    'Suspend' {
                        Write-Log "WARNING" "Cannot suspend - BitLocker is not yet enabled."
                        if ($restartMessage) { Write-Log "INFO" $restartMessage }
                        continue
                    }
                    default {
                        Write-Log "WARNING" "TPM protector added but protection is Off; restart may be required."
                        if ($restartMessage) { Write-Log "INFO" $restartMessage }
                        continue
                    }
                }
            }
            else {
                Write-Log "INFO" "BitLocker is not enabled and no TPM protector is pending."
            }
        }
        elseif ($blv.ProtectionStatus -eq 'Suspended') {
            Write-Log "INFO" "BitLocker is in a suspended state."
        }
        
        # TPM availability safety check
        try {
            $tpm = Get-Tpm
            $tpmAvailable = $tpm.TpmPresent -and $tpm.TpmReady
        }
        catch {
            $tpmAvailable = $false
        }
        if (-not $tpmAvailable -and $PreventKeyPromptOnEveryBoot) {
            Write-Log "ERROR" "TPM is not available and PreventKeyPromptOnEveryBoot is true for $MountPoint. Skipping."
            continue
        }
        elseif (-not $tpmAvailable) {
            Write-Log "WARNING" "TPM is not available for $MountPoint, but PreventKeyPromptOnEveryBoot is false. Continuing without TPM."
        }
        
        # Manage BitLocker protection
        switch ($BitLockerProtection) {
            'Enable' {
                Write-Log "INFO" "Requested: Enable/Resume protection for $MountPoint"
                if ($blv.ProtectionStatus -eq 'Suspended') {
                    Write-Log "INFO" "BitLocker is suspended; resuming protection"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -v $blv
                        Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                        Get-VolumeObject
                    }
                    try {
                        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                        Write-Log "SUCCESS" "Protection resumed"
                        Get-VolumeObject
                        # Set state
                        $finalEnableState = "resumed"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to resume protection: $_"
                        continue
                    }
                }
                elseif ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                    Write-Log "INFO" "Volume is FullyEncrypted but Protection is Off; adding protectors and resuming"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -v $blv
                        try {
                            Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed before recovery action"
                            Get-VolumeObject
                            $script:PreviousRecoveryKey = (Get-ValidRecoveryProtectors -v $blv | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1)
                            Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                            Get-VolumeObject
                            # Set state
                            $finalEnableState = "resumed"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $_"
                            continue
                        }
                    }
                    else {
                        if ($UseTpmProtector) { Ensure-TpmProtector -v $blv }
                        try {
                            Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed"
                            Get-VolumeObject
                            Invoke-RecoveryAction -v $blv -Action 'Ensure' -SuppressLog
                            # Set state
                            $finalEnableState = "resumed"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $_"
                            continue
                        }
                    }
                }
                elseif ($blv.ProtectionStatus -eq 'Off') {
                    Write-Log "INFO" "Volume is off; enabling with protectors"
                    if ($blv.VolumeStatus -eq 'DecryptionInProgress') {
                        Write-Log "WARNING" "Volume is decrypting; skipping enablement for safety"
                        continue
                    }
                    if ($blv.VolumeStatus -eq 'FullyDecrypted') {
                        Remove-AllProtectors -v $blv
                    }
                    if ($UseUsedSpaceOnly) {
                        Write-Log "INFO" "Enabling BitLocker with -UsedSpaceOnly"
                    }
                    else {
                        Write-Log "INFO" "Enabling BitLocker without -UsedSpaceOnly (full disk encryption)"
                    }
                    try {
                        Enable-BitLocker `
                            -MountPoint $MountPoint `
                            -EncryptionMethod $BitlockerEncryptionMethod `
                            -RecoveryPasswordProtector `
                            -SkipHardwareTest `
                            -ErrorAction Stop `
                            -WarningAction SilentlyContinue `
                            -InformationAction SilentlyContinue `
                            -UsedSpaceOnly:$UseUsedSpaceOnly | Out-Null
                        Write-Log "SUCCESS" "BitLocker enabled with recovery key protector"
                        Get-VolumeObject
                        # Set state
                        $usedSpaceOnlyValue = if ($UseUsedSpaceOnly) { 'Yes' } else { 'No' }
                        if (-not (Test-Path $BitLockerStateStoragePath)) {
                            New-Item -Path $BitLockerStateStoragePath -Force | Out-Null
                        }
                        # Store custom registry key for each drive state. No other way to retrive after.
                        Set-ItemProperty -Path $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $MountPoint" -Value $usedSpaceOnlyValue -Type String -Force
                        Write-Log "INFO" "Stored UsedSpaceOnly setting in registry: $usedSpaceOnlyValue"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to enable BitLocker: $_"
                        continue
                    }
                    if ($UseTpmProtector) {
                        Write-Log "INFO" "Adding TPM protector post-enablement"
                        Ensure-TpmProtector -v $blv
                        Get-VolumeObject
                    }
                    # Set state
                    $finalEnableState = "enabled"
                }
                else {
                    Write-Log "INFO" "Protection already active; reconciling protectors"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -v $blv
                        Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                    }
                    else {
                        Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                        if ($UseTpmProtector) { Ensure-TpmProtector -v $blv }
                    }
                    Get-VolumeObject
                    if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                        try {
                            Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed"
                            Get-VolumeObject
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $_"
                            continue
                        }
                    }
                    $finalEnableState = "reconciled"
                }
                if ($finalEnableState) {
                    switch ($finalEnableState) {
                        'resumed' { Write-Log "INFO" "BitLocker protection successfully resumed" }
                        'enabled' {
                            if ($blv.VolumeStatus -eq 'EncryptionInProgress' -or $blv.VolumeStatus -eq 'EncryptionPaused') {
                                Write-Log "INFO" "BitLocker is encrypting (status: $($blv.VolumeStatus))."
                            }
                        }
                        'reconciled' { Write-Log "INFO" "Protectors reconciled; protection status: $($blv.ProtectionStatus)" }
                    }
                }
            }
            'Suspend' {
                Write-Log "INFO" "Requested: Suspend protection for $MountPoint"
                if ($blv.VolumeStatus -eq 'EncryptionInProgress') {
                    Write-Log "WARNING" "Cannot suspend - BitLocker is currently encrypting the volume."
                }
                elseif ($blv.ProtectionStatus -eq 'Suspended') {
                    Write-Log "WARNING" "Already suspended; skipping"
                }
                else {
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -v $blv
                        Ensure-RecoveryKey -v $blv
                    }
                    else {
                        if ($UseTpmProtector) { Ensure-TpmProtector -v $blv }
                        Ensure-RecoveryKey -v $blv
                    }
                    Get-VolumeObject
                    try {
                        Suspend-BitLocker -MountPoint $MountPoint -RebootCount $SuspensionRebootCount -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                        
                       # Set state
                        $suspensionCountValue = $SuspensionRebootCount
                        if (-not (Test-Path $BitLockerStateStoragePath)) {
                            New-Item -Path $BitLockerStateStoragePath -Force | Out-Null
                        }
                        # Store initial reboot count in registry key for each drive state
                        Set-ItemProperty -Path $BitLockerStateStoragePath -Name "$InitialSuspensionCountValueName $MountPoint" -Value $suspensionCountValue -Type String -Force
                        # Write-Log "INFO" "Stored initial suspensionCountValue setting in registry: $suspensionCountValue"
                        
                        Get-VolumeObject
                    }
                    catch {
                        Write-Log "ERROR" "Failed to suspend protection: $_"
                        continue
                    }
                }
            }
            'Disable' {
                Write-Log "INFO" "Requested: Disable protection for $MountPoint"
                if ($MountPoint -eq $osDrive) {
                    # Disable auto-unlock on all data drives with auto-unlock enabled
                    $dataDrivesWithAutoUnlock = Get-BitLockerVolume | Where-Object { $_.MountPoint -ne $osDrive -and $_.AutoUnlockEnabled }
                    foreach ($dataDrive in $dataDrivesWithAutoUnlock) {
                        Write-Log "INFO" "Disabling auto-unlock on $($dataDrive.MountPoint)"
                        try {
                            Disable-BitLockerAutoUnlock -MountPoint $dataDrive.MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Auto-unlock disabled on $($dataDrive.MountPoint)"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to disable auto-unlock on $($dataDrive.MountPoint): $_"
                        }
                    }
                }
                if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
                    Write-Log "WARNING" "Already disabled; skipping"
                }
                else {
                    try {
                        Disable-BitLocker -MountPoint $MountPoint -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                        Write-Log "SUCCESS" "Decryption initiated"
                        Get-VolumeObject
                    }
                    catch {
                        Write-Log "ERROR" "Failed to disable protection: $_"
                        continue
                    }
                }
                if (-not (Test-Path $BitLockerStateStoragePath)) {
                    New-Item -Path $BitLockerStateStoragePath -Force | Out-Null
                }
                Set-ItemProperty -Path $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $MountPoint" -Value "N/A" -Type String -Force
                Write-Log "INFO" "Set UsedSpaceOnly registry to 'N/A'"
                Set-ItemProperty -Path $BitLockerStateStoragePath -Name "$InitialSuspensionCountValueName $MountPoint" -Value "N/A" -Type String -Force
                Write-Log "INFO" "Set InitialSuspensionCount registry to 'N/A'"
            }
        }
        
        # Manage auto-unlock for non-OS drives if applicable
        if ($BitLockerProtection -eq 'Enable') {
            if ($MountPoint -ne $osDrive) {
                $osVolume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
                if ($AutoUnlockNonOSDrives) {
                    # Periodically check OS drive encryption status
                    $maxWaitSeconds = 1800  # 30 minutes max wait
                    $waitIntervalSeconds = 30
                    $elapsedSeconds = 0
                    
                    # Loop until system drive is fully encrypted to enable Auto-Unlock for non OS drives
                    while ($osVolume -and $osVolume.VolumeStatus -ne 'FullyEncrypted' -and $elapsedSeconds -lt $maxWaitSeconds) {
                        Start-Sleep -Seconds $waitIntervalSeconds
                        $elapsedSeconds += $waitIntervalSeconds
                        $osVolume = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
                    }
                    
                    # When OS Drive is fully encrypted
                    if ($osVolume -and $osVolume.VolumeStatus -eq 'FullyEncrypted') {
                        Write-Log "INFO" "OS Drive $osDrive is now fully encrypted... (Elapsed: $elapsedSeconds seconds)"
                        Write-Log "INFO" "Enabling auto-unlock for non-OS drive $MountPoint"
                        try {
                            # Enable AutoUnlock
                            Enable-BitLockerAutoUnlock -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Auto-unlock enabled for $MountPoint"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to enable auto-unlock for ${MountPoint}: $_"
                        }
                    }
                    else {
                        Write-Log "WARNING" "Cannot enable auto-unlock for $MountPoint because OS drive is not fully encrypted after $maxWaitSeconds seconds."
                    }
                }
                # Skip requirement 
                else {
                    Write-Log "INFO" "Skipping auto-unlock for non-OS drive $MountPoint"
                    try {
                        # Could be used to also disable autounlock like so by setting AutoUnlockNonOSDrives to false
                        # Disable-BitLockerAutoUnlock -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                        Write-Log "INFO" "Auto-Unlock was not opted for. Ensure ($MountPoint) is configured properly."
                    }
                    catch {
                        Write-Log "ERROR" "Failed to disable auto-unlock for ${MountPoint}: $_"
                    }
                }
            }
        }
        
        # Apply recovery key action if not part of Enable process
        if ($BitLockerProtection -ne 'Enable') {
            Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction
            Get-VolumeObject
        }
        
        # Backup to AD if set
        if ($BackupToAD) {
            Write-Host "`n=== AD/Intune Key Backup ==="
            Write-Log "INFO" "Backing up key for $MountPoint"
            Backup-KeyToAD -v $blv
        }
        
        # Separate each volume in output
        Write-Host ""
        
        # Store volume object for END block
        $script:ProcessedVolumes += ,$blv
    }
}

# =========================================
# END Block: Generate Card & Finalization
# =========================================
end {
    # Will always have a line space from above
    Write-Host "=== BitLocker Card Generation ==="
    Write-Log "INFO" "Generating status card for all processed drives"
    
    # Initialize combined HTML for all cards
    # Generate status cards for all fixed drives
    $allCardsHtml = ""
    foreach ($drive in $allFixedDrives) {
        $MountPoint = $drive
        $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
        if ($blv) {
            # Determine title icon and color (dynamic)
            switch ($blv.ProtectionStatus) {
                'On' {
                    switch ($blv.VolumeStatus) {
                        'FullyEncrypted' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#26A644" }
                        'EncryptionInProgress' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                        default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                    }
                }
                'Off' {
                    switch ($blv.VolumeStatus) {
                        'DecryptionInProgress' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                        'FullyDecrypted' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                        default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                    }
                }
                # Not a real option- but should be
                'Suspended' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
            }
            
            # Generate protection and volume status HTML (dynamic)
            $protectionStatusHtml = switch ($blv.ProtectionStatus) {
                'On' { '<i class="fas fa-check-circle" style="color:#26A644;"></i> On' }
                'Off' {
                    switch ($blv.VolumeStatus) {
                        'DecryptionInProgress' { '<i class="fas fa-check-circle" style="color:#D9534F;"></i> Pending Off' }
                        'FullyDecrypted' { '<i class="fas fa-check-circle" style="color:#D9534F;"></i> Off' }
                        # If Off and volume status is FullyEncrypted, the volume is suspended
                        default {
                            $rebootCount = Get-RebootCount -MountPoint ([string]$MountPoint)
                            # Include reboot count if suspended and reboot count is greater than 0
                            if ($null -ne $rebootCount -and $rebootCount -gt 0) {
                                '<i class="fas fa-check-circle" style="color:#F0AD4E;"></i> Suspended<br>     Reboot(s) Left: ' + $rebootCount
                            }
                            # Dont include reboot count if 0
                            else {
                                '<i class="fas fa-check-circle" style="color:#F0AD4E;"></i> Suspended'
                            }
                        }
                    }
                }
                default { $blv.ProtectionStatus }
            }
            $volumeStatusHtml = switch ($blv.VolumeStatus) {
                'FullyEncrypted' { '<i class="fas fa-lock" style="color:#26A644;"></i> Fully Encrypted' }
                'EncryptionInProgress' { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Encryption in Progress' }
                'FullyDecrypted' { '<i class="fas fa-unlock" style="color:#D9534F;"></i> Fully Decrypted' }
                'DecryptionInProgress' { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Decryption in Progress' }
                default { $blv.VolumeStatus }
            }
            
            $encryptionMethod = if ($blv.EncryptionMethod) { $blv.EncryptionMethod } else { 'N/A' }
            $protectors = if ($blv.KeyProtector) { ($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " } else { 'None' }
            
            # Determine UsedSpaceOnly display value
            if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
                $usedSpaceOnlyDisplay = "N/A"
            }
            else {
                try {
                    $value = Get-ItemPropertyValue -Path $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $MountPoint" -ErrorAction Stop
                    $usedSpaceOnlyDisplay = if ($value -in @("Yes", "No")) { $value } else { "Unknown" }
                }
                catch {
                    $usedSpaceOnlyDisplay = "Unknown"
                }
            }
            
            # Combine Card Panel Information
            $bitlockerInfo = [PSCustomObject]@{
                'Protection Status'       = $protectionStatusHtml
                'Volume Status'           = $volumeStatusHtml
                'Volume'                  = $MountPoint
                'Encryption Method'       = $encryptionMethod
                'Protectors'              = $protectors
                'Encrypt Used Space Only' = $usedSpaceOnlyDisplay
            }
            
            # Generate card for this drive
            $cardHtml = Get-NinjaOneInfoCard -Title "$CardTitle ($MountPoint)" -Data $bitlockerInfo -Icon $CardIcon -BackgroundGradient $CardBackgroundGradient -BorderRadius $CardBorderRadius -IconColor $CardIconColor -SeparationMargin $CardSeparationMargin
            $allCardsHtml += $cardHtml
        }
    }
    
    # Store all cards in the custom field
    try {
        $allCardsHtml | Ninja-Property-Set-Piped -Name $BitLockerStatusFieldName
        Write-Log "SUCCESS" "BitLocker status cards stored in '$BitLockerStatusFieldName'"
    }
    catch {
        Write-Log "ERROR" "Failed to store status cards: $_"
    }
    
    # Collect recovery keys for all fixed drives
    foreach ($drive in $allFixedDrives) {
        $blv = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
        if ($blv) {
            Store-RecoveryKey -v $blv
        }
    }
    
    # Store all recovery keys in single-line format
    Write-Log "INFO" "Storing all collected recovery keys in secure field"
    try {
        if ($script:RecoveryKeys.Count -eq 0) {
            Write-Log "INFO" "No recovery keys collected; setting secure field to N/A"
            Ninja-Property-Set $RecoveryKeySecureFieldName "N/A" | Out-Null
        }
        else {
            $allKeys = ($script:RecoveryKeys.Values -join "; ")
            Ninja-Property-Set $RecoveryKeySecureFieldName $allKeys | Out-Null
            Write-Log "SUCCESS" "Stored recovery keys for drive(s) ($($script:RecoveryKeys.Keys -join ', ')) in '$RecoveryKeySecureFieldName'"
            # Clear sensitive data
            Clear-Memory -VariableNames "allKeys"
        }
    }
    catch {
        Write-Log "ERROR" "Failed to store recovery keys: $_"
    }
    
    # Clear sensitive state
    Clear-Memory -VariableNames "RecoveryKeys"
    
    Write-Host "`n=== Complete ==="
    Write-Log "SUCCESS" "BitLocker management completed"
}