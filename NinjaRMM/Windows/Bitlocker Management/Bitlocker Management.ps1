#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 02-18-2026
    
    Note:
    02-18-2026: All USB drives are now blacklisted. All USB parameters removed. Recovery key collection now validates RecoveryPassword is non-empty. Added Maintain protection mode. Modified card order so OS Volume is always first. Squashed some bugs & edge case errors.
    02-06-2026: @Leapo pointed out USB Storage handling issues & a few other bugs. Attempted to implement safe USB handling. Optionally validates the secure field data (Custom Field automation Read/Write access required for this).
    12-23-2025: @Pegz in the NinjaOne discord mentioned this issue. Addressed multi-volume compatabillity for drives with multiple volumes, improved clarity.
    11-06-2025: @gmclelland in the NinjaOne discord mentioned this issue. During the logic clarity impovement process, one of the Param section brackets were removed by mistake. This has now been addressed.
    09-25-2025: Addressed a bug in the Get-SuspendedCount function, and furthermore the Cards Suspended Count logic to properly display the remaining suspend reboot count. Also improved clarity and formatting across the board.
    07-03-2025: General cleanup. Non critical output and syntax
    06-28-2025: @seravous in the NinjaOne discord helped dtermine an unlikely outcome that was not accounted for. Also addresses the possibillity of more than one numerical password during a enablement/resume process in with a niche initial starting point.
    06-18-2025: Modified AD/Intune Backup logic, improved Suspension insight, and Get-RebootCount logic.
    06-02-2025: Addressed a sanitization issue that prevented non-OS volumes from being disabled individually without the OS Volume.
    05-28-2025: Address suspend logic and validated
    05-27-2025: Status (Custom Field, Secure Field) update for all fixed drives, regardless of management as a safety precaution. Zero overriding of keys, etc.
    05-23-2025: Cleanup, big fixes, and consistency, testing.
    05-22-2025: Rewrite for multi-volume handling, improved safety, and use case.
    05-19-2025: General cleanup improvements.
    04-25-2025: Creation and validation testing.
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

.PARAMETER VerifyRecoveryKeyStorage
    Switch. When enabled, runs a pre-flight check before drive processing,
    writes a realistic-sized test payload to the secure field, reads it back
    to confirm permissions and field capacity. Assumes full recovery key data
    for every drive (security-case). If the pre-flight fails, the script aborts.
    Also verifies recovery keys after storage in the end block.
    REQUIRES: The secure custom field must have 'Read/Write' (Automation)
    permission enabled in NinjaRMM. Default: true.
#>

[CmdletBinding()]
param(
    # Drive letter        Ninja Variable Resolution                                                 Fallback
    [string[]]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint -split ',' } else { @((Get-CimInstance Win32_OperatingSystem).SystemDrive) }), # Ninja Script Variable; String
    
    # Dropdown options                                                                             Ninja Variable Resolution                                                    Fallback
    [ValidateSet("Enable", "Maintain", "Suspend", "Disable")]   [string]$BitLockerProtection       = $(if ($env:bitlockerProtection)        { $env:bitlockerProtection }        else { "Enable" }),    # Ninja Script Variable; Dropdown
    [ValidateSet("Ensure", "Rotate", "Remove")]                 [string]$RecoveryKeyAction         = $(if ($env:bitlockerRecoveryKeyAction) { $env:bitlockerRecoveryKeyAction } else { "Ensure" }),    # Ninja Script Variable; Dropdown
    [ValidateSet("Aes128", "Aes256", "XtsAes128", "XtsAes256")] [string]$BitlockerEncryptionMethod = $(if ($env:bitlockerEncryptionMethod)  { $env:bitlockerEncryptionMethod }  else { "XtsAes256" }), # Ninja Script Variable; Dropdown
    
    # Independent switches             Ninja Variable Resolution                                                                      Fallback
    [switch]$UseTpmProtector           = $(if ($env:useBitlockerTpmProtector) { [Convert]::ToBoolean($env:useBitlockerTpmProtector) } else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$AutoUnlockNonOSVolumes    = $(if ($env:autoUnlockNonOsVolumes) { [Convert]::ToBoolean($env:autoUnlockNonOsVolumes) }     else { $true }),  # Static - Optional Ninja Script Variable; Checkbox
    [switch]$ApplyToAllFixedDisk       = $(if ($env:applyToAllFixedDisk) { [Convert]::ToBoolean($env:applyToAllFixedDisk) }           else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$UseUsedSpaceOnly          = $(if ($env:encryptUsedspaceonly) { [Convert]::ToBoolean($env:encryptUsedspaceonly) }         else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$BackupToAD                = $(if ($env:bitlockerBackupToAd) { [Convert]::ToBoolean($env:bitlockerBackupToAd) }           else { $false }), # Ninja Script Variable; Checkbox
    [switch]$VerifyRecoveryKeyStorage  = $(if ($env:verifyRecoveryKeyStorage) { [Convert]::ToBoolean($env:verifyRecoveryKeyStorage) } else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice           = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }                   else { $false }), # Ninja Script Variable; Checkbox
    [int]$SuspensionRebootCount        = $(if ($env:bitlockerSuspensionRebootCount) { [int]$env:bitlockerSuspensionRebootCount }      else { 1 }),      # Static - Optional Ninja Script Variable; Integer
    
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
    
    ############
    # OS Volume #
    ############
    # Define OS Volume
    $script:OsVolume = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    $osVolume = $script:OsVolume
    
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
            $spannedVolumes = Get-Volume | Where-Object { $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' -and $_.DriveLetter } |
                Where-Object { (Get-Partition -Volume $_).DiskNumber.Count -gt 1 }
            if ($spannedVolumes) {
                Write-Host "[WARNING] Detected spanned volumes: $($spannedVolumes.DriveLetter -join ', '). BitLocker may not support these configurations."
            }
            Write-Host "[SUCCESS] Drive dependency check completed"
        }
        catch {
            Write-Host "[ERROR] Failed to check drive dependencies: $($_.Exception.Message)"
        }
    }
    # Immediately call drive dependency check ^
    Test-DriveDependencies
    
    # Helper function: Detect drive letters connected via USB bus
    # USB-connected drives (even if Windows reports them as 'Fixed') are always excluded from processing.
    # Encrypting USB drives with BitLocker via automated tooling is unsafe, disconnection during
    # encryption, key management across machines, and auto-unlock reliability make it too risky.
    function Get-USBDriveLetters {
        $usbLetters = @()
        
        # Primary method: Get-PhysicalDisk (available on Win10/Server2016+)
        try {
            $usbDisks = Get-PhysicalDisk | Where-Object { $_.BusType -eq 'USB' }
            if ($usbDisks) {
                foreach ($usbDisk in $usbDisks) {
                    $disk = $usbDisk | Get-Disk -ErrorAction SilentlyContinue
                    if ($null -ne $disk) {
                        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
                            Where-Object { $_.DriveLetter }
                        foreach ($partition in $partitions) {
                            $letter = "$($partition.DriveLetter):"
                            $usbLetters += $letter
                            Write-Host "[INFO] Detected USB drive: $letter (PhysicalDisk: $($usbDisk.FriendlyName), Disk #$($disk.Number))"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[WARNING] Get-PhysicalDisk USB detection failed: $($_.Exception.Message). Falling back to WMI."
        }
        
        # Fallback method: Win32_DiskDrive (broader compatibility)
        if ($usbLetters.Count -eq 0) {
            try {
                $wmiUsbDisks = Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }
                foreach ($wmiDisk in $wmiUsbDisks) {
                    $partitions = Get-CimAssociatedInstance -InputObject $wmiDisk -ResultClassName Win32_DiskPartition
                    foreach ($partition in $partitions) {
                        $logicalDisks = Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_LogicalDisk
                        foreach ($logicalDisk in $logicalDisks) {
                            if ($logicalDisk.DeviceID) {
                                $usbLetters += $logicalDisk.DeviceID
                                Write-Host "[INFO] Detected USB drive (WMI fallback): $($logicalDisk.DeviceID) (Model: $($wmiDisk.Model))"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "[ERROR] WMI USB detection also failed: $($_.Exception.Message)"
            }
        }
        
        return $usbLetters | Select-Object -Unique
    }
    
    # Blacklist USB drives, always excluded from processing regardless of configuration
    $script:USBDriveLetters = Get-USBDriveLetters
    if ($script:USBDriveLetters) {
        Write-Host "[INFO] USB drives blacklisted from processing: $($script:USBDriveLetters -join ', ')"
    }
    
    # Handle ApplyToAllFixedDisk, otherwise parse MountPoint
    if ($ApplyToAllFixedDisk) {
        Write-Host "[INFO] ApplyToAllFixedDisk is set; retrieving all fixed disks"
        # Ensure OS Volume (e.g., C:) is first in the $drives array by assigning it a sort key of 0
        $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
            Sort-Object { if ($_.DriveLetter -eq (Get-CimInstance Win32_OperatingSystem).SystemDrive[0]) { 0 } else { 1 } } |
            Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' }
        if (-not $drives) {
            Write-Host "[ERROR] No fixed disks found on this system"
            exit 1
        }
        # Blacklist USB-connected drives
        if ($script:USBDriveLetters) {
            $preFilterCount = $drives.Count
            $drives = $drives | Where-Object { $_ -notin $script:USBDriveLetters }
            $excludedCount = $preFilterCount - $drives.Count
            if ($excludedCount -gt 0) {
                Write-Host "[WARNING] Excluded $excludedCount USB-connected drive(s) from processing: $($script:USBDriveLetters -join ', ')"
            }
            if (-not $drives) {
                Write-Host "[ERROR] All fixed disks are USB-connected. No drives to process."
                exit 1
            }
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
                        # USB drive blacklist check
                        if ($mp -in $script:USBDriveLetters) {
                            Write-Host "[WARNING] MountPoint '$mp' is a USB-connected drive; skipping (USB drives are excluded from processing)"
                        }
                        else {
                            $drives += $mp
                        }
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
    
    # Get all fixed drives for reporting (regardless of selection logic), excluding USB
    # Sorted: OS volume first, then alphabetical. Ensures cards and recovery keys use the same ordering
    $allFixedDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' } |
        Sort-Object @{ Expression = { if ($_ -eq $OsVolume) { 0 } else { 1 } } }, @{ Expression = { $_ } }
    if ($script:USBDriveLetters) {
        $allFixedDrives = $allFixedDrives | Where-Object { $_ -notin $script:USBDriveLetters }
    }
    Write-Host "[INFO] allFixedDrives populated"
    
    # Validate SuspensionRebootCount
    if ($SuspensionRebootCount -lt 0 -or $SuspensionRebootCount -gt 10) {
        Write-Host "[WARNING] SuspensionRebootCount must be between 1 and 10; setting to 1"
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
    Write-Host "  - Auto Unlock non-OS volumes: $AutoUnlockNonOSVolumes"
    Write-Host "  - Verify Recovery Key Storage: $VerifyRecoveryKeyStorage"
    
    # Sanitization Section: Correct impossible or conflicting input combinations with detailed output
    Write-Host "`n=== Section: Sanitization ==="
    
    # PreventKeyPromptOnEveryBoot sanitization
    if ($PreventKeyPromptOnEveryBoot) {
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is ON; checking TPM, Recovery Key, and AutoUnlock requirements"
        if ($BitLockerProtection -in @("Enable", "Maintain", "Suspend")) {
            Write-Host "[INFO] Protection action '$BitLockerProtection' selected; validating protector requirements"
            # Sublogic: if TPM is disabled and BitLocker is Enabled/Suspended, handle based on PreventKeyPromptOnEveryBoot bool
            if (-not $UseTpmProtector) {
                Write-Host "[WARNING] TPM protector enforcement: UseTpmProtector was false, but PreventKeyPromptOnEveryBoot requires TPM for '$BitLockerProtection'. Setting UseTpmProtector to true."
                $UseTpmProtector = $true
            }
            else {
                Write-Host "[INFO] TPM protector enforcement: UseTpmProtector is true, meeting PreventKeyPromptOnEveryBoot requirement"
            }
            if (-not $AutoUnlockNonOSVolumes) {
                Write-Host "[WARNING] AutoUnlock enforcement: AutoUnlockNonOSVolumes was false, but PreventKeyPromptOnEveryBoot requires AutoUnlock (Non OS Drives) for '$BitLockerProtection'. Setting AutoUnlockNonOSVolumes to true."
                $AutoUnlockNonOSVolumes = $true
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
            if ($drives -contains $OsVolume -and $bitLockerVolumes -contains $OsVolume) {
                # If OS Volume is included and encrypted, ensure all encrypted drives are disabled for safety
                $drives = ($drives + $bitLockerVolumes) | Select-Object -Unique
                Write-Host "[INFO] Including all BitLocker-enabled volumes for disabling due to OS Volume selection and PreventKeyPromptOnEveryBoot being enabled."
            }
            else {
                # Allow disabling of explicitly specified drives, even if OS Volume is encrypted but not selected
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
        if (-not $UseTpmProtector -and $BitLockerProtection -in @("Enable", "Maintain", "Suspend")) {
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
    
    # Check if OS Volume is encrypted or included when enabling BitLocker on non-OS volumes
    if ($BitLockerProtection -eq 'Enable') {
        $nonOsVolumes = $drives | Where-Object { $_ -ne $OsVolume }
        if ($nonOsVolumes) {
            # Handle safely with PreventKeyPromptOnEveryBoot
            if ($PreventKeyPromptOnEveryBoot) {
                if ($drives -notcontains $OsVolume) {
                    # Set the OS Volume
                    $osVolume = Get-BitLockerVolume -MountPoint $OsVolume -ErrorAction SilentlyContinue
                    # Quit if there is no OS Volume
                    if (-not $osVolume -or $osVolume.VolumeStatus -ne 'FullyEncrypted') {
                        Write-Host "[ERROR] Cannot enable BitLocker on non-OS volumes ($($nonOsVolumes -join ', ')) without the OS Volume ($OsVolume) being encrypted or selected for encryption when PreventKeyPromptOnEveryBoot is enabled."
                        Write-Host "[ERROR] OS Volume ($OsVolume) must be encrypted or included in the operation to enable BitLocker on non-OS volumes when PreventKeyPromptOnEveryBoot is enabled."
                        exit 1
                    }
                    else {
                        Write-Host "[INFO] OS Volume ($OsVolume) is already fully encrypted; proceeding with non-OS volume enablement."
                    }
                }
                else {
                    Write-Host "[INFO] OS Volume ($OsVolume) is included in the drives to be encrypted; proceeding."
                }
            }
            # Skip system drive requirement. Will result in key prompting
            else {
                $osVolume = Get-BitLockerVolume -MountPoint $OsVolume -ErrorAction SilentlyContinue
                if (-not $osVolume -or $osVolume.VolumeStatus -ne 'FullyEncrypted') {
                    Write-Host "[WARNING] Enabling BitLocker on non-OS volumes ($($nonOsVolumes -join ', ')) without the OS Volume ($OsVolume) being encrypted. This may affect auto-unlock functionality."
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
        
        # Sublogic: Track errors and warnings for exit code determination
        if ($Level -eq 'ERROR') {
            if ($null -ne $script:Errors) { $script:Errors.Add($Message) }
            $script:ScriptSuccess = $false
        }
        elseif ($Level -eq 'WARNING') {
            if ($null -ne $script:Warnings) { $script:Warnings.Add($Message) }
        }
        
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
    
    # Helper function: Set or create a registry value, retrying until correct
    function RegistryShouldBe {
        param(
            [Parameter(Mandatory)][string]$KeyPath,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)]$Value,
            [ValidateSet('DWord','String','ExpandString','MultiString','Binary','QWord')]
            [string]$Type = 'DWord'
        )
        
        if (-not (Test-Path $KeyPath)) {
            try {
                New-Item -Path $KeyPath -Force | Out-Null
            }
            catch {
                Write-Log "ERROR" "Failed to create registry key for '$Name' at '$KeyPath': $_"
                return
            }
        }
        
        # Comparison helper that handles all types including Binary (byte arrays).
        # PowerShell's -ceq/-ne operators act as element filters on arrays instead of
        # returning a boolean, so arrays are compared via joined string representation.
        function Test-RegistryValueEqual {
            param(
                $Current,
                $Desired
            )
            if ($null -eq $Current -and $null -eq $Desired) { return $true }
            if ($null -eq $Current -or  $null -eq $Desired) { return $false }
            if ($Current -is [array] -or $Desired -is [array]) {
                return (($Current -join ',') -ceq ($Desired -join ','))
            }
            return ($Current -ceq $Desired)
        }
        
        $attempt = 0
        do {
            $attempt++
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
            if (-not $valuesMatch) {
                # For Binary, log name + byte length only. Raw byte arrays are unreadable noise
                $displayValue   = if ($Type -eq 'Binary') { "Binary ($($Value.Length) bytes)" } else { $Value }
                $displayCurrent = if ($Type -eq 'Binary' -and $current) { "Binary ($($current.Length) bytes)" } else { $current }
                if ($null -eq $current) {
                    Write-Log "VERBOSE" "Creating $Name = $displayValue"
                    New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                }
                else {
                    Write-Log "VERBOSE" "Updating $Name from $displayCurrent to $displayValue"
                    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
                }
            }
            
            Start-Sleep -Milliseconds 800
            
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
        } while (-not $valuesMatch -and $attempt -lt 5)
        
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
                
        if (Test-RegistryValueEqual -Current $final -Desired $Value) {
            $displayFinal = if ($Type -eq 'Binary') { "Binary ($($Value.Length) bytes)" } else { $Value }
            Write-Log "VERBOSE" "$Name confirmed $displayFinal"
        }
        else {
            $displayFail = if ($Type -eq 'Binary') { "Binary ($($Value.Length) bytes)" } else { $Value }
            Write-Log "WARNING" "$Name failed to set to $displayFail"
        }
    }
    
    # Helper function: Refresh drive state
    function Get-VolumeObject {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$TargetMountPoint,
            
            # Suppress the one-time "Volume state refreshed" log
            [switch]$SuppressLog
        )
        
        try {
            # Retrieve BitLocker volume object and suppress non-error output
            $global:blv = Get-BitLockerVolume `
                -MountPoint $TargetMountPoint `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue
                
            # Only log volume state if not already logged for this mount point in this run
            if (-not $script:LastLogContext) { $script:LastLogContext = @{} }
            
            if (-not $SuppressLog -and -not $script:LastLogContext.ContainsKey("VolumeState-$TargetMountPoint")) {
                Write-Host "[SUCCESS] Volume state refreshed: ProtectionStatus=$($global:blv.ProtectionStatus), VolumeStatus=$($global:blv.VolumeStatus)"
                $script:LastLogContext["VolumeState-$TargetMountPoint"] = $true
            }
            
            return $global:blv
        }
        catch {
            Write-Log "ERROR" "No BitLocker volume at $($TargetMountPoint): $($_.Exception.Message)"
            return $null
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
        param(
            [Parameter(Mandatory)]$volume
        )
        # Sublogic: Suppress logging from nested recovery protector scans
        $valid = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
        
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
        param(
            [Parameter(Mandatory)]$volume,
            [switch]$SuppressLog
        )
        # Log only if not suppressed and not already logged for this drive
        if (-not $SuppressLog -and -not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
            Write-Log "INFO" "Scanning for valid RecoveryPassword protectors..."
        }
        if (-not $volume.KeyProtector) {
            if (-not $SuppressLog) {
                Write-Log "WARNING" "No KeyProtector array found"
            }
            return @()
        }
        $candidates = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -ieq 'RecoveryPassword' }
        if (-not $candidates) {
            if (-not $SuppressLog) {
                Write-Log "INFO" "No RecoveryPassword entries found"
            }
            return @()
        }
        $valid = @()
        foreach ($keypair in $candidates) {
            if ($keypair.KeyProtectorId -match '^\{[0-9a-f\-]+\}$') {
                $valid += $keypair
            }
            else {
                if (-not $SuppressLog) {
                    Write-Log "WARNING" "Ignoring invalid protector ID: $($keypair.KeyProtectorId)"
                }
            }
        }
        if ($valid.Count -gt 0 -and -not $SuppressLog -and -not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
            Write-Log "INFO" "Found $($valid.Count) valid recovery key protector(s)"
        }
        return $valid
    }
    
    # Helper function: Ensure a recovery key exists (only 1)
    function Ensure-RecoveryKey {
        param(
            [Parameter(Mandatory)]$volume
        )
        Write-Log "INFO" "Ensuring single numeric recovery protector"
        try {
            $maxAttempts = 3
            $attempt = 0
            $existingProtectors = $null
            
            # Check for existing protectors only once at the start
            $existingProtectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
            
            # Handle multiple protectors
            while ($attempt -lt $maxAttempts -and $existingProtectors.Count -gt 1) {
                $latestProtector = $existingProtectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                foreach ($protector in $existingProtectors | Where-Object { $_.KeyProtectorId -ne $latestProtector.KeyProtectorId }) {
                    Remove-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    Write-Log "INFO" "Removed duplicate protector $($protector.KeyProtectorId)"
                }
                # Refresh volume state
                $volume = Get-BitLockerVolume -MountPoint $volume.MountPoint
                $existingProtectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
                $attempt++
            }
            
            if ($existingProtectors.Count -gt 1) {
                Write-Log "ERROR" "Failed to reduce recovery protectors to one after $($maxAttempts) attempts"
                return
            }
            
            # If one protector exists, confirm it and exit
            if ($existingProtectors.Count -eq 1) {
                if (-not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
                    Write-Log "INFO" "Confirmed 1 valid recovery key protector"
                    $script:LoggedRecoveryFound[$volume.MountPoint] = $true
                }
                return
            }
            
            # Add a new recovery protector if none exist
            $result = Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue
            $script:NumericProtectorCreated = $true
            Write-Log "SUCCESS" "Numeric recovery protector added"
        }
        catch {
            Write-Log "ERROR" "Failed to ensure recovery key: $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Helper function: If there is an existing recovery password; bool
    function Test-RecoveryPasswordPresent {
        param(
            [Parameter(Mandatory)]$volume,
            [switch]$SuppressLog
        )
        $valid = Get-ValidRecoveryProtectors -volume $volume -SuppressLog:$SuppressLog
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
        param(
            [Parameter(Mandatory)]$volume
        )
        Write-Log "INFO" "Rotating numeric recovery protector"
        # Sublogic: Remove existing numeric protectors
        Write-Log "INFO" "Removing existing numeric protectors before rotation..."
        # Unsupressed
        $existing = Get-ValidRecoveryProtectors -volume $volume
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
                    Write-Log "ERROR" "Failed to remove old protector $($keypair.KeyProtectorId): $($_.Exception.Message)"
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
            Write-Log "ERROR" "Failed to add new protector: $($_.Exception.Message)"
        }
    }
    
    # Helper function: Remove recovery key
    function Remove-RecoveryKey {
        param(
            [Parameter(Mandatory)]$volume
        )
        Write-Log "INFO" "Removing numeric recovery protector(s)"
        # Unsupressed
        $existing = Get-ValidRecoveryProtectors -volume $volume
        
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
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $($_.Exception.Message)"
            }
        }
        
        # Sublogic: Verify all protectors were removed
        # Unsupressed
        $remaining = Get-ValidRecoveryProtectors -volume $volume
        if ($remaining.Count -eq 0) {
            Write-Log "SUCCESS" "All valid numeric protectors removed"
        }
        else {
            Write-Log "WARNING" "Some protectors may not have been removed"
        }
    }
    
    # Helper function: Remove all existing protectors
    function Remove-AllProtectors {
        param(
            [Parameter(Mandatory)]$volume
        )
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
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $($_.Exception.Message)"
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
        $recoveryPresent = Test-RecoveryPasswordPresent -volume $volume -SuppressLog:$SuppressLog
        switch ($Action) {
            'Ensure' {
                if ($script:NumericProtectorCreated) {
                    if (-not $SuppressLog) { Write-Log "INFO" "Protector was just created; skipping Ensure" }
                }
                else {
                    # Ensure only one RecoveryPassword protector by removing extras before adding
                    $existingProtectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog:$SuppressLog
                    if ($existingProtectors.Count -gt 1) {
                        $latestProtector = $existingProtectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                        foreach ($protector in $existingProtectors | Where-Object { $_.KeyProtectorId -ne $latestProtector.KeyProtectorId }) {
                            Remove-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                            if (-not $SuppressLog) { Write-Log "INFO" "Removed duplicate protector $($protector.KeyProtectorId) to ensure single protector" }
                        }
                    }
                    elseif ($existingProtectors.Count -eq 1) {
                        if (-not $SuppressLog) { Write-Log "WARNING" "Valid recovery key already present; skipping Ensure" }
                        return
                    }
                    Ensure-RecoveryKey -volume $volume
                }
            }
            'Rotate' {
                if ($volume.VolumeStatus -ne 'FullyDecrypted') {
                    Rotate-RecoveryKey -volume $volume
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
                    if (-not $SuppressLog) {
                        Write-Log "WARNING" "Cannot remove recovery key when BitLocker is enabled or suspended; skipping"
                    }
                }
                elseif (-not $recoveryPresent) {
                    if (-not $SuppressLog) {
                        Write-Log "WARNING" "No valid recovery key to Remove; skipping"
                    }
                }
                else {
                    Remove-RecoveryKey -volume $volume
                }
            }
        }
    }
    
    # Helper Function: Check if a hardware test is pending using manage-bde
    function Test-HardwareTestPending {
        param (
            [Parameter(Mandatory)][string]$MountPoint
        )
        try {
            # Run manage-bde -status and capture output
            $statusOutput = & manage-bde -status $MountPoint 2>&1
            # Check for the specific instruction indicating a hardware test is required
            if ($statusOutput -match "Restart the computer to run a hardware test") {
                Write-Log "WARNING" "Hardware test required for $($MountPoint) before BitLocker can proceed."
                return $true
            }
            return $false
        }
        catch {
            Write-Log "ERROR" "Failed to check hardware test status for $(MountPoint): $($_.Exception.Message)"
            return $false
        }
    }
    
    # Helper function: Check TPM pending status
    function Test-TpmPending {
        param(
            [Parameter(Mandatory)]$volume
        )
        # Sublogic: Determine if a TPM protector is pending based on protection status and presence
        $isOff = ($volume.ProtectionStatus -eq 0)
        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
        if ($isOff -and $hasTpm -and (Test-IsKeyBackupRequired -volume $volume)) {
            return $false
        }
        return ($isOff -and $hasTpm)
    }
    
    # Helper function: Validate TPM exists
    function Ensure-TpmProtector {
        param(
            [Parameter(Mandatory)]$volume
        )
        # Check if the volume is the OS Volume
        if ($volume.MountPoint -ne $OsVolume) {
            Write-Log "INFO" "TPM protectors can only be used on the OS Volume. Skipping"
            return
        }
        Write-Log "INFO" "Ensuring TPM protector exists"
        # Sublogic: Verify TPM availability
        try {
            $tpm = Get-Tpm
            if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
                Write-Log "WARNING" "TPM is not available or not ready; skipping TPM protector addition"
                return
            }
        }
        catch {
            Write-Log "WARNING" "Failed to check TPM status: $($_.Exception.Message); skipping TPM protector addition"
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
            Write-Log "ERROR" "Failed to add TPM protector: $($_.Exception.Message)"
        }
    }
    
    # Helper function: Check if TPM is pending a restart or encryption already in progress
    function Check-RestartRequirement {
        param(
            [Parameter(Mandatory)]$volume
        )
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
        param(
            [Parameter(Mandatory)]$volume
        )
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
            Write-Log "WARNING" "Unable to check TPM status: $($_.Exception.Message)"
        }
        
        # Sublogic: Check for Group Policy settings that may enforce TPM
        $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        if (Test-Path $gpoPath) {
            $useTpm = Get-ItemProperty -Path $gpoPath -Name "UseTPM" -ErrorAction SilentlyContinue
            if ($useTpm -and $useTpm.UseTPM -eq 1 -and !$UseTpmProtector) {
                Write-Log "WARNING" "Group Policy requires TPM protector, but UseTpmProtector is False. This may cause a recovery key prompt."
            }
        }
        
        # Sublogic: Check protector configuration
        $protectors = $volume.KeyProtector
        if ($protectors.Count -eq 0) {
            Write-Log "INFO" "No protectors configured for volume. BitLocker will not function until protectors are added."
        }
    }
    
    # Helper function: Collect recovery key for later storage
    function Collect-RecoveryKey {
        param(
            [Parameter(Mandatory)]$volume
        )
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
            # Refresh volume object each attempt
            $refreshed = Get-VolumeObject -TargetMountPoint $volume.MountPoint -SuppressLog
            if ($refreshed) {
                $volume = $refreshed
            }
            $protectors = Get-ValidRecoveryProtectors -volume $volume
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
            # Validate that RecoveryPassword is actually populated (not just the protector ID)
            if ([string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                Write-Log "WARNING" "Protector $($latestProtector.KeyProtectorId) found but RecoveryPassword is empty for $($volume.MountPoint); retrying volume refresh"
                # RecoveryPassword can be blank if queried too soon after rotation. Retry if this is the case.
                $rpRetry = 0
                while ($rpRetry -lt 3 -and [string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                    Start-Sleep -Seconds 2
                    $rpRetry++
                    $refreshed = Get-VolumeObject -TargetMountPoint $volume.MountPoint -SuppressLog
                    if ($refreshed) { $volume = $refreshed }
                    $latestProtector = Get-ValidRecoveryProtectors -volume $volume | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                }
            }
            if ([string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                Write-Log "ERROR" "RecoveryPassword is empty for protector $($latestProtector.KeyProtectorId) on $($volume.MountPoint) after retries. Cannot store recovery key."
                $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - ERROR: Key not retrievable"
            }
            else {
                # Format the key information in a single-line string
                $keyInfo = "$($volume.MountPoint) - Protector ID: $($latestProtector.KeyProtectorId) | Recovery Key: $($latestProtector.RecoveryPassword)"
                Write-Log "INFO" "Collected recovery key"
                # Overwrite the recovery keys collection (no appending)
                $script:RecoveryKeys[$volume.MountPoint] = $keyInfo
                # Clear sensitive param per call
                Clear-Memory -VariableNames "keyInfo"
            }
        }
        else {
            Write-Log "WARNING" "No recovery key protectors found after $maxRetries retries for $($volume.MountPoint); recording 'None'"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - None"
        }
    }
    
    # Helper function: Save key to AD & AAD if applicable
    function Backup-KeyToAD {
        param(
            [Parameter(Mandatory)]$volume
        )
        
        # Call with no Get-ValidRecoveryProtectors logging
        $protectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
        
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
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AAD: $($_.Exception.Message)"
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
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AD: $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Log "WARNING" "Device is not joined to AD or AAD; skipping backup"
        }
    }
    
    # Helper function: Verify recovery key was successfully written to the NinjaRMM agent cache.
    #
    # How NinjaRMM custom field caching works:
    #   - Ninja-Property-Set writes to the LOCAL AGENT CACHE only.
    #   - Ninja-Property-Get reads from the LOCAL AGENT CACHE (if a cached value exists).
    #   - The agent checks in to the NinjaRMM console approximately every 60 seconds,
    #     flushing any cached custom field changes to the server at that time.
    #   - If the machine reboots/loses power before the next check-in, cached data is lost.
    #
    # What this verification DOES confirm:
    #   - The field accepts writes (permissions are correct)
    #   - The data was not truncated (field character limit is sufficient)
    #   - The cached value matches what was written (no silent corruption)
    #
    # What this verification CANNOT confirm:
    #   - That the data has been flushed to the NinjaRMM console (server-side persistence)
    #   - There is no agent-side API to confirm a successful console sync
    #
    # The pre-flight caller handles the console sync timing separately (see process block).
    function Test-RecoveryKeyStorageVerification {
        param(
            [Parameter(Mandatory)][string]$FieldName,
            [Parameter(Mandatory)][string]$ExpectedValue
        )
        try {
            $readBack = Ninja-Property-Get $FieldName
            if ($null -eq $readBack) {
                Write-Log "ERROR" "Recovery key verification: Ninja-Property-Get returned null for '$FieldName'. Ensure the secure custom field has 'Read/Write' (Automation) permission enabled."
                return $false
            }
            if ($readBack.Trim() -ne $ExpectedValue.Trim()) {
                Write-Log "ERROR" "Recovery key verification FAILED. Written length: $($ExpectedValue.Length), Read back length: $($readBack.Length). The field may have a character limit (default: 200) that truncated the data."
                return $false
            }
            Write-Log "SUCCESS" "Recovery key cached to agent successfully (field: '$FieldName', $($ExpectedValue.Length) chars)"
            return $true
        }
        catch {
            Write-Log "ERROR" "Recovery key verification failed: Ninja-Property-Get unavailable or errored: $($_.Exception.Message). Ensure the secure field has 'Read/Write' (Automation) permission enabled."
            return $false
        }
    }
    
    # Helper function: Enable auto-unlock with 3 retries.
    # Uses Enable-BitLockerAutoUnlock to enable auto-unlock for a non-OS volume.
    # Each attempt starts with a clean slate, disables any existing auto-unlock and removes
    # orphaned ExternalKey protectors so only one (the auto-unlock key) exists.
    # If the cmdlet fails after all retries, BitLocker is disabled on the volume to prevent
    # an inaccessible drive after reboot.
    function Enable-VerifiedAutoUnlock {
        param(
            [Parameter(Mandatory)][string]$TargetMountPoint,
            [int]$MaxRetries = 3,
            [int]$RetryDelaySeconds = 5
        )
        $attempt = 0
        $autoUnlockEnabled = $false
        
        while ($attempt -lt $MaxRetries -and -not $autoUnlockEnabled) {
            $attempt++
            Write-Log "INFO" "Auto-unlock attempt $attempt of $MaxRetries for $TargetMountPoint"
            
            # Clean slate: disable any existing auto-unlock and remove orphaned ExternalKey protectors
            try {
                & manage-bde -autounlock -disable $TargetMountPoint 2>&1 | Out-Null
            }
            catch { }
            try {
                $vol = Get-BitLockerVolume -MountPoint $TargetMountPoint -ErrorAction Stop
                $existingKeys = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'ExternalKey' }
                foreach ($key in $existingKeys) {
                    Write-Log "INFO" "Removing ExternalKey protector $($key.KeyProtectorId) from $TargetMountPoint"
                    Remove-BitLockerKeyProtector -MountPoint $TargetMountPoint -KeyProtectorId $key.KeyProtectorId -ErrorAction SilentlyContinue | Out-Null
                }
            }
            catch {
                Write-Log "WARNING" "Failed to clean up ExternalKey protectors: $($_.Exception.Message)"
            }
            
            # Enable auto-unlock
            try {
                Enable-BitLockerAutoUnlock -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                Write-Log "INFO" "Enable-BitLockerAutoUnlock succeeded for $TargetMountPoint"
                $autoUnlockEnabled = $true
            }
            catch {
                Write-Log "WARNING" "Enable-BitLockerAutoUnlock failed on attempt $attempt : $($_.Exception.Message)"
                if ($attempt -lt $MaxRetries) {
                    Write-Log "INFO" "Waiting $RetryDelaySeconds seconds before retry..."
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
                continue
            }
        }
        
        if ($autoUnlockEnabled) {
            Start-Sleep -Seconds 2
            
            # Log manage-bde status for diagnostics
            try {
                $statusOutput = & manage-bde -status $TargetMountPoint 2>&1
                $statusString = $statusOutput | Out-String
                $autoUnlockLine = ($statusString -split "`n" | Where-Object { $_ -match 'Automatic Unlock' }) -join ''
                if ($autoUnlockLine) {
                    Write-Log "INFO" "manage-bde reports: '$($autoUnlockLine.Trim())'"
                }
            }
            catch { }
            
            # Verify only one ExternalKey protector exists (the auto-unlock key)
            try {
                $vol = Get-BitLockerVolume -MountPoint $TargetMountPoint -ErrorAction Stop
                $externalKeys = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'ExternalKey' }
                if ($externalKeys.Count -gt 1) {
                    Write-Log "WARNING" "Multiple ExternalKey protectors found ($($externalKeys.Count)) on $TargetMountPoint - expected 1. Cleaning up extras."
                    $toRemove = $externalKeys | Select-Object -SkipLast 1
                    foreach ($extra in $toRemove) {
                        Write-Log "INFO" "Removing extra ExternalKey protector $($extra.KeyProtectorId) from $TargetMountPoint"
                        Remove-BitLockerKeyProtector -MountPoint $TargetMountPoint -KeyProtectorId $extra.KeyProtectorId -ErrorAction SilentlyContinue | Out-Null
                    }
                }
            }
            catch { }
            
            return $true
        }
        
        # All retries exhausted, cmdlet never succeeded
        Write-Log "ERROR" "Auto-unlock FAILED for $TargetMountPoint after $MaxRetries attempts. Disabling BitLocker on this volume to prevent inaccessible drive after reboot."
        try {
            Disable-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
            Write-Log "WARNING" "BitLocker disabled on $TargetMountPoint due to auto-unlock failure. Drive will remain accessible but unencrypted."
        }
        catch {
            Write-Log "ERROR" "Failed to disable BitLocker on $TargetMountPoint after auto-unlock failure: $($_.Exception.Message). MANUAL INTERVENTION REQUIRED."
        }
        return $false
    }
    
    # Helper function: Check if auto-unlock is configured (will survive reboot)
    # For internal (fixed) drives, use Get-BitLockerVolume to check the AutoUnlockEnabled property
    # This directly queries the BitLocker status for the volume
    function Test-AutoUnlockStatus {
        param(
            [Parameter(Mandatory)]$TargetMountPoint
        )
        try {
            $TargetMountPoint = [string]$TargetMountPoint
            $volume = Get-BitLockerVolume -MountPoint $TargetMountPoint -ErrorAction Stop
            return $volume.AutoUnlockEnabled
        }
        catch {
            return $false
        }
    }
    
    # Helper function: Retrieve the remaining reboot count for a suspended BitLocker volume
    function Get-RebootCount {
        param (
            [Parameter(Mandatory)][string]$MountPoint
        )
        # Lock to OS volume only by design
        if ($MountPoint -ne $script:OsVolume) {
            return $null
        }
        try {
            $driveLetter = $MountPoint
            $volume = Get-CimInstance `
                -Namespace 'ROOT/CIMV2/Security/MicrosoftVolumeEncryption' `
                -Class Win32_EncryptableVolume `
                -Filter "DriveLetter='$driveLetter'" `
                -ErrorAction Stop
            
            if (-not $volume) {
                Write-Log "WARNING" "No encryptable volume found for drive letter $driveLetter"
                return $null
            }
            
            $result = $volume | Invoke-CimMethod -MethodName GetSuspendCount -ErrorAction Stop
            
            # Stored return values
            $returnValue    = $result.ReturnValue
            $suspendedCount = $result.SuspendCount
            
            switch ($returnValue) {
                0 {
                    if ($suspendedCount -gt 0) {
                        # real suspend with N reboots left
                        Write-Log "INFO" "Drive $($MountPoint) Reboot Count: $($suspendedCount)"
                        return $($suspendedCount)
                    }
                    else {
                        # suspendedCount == 0 -> indefinitely suspended
                        Write-Log "INFO" "Drive $($MountPoint) is indefinitely suspended (SuspendCount=0)."
                        return 0
                    }
                }
                2147942450 {
                    # enabled and not suspended
                    Write-Log "INFO" "Drive $($MountPoint) is not suspended"
                    return 0
                }
                default {
                    Write-Log "ERROR" "GetSuspendCount returned: $($returnValue) for $($MountPoint)"
                    return 0
                }
            }
        }
        catch {
            Write-Log "ERROR" "Failed retrieving state/count for $($MountPoint): $($_.Exception.Message)"
            return $null
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
    
    # Exit code tracking
    $script:ScriptSuccess = $true
    $script:CriticalFailure = $false
    $script:Warnings = [System.Collections.Generic.List[string]]::new()
    $script:Errors = [System.Collections.Generic.List[string]]::new()
    $script:AutoUnlockFailures = [System.Collections.Generic.List[string]]::new()
    
    # Pre-flight: Verify NinjaRMM secure field is writable, readable, AND large enough for all drives.
    # A single drive entry is ~120 characters:
    #   "C: - Protector ID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} | Recovery Key: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
    # Multiple drives are joined with " | ", so 2 drives ~= 245 chars, 3 drives ~= 370 chars.
    # The default NinjaRMM secure field size is 200 characters, which overflows on 2+ drives.
    # This pre-flight generates a test payload assuming full recovery key data for every drive
    # (worst-case capacity) to catch truncation early, regardless of current volume state.
    #
    # After the cache write is verified, the script waits 60 seconds for the NinjaRMM agent to check in
    # and flush the cached data to the console. This cannot be confirmed from the agent, but provides a
    # best-effort window so that if someone is watching the NinjaRMM console live, they can visually
    # confirm the test data arrived before proceeding.
    if ($VerifyRecoveryKeyStorage) {
        Write-Log "INFO" "Pre-flight: Testing NinjaRMM secure field accessibility and capacity for '$RecoveryKeySecureFieldName'"
        # Build a realistic-sized test payload matching actual recovery key format for all fixed drives
        # Assumes full data for every drive (no N/A shortcuts) to test worst-case capacity
        $preflightDriveCount = @($allFixedDrives).Count
        if ($preflightDriveCount -eq 0) { $preflightDriveCount = 1 }
        [System.Collections.Generic.List[string]]$preflightEntries = @()
        foreach ($pfDrive in $allFixedDrives) {
            # Simulate: "C: - Protector ID: {GUID} | Recovery Key: 000000-000000-000000-000000-000000-000000-000000-000000"
            $preflightEntries.Add("$pfDrive - Protector ID: {00000000-0000-0000-0000-000000000000} | Recovery Key: 000000-000000-000000-000000-000000-000000-000000-000000")
        }
        $preflightTestValue = ($preflightEntries -join " | ")
        Write-Log "INFO" "Pre-flight: Test payload is $($preflightTestValue.Length) characters for $preflightDriveCount drive(s)"

        $preflightWriteSuccess = $false
        try {
            try {
                Ninja-Property-Set -Name $RecoveryKeySecureFieldName -Value $preflightTestValue | Out-Null
                $preflightWriteSuccess = $true
            }
            catch {
                Ninja-Property-Set $RecoveryKeySecureFieldName $preflightTestValue | Out-Null
                $preflightWriteSuccess = $true
            }
        }
        catch {
            Write-Log "ERROR" "Pre-flight FAILED: Cannot write to NinjaRMM secure field '$RecoveryKeySecureFieldName': $($_.Exception.Message)"
            Write-Log "ERROR" "Aborting. Resolve NinjaRMM field configuration and retry."
            exit 1
        }
        if ($preflightWriteSuccess) {
            $preflightVerified = Test-RecoveryKeyStorageVerification -FieldName $RecoveryKeySecureFieldName -ExpectedValue $preflightTestValue
            if (-not $preflightVerified) {
                Write-Log "ERROR" "Pre-flight FAILED: Secure field cannot hold recovery keys for $preflightDriveCount drive(s) ($($preflightTestValue.Length) characters). The field likely has a character limit (default: 200) that is too small."
                Write-Log "ERROR" "Increase the secure field character limit in NinjaRMM and ensure 'Read/Write' (Automation) is enabled. Aborting."
                exit 1
            }
            Write-Log "SUCCESS" "Pre-flight: Agent cache verified - field is writable, readable, and has sufficient capacity ($($preflightTestValue.Length) chars for $preflightDriveCount drive(s))"
            # Wait 60 seconds for the NinjaRMM agent to check in and post the test data to the console.
            # The agent syncs cached custom field data to the NinjaRMM console approximately every 60 seconds.
            # This wait provides a best-effort attempt for the data to reach the console, and allows anyone
            # watching the console to visually confirm the test payload arrived before proceeding.
            Write-Log "INFO" "Waiting 60 seconds for NinjaRMM agent to sync cached data to the console before proceeding..."
            Start-Sleep -Seconds 60
            Write-Log "INFO" "Console sync window complete. Test data should now be visible in the NinjaRMM console. Proceeding with drive processing."
        }
    }
    elseif (-not $VerifyRecoveryKeyStorage) {
        Write-Log "WARNING" "Recovery key storage verification is DISABLED. Keys will be written but NOT verified. Enable VerifyRecoveryKeyStorage for safety."
    }
    
    Write-Host "`n=== Drive Processing ==="
    # Process each drive
    foreach ($CurrentMountPoint in $drives) {
        
        # IMPORTANT:
        # Do NOT assign into $MountPoint here. $MountPoint is a [string[]] script parameter.
        # Use a per-iteration variable that is always a scalar string.
        $TargetMountPoint = [string]$CurrentMountPoint
        
        Write-Log "INFO" "Processing drive $TargetMountPoint"
        
        # Update the volume state
        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
        if (-not $blv) { continue }
        
        $script:initialProtectionStatus = $blv.ProtectionStatus
        
        # Reset per-drive state
        $script:PreviousRecoveryKey = $null
        $script:NumericProtectorCreated = $false
        
        # Validate BitLocker and TPM state
        Validate-BitLockerState -volume $blv
        
        # Evaluate TPM status and restart requirements
        $isTpmPending = $false
        if ($blv.ProtectionStatus -eq 'Off') {
            $isTpmPending = Test-TpmPending -volume $blv
            if ($isTpmPending) {
                $restartMessage = Check-RestartRequirement -volume $blv
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
            Write-Log "ERROR" "TPM is not available and PreventKeyPromptOnEveryBoot is true for $($TargetMountPoint). Skipping."
            continue
        }
        elseif (-not $tpmAvailable) {
            Write-Log "WARNING" "TPM is not available for $TargetMountPoint, but PreventKeyPromptOnEveryBoot is false. Continuing without TPM."
        }
        
        # Manage BitLocker protection
        switch ($BitLockerProtection) {
            'Enable' {
                Write-Log "INFO" "Requested: Enable/Resume protection for $TargetMountPoint"
                if ($blv.ProtectionStatus -eq 'Suspended') {
                    Write-Log "INFO" "BitLocker is suspended; resuming protection"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -volume $blv
                        Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction
                        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                        if (-not $blv) {
                            continue
                        }
                    }
                    try {
                        Resume-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                        Write-Log "SUCCESS" "Protection resumed"
                        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                        if (-not $blv) {
                            continue
                        }
                        # Set state
                        $finalEnableState = "resumed"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to resume protection: $($_.Exception.Message)"
                        continue
                    }
                }
                elseif ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                    Write-Log "INFO" "Volume is FullyEncrypted but Protection is Off; adding protectors and resuming"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -volume $blv
                        try {
                            Resume-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed before recovery action"
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                            $script:PreviousRecoveryKey = (Get-ValidRecoveryProtectors -volume $blv | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1)
                            Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction -SuppressLog
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                            # Set state
                            $finalEnableState = "resumed"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $($_.Exception.Message)"
                            continue
                        }
                    }
                    else {
                        if ($UseTpmProtector) { Ensure-TpmProtector -volume $blv }
                        try {
                            Resume-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed"
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                            Invoke-RecoveryAction -volume $blv -Action 'Ensure'
                            # Set state
                            $finalEnableState = "resumed"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $($_.Exception.Message)"
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
                    elseif ($blv.VolumeStatus -eq 'EncryptionInProgress') {
                        Write-Log "INFO" "Volume is already encrypting; ensuring protectors are correct"
                        if ($PreventKeyPromptOnEveryBoot) {
                            Ensure-TpmProtector -volume $blv
                            Invoke-RecoveryAction -volume $blv -Action 'Ensure' -SuppressLog
                        }
                        else {
                            Invoke-RecoveryAction -volume $blv -Action 'Ensure'
                            if ($UseTpmProtector) { Ensure-TpmProtector -volume $blv }
                        }
                        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                        if (-not $blv) {
                            continue
                        }
                        $finalEnableState = "reconciled"
                    }
                    elseif ($blv.VolumeStatus -eq 'FullyDecrypted') {
                        Write-Log "INFO" "Volume is fully decrypted; removing all protectors and enabling BitLocker"
                        Remove-AllProtectors -volume $blv
                        if ($UseUsedSpaceOnly) {
                            Write-Log "INFO" "Enabling BitLocker with -UsedSpaceOnly"
                        }
                        else {
                            Write-Log "INFO" "Enabling BitLocker without -UsedSpaceOnly (full disk encryption)"
                        }
                        try {
                            Enable-BitLocker `
                                -MountPoint $TargetMountPoint `
                                -EncryptionMethod $BitlockerEncryptionMethod `
                                -RecoveryPasswordProtector `
                                -SkipHardwareTest `
                                -ErrorAction Stop `
                                -WarningAction SilentlyContinue `
                                -InformationAction SilentlyContinue `
                                -UsedSpaceOnly:$UseUsedSpaceOnly | Out-Null
                            Write-Log "SUCCESS" "BitLocker enabled with recovery key protector"
                            
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                            # Ensure only one recovery key after enablement
                            Invoke-RecoveryAction -volume $blv -Action 'Ensure' -SuppressLog
                            # Set state
                            $usedSpaceOnlyValue = if ($UseUsedSpaceOnly) { 'Yes' } else { 'No' }
                            RegistryShouldBe -KeyPath $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $TargetMountPoint" -Value $usedSpaceOnlyValue -Type 'String'
                            Write-Log "INFO" "Stored UsedSpaceOnly setting in registry: $usedSpaceOnlyValue"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to enable BitLocker: $($_.Exception.Message)"
                            continue
                        }
                        if ($UseTpmProtector) {
                            Write-Log "INFO" "Adding TPM protector post-enablement"
                            Ensure-TpmProtector -volume $blv
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                            # Ensure only one recovery key after adding TPM
                            Invoke-RecoveryAction -volume $blv -Action 'Ensure' -SuppressLog
                        }
                        $finalEnableState = "enabled"
                        
                        # Hardware test is an OS-volume concern in this script design
                        if ($TargetMountPoint -eq $script:OsVolume) {
                            if (Test-HardwareTestPending -MountPoint $TargetMountPoint) {
                                Write-Log "WARNING" "BitLocker setup requires a hardware test. Disabling to prevent lockout."
                                try {
                                    Disable-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                                    $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint -SuppressLog
                                    if ($blv) { Remove-AllProtectors -volume $blv }
                                    Write-Log "INFO" "BitLocker disabled due to hardware test requirement."
                                }
                                catch {
                                    Write-Log "ERROR" "Failed to disable BitLocker: $($_.Exception.Message)"
                                }
                                $finalEnableState = "disabled"
                                continue
                            }
                        }
                        else {
                            Write-Log "INFO" "Skipping hardware test check for data volume $TargetMountPoint (OS-volume only)."
                        }
                    }
                }
                else {
                    Write-Log "INFO" "Protection already active; reconciling protectors"
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -volume $blv
                        Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction -SuppressLog
                    }
                    else {
                        Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction
                        if ($UseTpmProtector) { Ensure-TpmProtector -volume $blv }
                    }
                    $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                    if (-not $blv) {
                        continue
                    }
                    if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                        try {
                            Resume-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Protection resumed"
                            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                            if (-not $blv) {
                                continue
                            }
                        }
                        catch {
                            Write-Log "ERROR" "Failed to resume protection: $($_.Exception.Message)"
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
            'Maintain' {
                Write-Log "INFO" "Requested: Maintain (no state changes) for $TargetMountPoint"
                if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
                    Write-Log "INFO" "Volume is fully decrypted; nothing to maintain. Skipping protector reconciliation."
                }
                else {
                    # Reconcile protectors without changing encryption/protection state
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -volume $blv
                        Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction -SuppressLog
                    }
                    else {
                        Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction
                        if ($UseTpmProtector) { Ensure-TpmProtector -volume $blv }
                    }
                    # Auto-unlock check for non-OS volumes (equivalent to TPM check for OS volume)
                    if ($TargetMountPoint -ne $OsVolume -and $AutoUnlockNonOSVolumes) {
                        if (Test-AutoUnlockStatus -TargetMountPoint $TargetMountPoint) {
                            Write-Log "SUCCESS" "Auto-unlock already enabled for $TargetMountPoint"
                        }
                        else {
                            Write-Log "INFO" "Auto-unlock not enabled for $TargetMountPoint; enabling"
                            $autoUnlockResult = Enable-VerifiedAutoUnlock -TargetMountPoint $TargetMountPoint
                            if (-not $autoUnlockResult) {
                                $script:AutoUnlockFailures.Add($TargetMountPoint)
                            }
                        }
                    }
                    $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                    if (-not $blv) {
                        continue
                    }
                    Write-Log "INFO" "Protectors reconciled; protection status unchanged: $($blv.ProtectionStatus)"
                }
            }
            'Suspend' {
                Write-Log "INFO" "Requested: Suspend protection for $TargetMountPoint"
                if ($blv.VolumeStatus -eq 'EncryptionInProgress') {
                    Write-Log "WARNING" "Cannot suspend - BitLocker is currently encrypting the volume."
                }
                elseif ($blv.ProtectionStatus -eq 'Suspended') {
                    Write-Log "WARNING" "Already suspended; skipping"
                }
                else {
                    if ($PreventKeyPromptOnEveryBoot) {
                        Ensure-TpmProtector -volume $blv
                        Ensure-RecoveryKey -volume $blv
                    }
                    else {
                        if ($UseTpmProtector) { Ensure-TpmProtector -volume $blv }
                        Ensure-RecoveryKey -volume $blv
                    }
                    $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                    if (-not $blv) {
                        continue
                    }
                    try {
                        Suspend-BitLocker -MountPoint $TargetMountPoint -RebootCount $SuspensionRebootCount -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                        
                        # Set state
                        $suspensionCountValue = $SuspensionRebootCount
                        # Store initial reboot count in registry key for each drive state
                        RegistryShouldBe -KeyPath $BitLockerStateStoragePath -Name "$InitialSuspensionCountValueName $TargetMountPoint" -Value $suspensionCountValue -Type 'String'
                        # Write-Log "INFO" "Stored initial suspensionCountValue setting in registry: $suspensionCountValue"
                        
                        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                        if (-not $blv) {
                            continue
                        }
                    }
                    catch {
                        Write-Log "ERROR" "Failed to suspend protection: $($_.Exception.Message)"
                        continue
                    }
                }
            }
            'Disable' {
                Write-Log "INFO" "Requested: Disable protection for $TargetMountPoint"
                if ($TargetMountPoint -eq $OsVolume) {
                    # Disable auto-unlock on all data drives with auto-unlock enabled
                    $dataDrivesWithAutoUnlock = Get-BitLockerVolume | Where-Object { $_.MountPoint -ne $OsVolume -and $_.AutoUnlockEnabled }
                    foreach ($dataDrive in $dataDrivesWithAutoUnlock) {
                        Write-Log "INFO" "Disabling auto-unlock on $($dataDrive.MountPoint)"
                        try {
                            Disable-BitLockerAutoUnlock -MountPoint $dataDrive.MountPoint -ErrorAction Stop | Out-Null
                            Write-Log "SUCCESS" "Auto-unlock disabled on $($dataDrive.MountPoint)"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to disable auto-unlock on $($dataDrive.MountPoint): $($_.Exception.Message)"
                        }
                    }
                }
                if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
                    Write-Log "WARNING" "Already disabled; skipping"
                }
                else {
                    try {
                        Disable-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                        Write-Log "SUCCESS" "Decryption initiated"
                        $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
                        if (-not $blv) {
                            continue
                        }
                    }
                    catch {
                        Write-Log "ERROR" "Failed to disable protection: $($_.Exception.Message)"
                        continue
                    }
                }
                RegistryShouldBe -KeyPath $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $TargetMountPoint" -Value "N/A" -Type 'String'
                Write-Log "INFO" "Set UsedSpaceOnly registry to 'N/A'"
                RegistryShouldBe -KeyPath $BitLockerStateStoragePath -Name "$InitialSuspensionCountValueName $TargetMountPoint" -Value "N/A" -Type 'String'
                Write-Log "INFO" "Set InitialSuspensionCount registry to 'N/A'"
            }
        }
        
        # Manage auto-unlock for non-OS volumes if applicable
        if ($BitLockerProtection -eq 'Enable') {
            if ($TargetMountPoint -ne $OsVolume) {
                $osVolume = Get-BitLockerVolume -MountPoint $OsVolume -ErrorAction SilentlyContinue
                if ($AutoUnlockNonOSVolumes) {
                    # Pre-check: Verify the OS volume has BitLocker enabled before attempting auto-unlock
                    # Auto-unlock requires the OS volume to be encrypted; if BitLocker is off on the OS drive
                    # (e.g., no TPM, not targeted), auto-unlock cannot work and the data drive will be inaccessible.
                    $osVolumeEligible = $false
                    if (-not $osVolume) {
                        Write-Log "ERROR" "Cannot enable auto-unlock for $($TargetMountPoint): OS Volume $OsVolume not found or inaccessible."
                    }
                    elseif ($osVolume.ProtectionStatus -eq 'Off' -and $osVolume.VolumeStatus -eq 'FullyDecrypted') {
                        Write-Log "ERROR" "Cannot enable auto-unlock for $($TargetMountPoint): OS Volume $OsVolume does not have BitLocker enabled. Auto-unlock requires the OS volume to be encrypted. Disabling BitLocker on $TargetMountPoint to prevent inaccessible drive."
                        try {
                            Disable-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                            Write-Log "WARNING" "BitLocker disabled on $TargetMountPoint because auto-unlock is not possible without an encrypted OS volume."
                        }
                        catch {
                            Write-Log "ERROR" "Failed to disable BitLocker on $($TargetMountPoint): $($_.Exception.Message). CHECK ALL VOLUMES FOR ACCESSIBILITY."
                        }
                        $script:AutoUnlockFailures.Add($TargetMountPoint)
                    }
                    else {
                        $osVolumeEligible = $true
                    }
                    
                    if ($osVolumeEligible) {
                        # Periodically check OS Volume encryption status
                        $maxWaitSeconds = 1800  # 30 minutes max wait
                        $waitIntervalSeconds = 30
                        $elapsedSeconds = 0
                        
                        # Loop until system drive is fully encrypted to enable Auto-Unlock for non OS volumes
                        while ($osVolume -and $osVolume.VolumeStatus -ne 'FullyEncrypted' -and $elapsedSeconds -lt $maxWaitSeconds) {
                            Start-Sleep -Seconds $waitIntervalSeconds
                            $elapsedSeconds += $waitIntervalSeconds
                            $osVolume = Get-BitLockerVolume -MountPoint $OsVolume -ErrorAction SilentlyContinue
                        }
                        
                        # When OS Volume is fully encrypted
                        if ($osVolume -and $osVolume.VolumeStatus -eq 'FullyEncrypted') {
                            Write-Log "INFO" "OS Volume $OsVolume is now fully encrypted... (Elapsed: $elapsedSeconds seconds)"
                            # Check if auto-unlock is already enabled before doing the full clean-slate cycle
                            if (Test-AutoUnlockStatus -TargetMountPoint $TargetMountPoint) {
                                Write-Log "INFO" "Auto-unlock already enabled for $TargetMountPoint; skipping"
                            }
                            else {
                                Write-Log "INFO" "Enabling auto-unlock for non-OS volume $TargetMountPoint"
                                $autoUnlockResult = Enable-VerifiedAutoUnlock -TargetMountPoint $TargetMountPoint
                                if (-not $autoUnlockResult) {
                                    $script:AutoUnlockFailures.Add($TargetMountPoint)
                                }
                            }
                        }
                        else {
                            Write-Log "WARNING" "Cannot enable auto-unlock for $TargetMountPoint because OS Volume is not fully encrypted after $maxWaitSeconds seconds."
                            # PreventKeyPromptOnEveryBoot: if the OS volume can't finish encrypting, non-OS volumes with auto-unlock will be inaccessible
                            if ($PreventKeyPromptOnEveryBoot) {
                                Write-Log "ERROR" "PreventKeyPromptOnEveryBoot is active but auto-unlock cannot be configured for $TargetMountPoint. Disabling BitLocker on $TargetMountPoint to prevent inaccessible drive."
                                try {
                                    Disable-BitLocker -MountPoint $TargetMountPoint -ErrorAction Stop | Out-Null
                                    Write-Log "WARNING" "BitLocker disabled on $TargetMountPoint due to auto-unlock timeout with PreventKeyPromptOnEveryBoot."
                                }
                                catch {
                                    Write-Log "ERROR" "Failed to disable BitLocker on $TargetMountPoint after auto-unlock timeout: $($_.Exception.Message). MANUAL INTERVENTION REQUIRED."
                                }
                                $script:AutoUnlockFailures.Add($TargetMountPoint)
                                $script:CriticalFailure = $true
                            }
                        }
                    }
                }
                # Skip requirement
                else {
                    Write-Log "INFO" "Skipping auto-unlock for non-OS volume $TargetMountPoint"
                    try {
                        Write-Log "INFO" "Auto-Unlock was not opted for. Ensure ($TargetMountPoint) is configured properly."
                    }
                    catch {
                        Write-Log "ERROR" "Failed to disable auto-unlock for $($MountTargetMountPointPoint): $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Apply recovery key action if not already handled (Enable and Maintain handle it inline)
        if ($BitLockerProtection -notin @('Enable', 'Maintain')) {
            Invoke-RecoveryAction -volume $blv -Action $RecoveryKeyAction -SuppressLog
            $blv = Get-VolumeObject -TargetMountPoint $TargetMountPoint
            if (-not $blv) {
                continue
            }
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
                            # OS-Volume only check for reboot count
                            $rebootCount = Get-RebootCount -MountPoint ([string]$MountPoint)
                            # Include reboot count if suspended and reboot count is greater than 0
                            if ($null -ne $rebootCount -and $rebootCount -gt 0) {
                                '<i class="fas fa-check-circle" style="color:#F0AD4E;"></i> Suspended<br>     Reboot(s) Left: ' + $rebootCount
                            }
                            elseif ($null -ne $rebootCount -and $rebootCount -eq 0) {
                                '<i class="fas fa-check-circle" style="color:#F0AD4E;"></i> Suspended<br>     Indefinitely'
                            }
                            else {
                                '<i class="fas fa-check-circle" style="color:#F0AD4E;"></i> Suspended<br>     Reboot(s) Left: N/A'
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
            
            # Auto-unlock status (non-OS volumes only, only relevant when encrypted)
            # Uses manage-bde -status as the single source of truth for auto-unlock state
            $autoUnlockDisplay = $null
            if ($MountPoint -ne $script:OsVolume) {
                if ($blv.VolumeStatus -eq 'FullyDecrypted' -and $blv.ProtectionStatus -eq 'Off') {
                    $autoUnlockDisplay = "N/A"
                }
                else {
                    $autoUnlockConfirmed = Test-AutoUnlockStatus -TargetMountPoint $MountPoint
                    if ($autoUnlockConfirmed) {
                        $autoUnlockDisplay = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Enabled'
                    }
                    else {
                        $autoUnlockDisplay = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Not Enabled'
                        Write-Log "WARNING" "Auto-unlock is not enabled for $MountPoint. manage-bde -status does not report 'Automatic Unlock: Enabled'."
                    }
                }
            }
            
            # Combine Card Panel Information
            $cardProperties = [ordered]@{
                'Protection Status' = $protectionStatusHtml
                'Volume Status'     = $volumeStatusHtml
            }
            # Only add auto-unlock row for non-OS volumes
            if ($null -ne $autoUnlockDisplay) {
                $cardProperties['AutoUnlock'] = $autoUnlockDisplay
            }
            $cardProperties['Volume']                  = $MountPoint
            $cardProperties['Encryption Method']       = $encryptionMethod
            $cardProperties['Encrypt Used Space Only'] = $usedSpaceOnlyDisplay
            $cardProperties['Protectors']              = $protectors
            
            $bitlockerInfo = [PSCustomObject]$cardProperties
            
            # Generate card for this drive
            $cardHtml = Get-NinjaOneInfoCard `
                -Title "$CardTitle ($MountPoint)" `
                -Data $bitlockerInfo `
                -Icon $CardIcon `
                -BackgroundGradient $CardBackgroundGradient `
                -BorderRadius $CardBorderRadius `
                -IconColor $CardIconColor `
                -SeparationMargin $CardSeparationMargin
            
            $allCardsHtml += $cardHtml
        }
    }
    
    # Store all cards in the custom field
    try {
        $allCardsHtml | Ninja-Property-Set-Piped -Name $BitLockerStatusFieldName
        Write-Log "SUCCESS" "BitLocker status cards stored in '$BitLockerStatusFieldName'"
    }
    catch {
        Write-Log "ERROR" "Failed to store status cards: $($_.Exception.Message)"
    }
    
    # Collect recovery keys for all fixed drives
    Write-Host "`n=== Recovery Key Backup ==="
    foreach ($drive in $allFixedDrives) {
        $blv = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
        if ($blv) {
            Collect-RecoveryKey -volume $blv
        }
        # Backup to AD if set
        if ($BackupToAD) {
            Write-Log "INFO" "Backing up $drive recovery key to Intune/AD"
            Backup-KeyToAD -volume $blv
        }
    }
    
    # Store all recovery keys in a deterministic, multi-line format (stable ordering: OS first)
    Write-Log "INFO" "Storing recovery key(s) in secure field"
    try {
        if ($script:RecoveryKeys.Count -eq 0) {
            Write-Log "INFO" "No recovery keys collected; setting secure field to N/A"
            Ninja-Property-Set $RecoveryKeySecureFieldName "N/A" | Out-Null
        }
        else {
            # Stable ordering: OS first, then alphabetical
            $orderedMountPoints = @(
                $allFixedDrives | Sort-Object `
                    @{ Expression = { if ($_ -eq $script:OsVolume) { 0 } else { 1 } } }, `
                    @{ Expression = { $_ } }
            )
            
            [System.Collections.Generic.List[string]]$lines = @()
            foreach ($mp in $orderedMountPoints) {
                if ($script:RecoveryKeys.ContainsKey($mp)) {
                    $lines.Add($script:RecoveryKeys[$mp])
                }
                else {
                    # Safety: ensure every fixed drive has *some* representation
                    $lines.Add("Drive: $mp - None")
                }
            }
            # Seperator per key
            $allKeys = ($lines -join " | ")
            
            # Use named params if available, otherwise positional (keeps compatibility across Ninja module variants)
            $stored = $false
            try {
                Ninja-Property-Set -Name $RecoveryKeySecureFieldName -Value $allKeys | Out-Null
                $stored = $true
            }
            catch {
                # Swallow
            }
            
            if (-not $stored) {
                Ninja-Property-Set $RecoveryKeySecureFieldName $allKeys | Out-Null
            }
            
            Write-Log "SUCCESS" "Stored recovery keys for drive(s) ($($orderedMountPoints -join ', ')) in '$RecoveryKeySecureFieldName'"
            
            # Post-storage verification
            if ($VerifyRecoveryKeyStorage) {
                $postVerified = Test-RecoveryKeyStorageVerification -FieldName $RecoveryKeySecureFieldName -ExpectedValue $allKeys
                if (-not $postVerified) {
                    Write-Log "ERROR" "CRITICAL: Recovery key post-storage verification FAILED. Keys may not be retrievable. Review NinjaRMM field permissions and character limits."
                    $script:CriticalFailure = $true
                }
            }
            else {
                Write-Log "WARNING" "Recovery key storage verification is disabled. Keys were written but NOT verified."
            }
            
            # Clear sensitive data
            Clear-Memory -VariableNames "allKeys"
        }
    }
    catch {
        Write-Log "ERROR" "Failed to store recovery keys: $($_.Exception.Message)"
    }
    
    # Clear sensitive state
    Clear-Memory -VariableNames "RecoveryKeys"
    
    Write-Host "`n=== Complete ==="
    if ($script:CriticalFailure) {
        Write-Log "ERROR" "BitLocker management completed with CRITICAL FAILURES. $($script:Errors.Count) error(s). Review output above."
        exit 1
    }
    elseif (-not $script:ScriptSuccess) {
        Write-Log "WARNING" "BitLocker management completed with errors. $($script:Errors.Count) error(s), $($script:Warnings.Count) warning(s)."
        exit 2
    }
    elseif ($script:Warnings.Count -gt 0) {
        Write-Log "WARNING" "BitLocker management completed with $($script:Warnings.Count) warning(s). Review output above."
        exit 0
    }
    else {
        Write-Log "SUCCESS" "BitLocker management completed successfully"
        exit 0
    }
}