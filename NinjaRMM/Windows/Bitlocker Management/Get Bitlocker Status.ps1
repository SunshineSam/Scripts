#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 02-18-2026
    
    Note:
    02-18-2026: All USB drives are now blacklisted. Recovery key collection now validates RecoveryPassword is non-empty. Modified card order so OS Volume is always first. Squashed some bugs & edge case errors.
    02-06-2026: @Leapo pointed out USB Storage handling issues & a few other bugs. Attempted to implement safe USB handling. Optionally validates the secure field data (Custom Field automation Read/Write access required for this).
    12-23-2025: @Pegz in the NinjaOne discord mentioned this issue. Addressed multi-volume compatabillity for drives with multiple volumes, improved clarity.
    09-25-2025: Addressed a bug in the Get-SuspendedCount/Get-RebootCount logic and improved suspended display behavior.
    06-18-2025: Modified AD/Intune Backup logic, improved Suspension insight, and Get-RebootCount logic.
    05-28-2025: Modified to a Status Only version for reporting BitLocker status of all fixed drives.
    05-27-2025: Status (Custom Field, Secure Field) update for all fixed drives, regardless of management as a safety precaution.
    04-25-2025: Creation and validation testing
#>

<#
.SYNOPSIS
    Report BitLocker status for all fixed drives and store in a WYSIWYG custom field (status card) for NinjaRMM.

.DESCRIPTION
    This script reports the BitLocker status for all fixed drives on the system, generates HTML status cards,
    and (optionally) collects recovery key(s) for storage in NinjaRMM secure custom fields. It does not perform
    any management actions such as enabling, suspending, or disabling BitLocker.

    Recovery keys for all fixed drives (when UpdateRecoveryKeys is enabled) are stored in a single secure custom field
    in a deterministic, stable ordering (OS volume first, then alphabetical) using a structured single-line format:
      "C: - Protector ID: {GUID} | Recovery Key: {KEY} | D: - N/A | E: - None"
    
    If no recovery protector exists:
      - Fully disabled (Off + FullyDecrypted + no protectors) -> "Drive: X: - N/A"
      - Otherwise -> "Drive: X: - None"

.PARAMETER SaveLogToDevice
    If specified, logs are saved to <SystemDrive>:\Logs\Bitlocker\BitlockerStatus.log on the device.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the Bitlocker status card.
    Defaults to "BitLockerStatusCard" or env:bitLockerStatusFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.

.PARAMETER UpdateRecoveryKeys
    Optionally force update the stored keys securely.
    Defaults to true or env:updateRecoveryKeys.

.PARAMETER BackupToAD
    Switch to backup recovery keys to AD/AAD (Intune) when UpdateRecoveryKeys is enabled.

.PARAMETER BitLockerStateStoragePath
    Registry path used for reading prior run state (UsedSpaceOnly).
    Defaults to HKLM:\SOFTWARE\BitLockerManagement (or env:bitLockerStateStoragePath).

.PARAMETER UsedSpaceOnlyStateValueName
    Registry value name prefix used to read UsedSpaceOnly state per volume.
    Defaults to "UsedSpaceOnly" (or env:usedSpaceOnlyStateValueName).

.PARAMETER InitialSuspensionCountValueName
    Registry value name prefix used to read initial suspend count per volume (kept for parity; not required for display).
    Defaults to "InitialSuspensionCount" (or env:suspensionCountValueName).

.PARAMETER VerifyRecoveryKeyStorage
    Switch. When enabled, runs a pre-flight check before drive processing,
    writes a realistic-sized test payload to the secure field, reads it back
    to confirm permissions and field capacity. Assumes full recovery key data
    for every drive (security-case). If the pre-flight fails, recovery key
    collection and storage are skipped entirely for this run.
    REQUIRES: The secure custom field must have 'Read/Write' (Automation)
    permissions enabled in NinjaRMM. Default: true.
#>

[CmdletBinding()]
param(
    # Independent switches         Ninja Variable Resolution                                                                      Fallback
    [switch]$UpdateRecoveryKeys = $(if ($env:updateRecoveryKeys) { [Convert]::ToBoolean($env:updateRecoveryKeys) } else { $true }),   # Ninja Script Variable; Checkbox
    [switch]$VerifyRecoveryKeyStorage  = $(if ($env:verifyRecoveryKeyStorage) { [Convert]::ToBoolean($env:verifyRecoveryKeyStorage) } else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice           = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }                       else { $false }), # Ninja Script Variable; Checkbox
    [switch]$BackupToAD                = $(if ($env:bitlockerBackupToAd) { [Convert]::ToBoolean($env:bitlockerBackupToAd) }               else { $false }), # Ninja Script Variable; Checkbox
    
    # Ninja custom field names          Ninja Variable Resolution                                                    Fallback
    [string]$BitLockerStatusFieldName   = $(if ($env:bitLockerStatusFieldName) { $env:bitLockerStatusFieldName }     else { "BitLockerStatusCard" }),  # Optional Ninja Script Variable; String
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }), # Optional Ninja Script Variable; String
    
    # Registry Information                   Optional Ninja Variable Resolution                                             Fallback
    [string]$BitLockerStateStoragePath       = $(if ($env:bitLockerStateStoragePath) { $env:bitLockerStateStoragePath }     else { "HKLM:\SOFTWARE\BitLockerManagement" }), # Optional Ninja Script Variable; String
    [string]$UsedSpaceOnlyStateValueName     = $(if ($env:usedSpaceOnlyStateValueName) { $env:usedSpaceOnlyStateValueName } else { "UsedSpaceOnly" }),                      # Optional Ninja Script Variable; String
    [string]$InitialSuspensionCountValueName = $(if ($env:suspensionCountValueName) { $env:suspensionCountValueName }       else { "InitialSuspensionCount" }),             # Optional Ninja Script Variable; String
    
    # Card customization options
    [string]$CardTitle = "Bitlocker Status",     # Default title + Volume Letter (added later)
    [string]$CardIcon = "fas fa-shield-alt",     # Default icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default", # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius = "10px",          # Default border radius
    [string]$CardSeparationMargin = "0 8px"      # Default distance between cards
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
    $script:OsVolume = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    
    ##############
    # Validation #
    ##############
    Write-Host "`n=== Initialization & Validation ==="
    
    # Helper Function: Called early to check for drive dependencies (e.g., RAID or spanned volumes)
    function Test-DriveDependencies {
        Write-Host "[INFO] Checking for drive dependencies that may affect BitLocker operations"
        try {
            $disks = Get-Disk
            foreach ($disk in $disks) {
                if ($disk.OperationalStatus -eq 'RAID' -or $disk.PartitionStyle -eq 'Unknown') {
                    Write-Host "[WARNING] Detected RAID or non-standard disk configuration on Disk $($disk.Number). BitLocker operations may fail."
                }
                if ($disk.IsBoot -and $disk.NumberOfPartitions -gt 1) {
                    Write-Host "[INFO] Multiple partitions detected on boot disk. Ensure BitLocker is applied to the correct volume."
                }
            }
            
            # Best-effort detection of spanned volumes
            $spannedVolumes = Get-Volume | Where-Object { $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' -and $_.DriveLetter } |
                Where-Object {
                    try {
                        (Get-Partition -Volume $_ -ErrorAction Stop).DiskNumber.Count -gt 1
                    }
                    catch { $false }
                }
                
            if ($spannedVolumes) {
                Write-Host "[WARNING] Detected spanned volumes: $($spannedVolumes.DriveLetter -join ', '). BitLocker may not support these configurations."
            }
            
            Write-Host "[SUCCESS] Drive dependency check completed"
        }
        catch {
            Write-Host "[ERROR] Failed to check drive dependencies: $($_.Exception.Message)"
        }
    }
    Test-DriveDependencies
    
    # Helper function: Detect drive letters connected via USB bus
    # USB-connected drives (even if Windows reports them as 'Fixed') are always excluded from reporting.
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
    
    # Get all fixed drives for reporting (DriveLetter-based volumes only), excluding USB
    # Sorted: OS volume first, then alphabetical, ensures cards and recovery keys use the same ordering
    $script:USBDriveLetters = Get-USBDriveLetters
    $script:AllFixedDrives = Get-Volume |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } |
        Select-Object -ExpandProperty DriveLetter |
        ForEach-Object { $_ + ':' } |
        Sort-Object @{ Expression = { if ($_ -eq $script:OsVolume) { 0 } else { 1 } } }, @{ Expression = { $_ } }
    if ($script:USBDriveLetters) {
        $script:AllFixedDrives = $script:AllFixedDrives | Where-Object { $_ -notin $script:USBDriveLetters }
        Write-Host "[INFO] USB drives blacklisted from reporting: $($script:USBDriveLetters -join ', ')"
    }
    
    if (-not $script:AllFixedDrives) {
        Write-Host "[ERROR] No fixed disks found on this system"
        exit 1
    }
    
    Write-Host "[INFO] Found fixed disks: $($script:AllFixedDrives -join ', ')"
    Write-Host "[INFO] OS Volume: $($script:OsVolume)"
    Write-Host "[INFO] UpdateRecoveryKeys: $UpdateRecoveryKeys"
    Write-Host "[INFO] BackupToAD: $BackupToAD"
    
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
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor -SeparationMargin $CardSeparationMargin
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
            $logFile = Join-Path $logDir "BitlockerStatus.log"
            
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
    
    # Helper Function: Safe variable management
    function Clear-Memory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string[]]$VariableNames
        )
        foreach ($name in $VariableNames) {
            Set-Variable -Name $name -Value $null -Scope Local -ErrorAction SilentlyContinue
            Clear-Variable -Name $name -Scope Local -ErrorAction SilentlyContinue
        }
        Write-Host "[INFO] Cleared memory for variables: $($VariableNames -join ', ')"
    }
    
    # Helper function: Return the list of valid recovery protectors; list
    function Get-ValidRecoveryProtectors {
        param(
            [Parameter(Mandatory)]$volume,
            [switch]$SuppressLog
        )
        
        if (-not $volume.KeyProtector) {
            if (-not $SuppressLog) {
                Write-Log "WARNING" "No KeyProtector array found on volume $($volume.MountPoint)"
            }
            return @()
        }
        
        $candidates = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -ieq 'RecoveryPassword' }
        if (-not $candidates) {
            if (-not $SuppressLog) {
                Write-Log "INFO" "No RecoveryPassword entries found on $($volume.MountPoint)"
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
                    Write-Log "WARNING" "Ignoring invalid protector ID: $($keypair.KeyProtectorId) on $($volume.MountPoint)"
                }
            }
        }
        
        return $valid
    }
    
    # Helper function: Collect recovery key for later storage (robust; uses latest valid protector)
    function Collect-RecoveryKey {
        param(
            [Parameter(Mandatory)]$volume
        )
        
        Write-Log "INFO" "Collecting recovery key for $($volume.MountPoint)"
        
        # Fully disabled state -> N/A
        if (-not $volume.KeyProtector -and $volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "INFO" "No protectors and volume is fully disabled; recording 'N/A' for $($volume.MountPoint)"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - N/A"
            return
        }
        
        $protectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
        if ($protectors -and $protectors.Count -gt 0) {
            $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
            # Validate that RecoveryPassword is actually populated (not just the protector ID)
            if ([string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                Write-Log "WARNING" "Protector $($latestProtector.KeyProtectorId) found but RecoveryPassword is empty for $($volume.MountPoint); retrying volume refresh"
                $rpRetry = 0
                while ($rpRetry -lt 3 -and [string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                    Start-Sleep -Seconds 2
                    $rpRetry++
                    $refreshed = Get-BitLockerVolume -MountPoint $volume.MountPoint -ErrorAction SilentlyContinue
                    if ($refreshed) { $volume = $refreshed }
                    $latestProtector = Get-ValidRecoveryProtectors -volume $volume | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                }
            }
            if ([string]::IsNullOrWhiteSpace($latestProtector.RecoveryPassword)) {
                Write-Log "ERROR" "RecoveryPassword is empty for protector $($latestProtector.KeyProtectorId) on $($volume.MountPoint) after retries. Cannot store recovery key."
                $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - ERROR: Key not retrievable"
            }
            else {
                $keyInfo = "$($volume.MountPoint) - Protector ID: $($latestProtector.KeyProtectorId) | Recovery Key: $($latestProtector.RecoveryPassword)"
                Write-Log "INFO" "Collected recovery key"
                $script:RecoveryKeys[$volume.MountPoint] = $keyInfo
                Clear-Memory -VariableNames "keyInfo"
            }
        }
        else {
            Write-Log "INFO" "No valid recovery key protectors found for $($volume.MountPoint); recording 'None'"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - None"
        }
    }
    
    # Helper function: Save key to AD & AAD if applicable
    function Backup-KeyToAD {
        param(
            [Parameter(Mandatory)]$volume
        )
        
        $protectors = Get-ValidRecoveryProtectors -volume $volume -SuppressLog
        if (-not $protectors -or $protectors.Count -eq 0) {
            Write-Log "WARNING" "No numeric recovery protectors found; nothing to back up for $($volume.MountPoint)"
            return
        }
        
        # Check join status with dsregcmd.exe
        $DSRegOutput = [PSObject]::New()
        & dsregcmd.exe /status | Where-Object { $_ -match ' : ' } | ForEach-Object {
            $Item = $_.Trim() -split '\s:\s'
            $DSRegOutput | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $Item[1] -ErrorAction SilentlyContinue
        }
        
        if ($DSRegOutput.AzureADJoined -eq 'YES') {
            Write-Log "INFO" "Device is AAD-joined; backing up to AAD"
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AAD"
                try {
                    BackupToAAD-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $keypair.KeyProtectorId -ErrorAction Stop
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
                    Backup-BitLockerKeyProtector -MountPoint $volume.MountPoint -KeyProtectorId $keypair.KeyProtectorId -ErrorAction Stop
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
    function Test-RecoveryKeyStorageVerification {
        param(
            [Parameter(Mandatory)][string]$FieldName,
            [Parameter(Mandatory)][string]$ExpectedValue
        )
        try {
            $readBack = Ninja-Property-Get $FieldName
            if ($null -eq $readBack) {
                Write-Log "ERROR" "Recovery key verification: Ninja-Property-Get returned null for '$FieldName'. Ensure the field has 'Script Read' (Automation Read) permission enabled."
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
            Write-Log "ERROR" "Recovery key verification failed: Ninja-Property-Get unavailable or errored: $($_.Exception.Message). Ensure the secure field has 'Script Read' (Automation Read) permission enabled."
            return $false
        }
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
            
            $returnValue    = $result.ReturnValue
            $suspendedCount = $result.SuspendCount
            
            switch ($returnValue) {
                0 {
                    if ($suspendedCount -gt 0) {
                        Write-Log "INFO" "Drive $($MountPoint) Reboot Count: $($suspendedCount)"
                        return $($suspendedCount)
                    }
                    else {
                        Write-Log "INFO" "Drive $($MountPoint) is indefinitely suspended (SuspendCount=0)."
                        return 0
                    }
                }
                2147942450 {
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
# process {
#     # Status Logic Only. No Bitlocker Management Logic
# }

# =========================================
# END Block: Generate Card & Finalization
# =========================================
end {
    # ==============================
    # Pre-flight: Recovery Key Field
    # ==============================
    # Before collecting or storing recovery keys, verify the NinjaRMM secure field is writable,
    # readable, and has sufficient capacity. Uses a realistic-sized test payload matching the
    # expected format for all fixed drives.
    #
    # A single drive entry is ~120 characters:
    #   "C: - Protector ID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} | Recovery Key: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
    # Multiple drives are joined with " | ", so 2 drives ~= 245 chars, 3 drives ~= 370 chars.
    # The default NinjaRMM secure field size is 200 characters, which overflows on 2+ drives.
    # This pre-flight generates a test payload matching the expected real size to catch truncation early.
    $script:PreflightPassed = $false
    if ($VerifyRecoveryKeyStorage -and $UpdateRecoveryKeys) {
        Write-Log "INFO" "Pre-flight: Testing NinjaRMM secure field accessibility and capacity for '$RecoveryKeySecureFieldName'"
        $preflightDriveCount = @($script:AllFixedDrives).Count
        if ($preflightDriveCount -eq 0) { $preflightDriveCount = 1 }
        [System.Collections.Generic.List[string]]$preflightEntries = @()
        foreach ($pfDrive in $script:AllFixedDrives) {
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
        }
        if ($preflightWriteSuccess) {
            $preflightVerified = Test-RecoveryKeyStorageVerification -FieldName $RecoveryKeySecureFieldName -ExpectedValue $preflightTestValue
            if (-not $preflightVerified) {
                Write-Log "ERROR" "Pre-flight FAILED: Secure field cannot hold recovery keys for $preflightDriveCount drive(s) ($($preflightTestValue.Length) characters). The field likely has a character limit (default: 200) that is too small."
                Write-Log "ERROR" "Increase the secure field character limit in NinjaRMM and ensure 'Read/Write' (Automation) is enabled. Recovery keys will NOT be stored this run."
            }
            else {
                Write-Log "SUCCESS" "Pre-flight: Agent cache verified - field is writable, readable, and has sufficient capacity ($($preflightTestValue.Length) chars for $preflightDriveCount drive(s))"
                $script:PreflightPassed = $true
            }
        }
    }
    elseif (-not $VerifyRecoveryKeyStorage -and $UpdateRecoveryKeys) {
        Write-Log "WARNING" "Recovery key storage verification is DISABLED. Keys will be written but NOT verified. Enable VerifyRecoveryKeyStorage for safety."
        $script:PreflightPassed = $true
    }

    # ==============================
    # Card Generation
    # ==============================
    Write-Host "=== BitLocker Card Generation ==="
    Write-Log "INFO" "Generating status card for all fixed drives"

    # Initialize combined HTML for all cards
    $allCardsHtml = ""
    
    foreach ($drive in $script:AllFixedDrives) {
        $MountPoint = $drive
        $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
        if (-not $blv) { continue }
        
        # Determine title icon and color (dynamic)
        switch ($blv.ProtectionStatus) {
            'On' {
                switch ($blv.VolumeStatus) {
                    'FullyEncrypted'        { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#26A644" }
                    'EncryptionInProgress'  { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                    default                 { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                }
            }
            'Off' {
                switch ($blv.VolumeStatus) {
                    'DecryptionInProgress' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                    'FullyDecrypted'       { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                    default                { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                }
            }
            # Not a real option- but should be
            'Suspended' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
            default     { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
        }
        
        # Generate protection and volume status HTML (dynamic)
        $protectionStatusHtml = switch ($blv.ProtectionStatus) {
            'On' { '<i class="fas fa-check-circle" style="color:#26A644;"></i> On' }
            'Off' {
                switch ($blv.VolumeStatus) {
                    'DecryptionInProgress' { '<i class="fas fa-check-circle" style="color:#D9534F;"></i> Pending Off' }
                    'FullyDecrypted'       { '<i class="fas fa-check-circle" style="color:#D9534F;"></i> Off' }
                    default {
                        # If Off and volume status is FullyEncrypted, interpret as suspended
                        $rebootCount = Get-RebootCount -MountPoint ([string]$MountPoint)
                        
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
            'FullyEncrypted'        { '<i class="fas fa-lock" style="color:#26A644;"></i> Fully Encrypted' }
            'EncryptionInProgress'  { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Encryption in Progress' }
            'FullyDecrypted'        { '<i class="fas fa-unlock" style="color:#D9534F;"></i> Fully Decrypted' }
            'DecryptionInProgress'  { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Decryption in Progress' }
            default                 { $blv.VolumeStatus }
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
                    Write-Log "WARNING" "Auto-unlock is not enabled for $MountPoint."
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
    
    # Store all cards in the custom field
    try {
        $allCardsHtml | Ninja-Property-Set-Piped -Name $BitLockerStatusFieldName
        Write-Log "SUCCESS" "BitLocker status cards stored in '$BitLockerStatusFieldName'"
    }
    catch {
        Write-Log "ERROR" "Failed to store status cards: $($_.Exception.Message)"
    }
    
    # Recovery key workflow (optional, gated by pre-flight when verification is enabled)
    Write-Host "`n=== Recovery Key Backup ==="
    if ($UpdateRecoveryKeys -and ($script:PreflightPassed -or -not $VerifyRecoveryKeyStorage)) {

        foreach ($drive in $script:AllFixedDrives) {
            $blv = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
            if (-not $blv) { continue }

            Collect-RecoveryKey -volume $blv

            if ($BackupToAD) {
                Write-Log "INFO" "Backing up $drive recovery key to Intune/AD"
                Backup-KeyToAD -volume $blv
            }
        }

        # Store all recovery keys in a deterministic format (stable ordering: OS first, then alphabetical)
        Write-Log "INFO" "Storing recovery key(s) in secure field"
        try {
            if ($script:RecoveryKeys.Count -eq 0) {
                Write-Log "INFO" "No recovery keys collected; setting secure field to N/A"
                Ninja-Property-Set $RecoveryKeySecureFieldName "N/A" | Out-Null
            }
            else {
                # Stable ordering: OS first, then alphabetical
                $orderedMountPoints = @(
                    $script:AllFixedDrives | Sort-Object `
                        @{ Expression = { if ($_ -eq $script:OsVolume) { 0 } else { 1 } } }, `
                        @{ Expression = { $_ } }
                )

                [System.Collections.Generic.List[string]]$lines = @()
                foreach ($mp in $orderedMountPoints) {
                    if ($script:RecoveryKeys.ContainsKey($mp)) {
                        $lines.Add($script:RecoveryKeys[$mp])
                    }
                    else {
                        $lines.Add("Drive: $mp - None")
                    }
                }

                # Separator per key
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
                Clear-Memory -VariableNames "allKeys"
            }
        }
        catch {
            Write-Log "ERROR" "Failed to store recovery keys: $($_.Exception.Message)"
        }
    }
    elseif ($UpdateRecoveryKeys -and -not $script:PreflightPassed) {
        Write-Log "ERROR" "Recovery key storage skipped - pre-flight verification failed. Keys were NOT collected or stored."
    }
    else {
        Write-Log "INFO" "UpdateRecoveryKeys is false; skipping storage of recovery keys"
    }
    
    # Clear sensitive state
    Clear-Memory -VariableNames "RecoveryKeys"
    
    Write-Host "`n=== Complete ==="
    Write-Log "SUCCESS" "BitLocker status reporting completed"
}