#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-28-2025
    
    Note:
    05-29-2025: Bug fix with parsing reboot count
    05-28-2025: Bug fix for output regarding script scope variables
    05-28-2025: Modified to a Status Only version for reporting BitLocker status of all fixed drives.
    05-28-2025: Address suspend logic and validated 
    05-27-2025: Status (Custom Field, Secure Field) update for all fixed drives, regardless of management as a safety precaution. Zero overriding of keys, etc.
    05-23-2025: Cleanup, big fixes, and consistency, testing
    05-22-2025: Rewrite for multi-volume handling, improved safety, and use case
    05-19-2025: General cleanup improvements
    04-25-2025: Creation and validation testing
#>

<#
.SYNOPSIS
    Report BitLocker status for all fixed drives and and store in a WYSIWYG custom field (status card) for NinjaRMM.

.DESCRIPTION
    This script reports the BitLocker status for all fixed drives on the system, generates HTML status cards
    and collects recovery key(s) for display in NinjaRMM custom fields. It does not perform any management actions
    such as enabling, suspending, or disabling BitLocker. Up to date Recovery Keys for all fixed drives are stored in a single
    secure custom field in a structured format (e.g., "Drive: C: - ID: {GUID} | Key: {Key}; Drive: D: - ID: {GUID} | Key: {Key};").
    If no recovery key exists, it reports "Drive: C: - N/A" or "Drive: C: - None".

.PARAMETER SaveLogToDevice
    If specified, logs are saved to <SystemDrive>:\Logs\BitLockerScript.log on the device.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the BitLocker status card.
    Defaults to "BitLockerStatusCard" or env:bitLockerStatusFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.

.PARAMETER UpdateRecoveryKeys
    Optionally force update the stored keys securely.
    Defaults to true or env:updateRecoveryKeys
#>

[CmdletBinding()]
param(
    # Independent switches      Ninja Variable Resolution                                                          Fallback
    [string]$UpdateRecoveryKeys = $(if ($env:updateRecoveryKeys) { [Convert]::ToBoolean($env:updateRecoveryKeys) } else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice    = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }       else { $false }), # Ninja Script Variable; Checkbox

    # Ninja custom field names          Ninja Variable Resolution                                                    Fallback
    [string]$BitLockerStatusFieldName   = $(if ($env:bitLockerStatusFieldName) { $env:bitLockerStatusFieldName }     else { "BitLockerStatusCard" }),  # Static - Optional Ninja Script Variable;  String
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }), # Static - Optional Ninja Script Variable;  String
    
    # Card customization options
    [string]$CardTitle = "Bitlocker Status",     # Default title
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

    # Initialize script scoped variables
    $script:LoggedRecoveryFound = @{}
    $script:SuppressRecoveryProtectorScanLog = $false
    
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
    
    # Get all fixed drives for reporting
    $allFixedDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
        Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' }
    if (-not $allFixedDrives) {
        Write-Host "[ERROR] No fixed disks found on this system"
        exit 1
    }
    Write-Host "[INFO] Found fixed disks: $($allFixedDrives -join ', ')"
    Write-Host "[INFO] allFixedDrives populated"
    
    Write-Host "[SUCCESS] Values loaded:"
    Write-Host "  - Bitlocker Mount Point(s): All fixed drives ($($allFixedDrives -join ', '))"
    
    # Define the OS drive for use throughout the script (not used in status-only version but kept for structure)
    $osDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    
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
            # Null out the variable
            Set-Variable -Name $name -Value $null -Scope Local -ErrorAction SilentlyContinue
            # Remove it entirely
            Clear-Variable -Name $name -Scope Local -ErrorAction SilentlyContinue
        }
        # No Write-Log output for safety
        Write-Host "[INFO] Cleared memory for variables: $($VariableNames -join ', ')"
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
    
    # Helper function: Collect recovery key for later storage (simplified for status-only)
    function Store-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Collecting recovery key for $($volume.MountPoint)"
        
        # Check if there are no protectors and the volume is fully disabled
        if (-not $volume.KeyProtector -and $volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "INFO" "No protectors and volume is fully disabled; recording 'N/A' for $($volume.MountPoint)"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - N/A"
            return
        }
        
        # Get current recovery protectors
        $protectors = Get-ValidRecoveryProtectors -v $volume
        if ($protectors) {
            $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
            $keyInfo = "$($volume.MountPoint) - Protector ID: $($latestProtector.KeyProtectorId) | Recovery Key: $($latestProtector.RecoveryPassword)"
            Write-Log "INFO" "Collected recovery key for $($volume.MountPoint)"
            $script:RecoveryKeys[$volume.MountPoint] = $keyInfo
            Clear-Memory -VariableNames "keyInfo"
        }
        else {
            Write-Log "INFO" "No recovery key protectors found for $($volume.MountPoint); recording 'None'"
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
}

# =========================================
# PROCESS Block: Execute Bitlocker Actions (Removed for Status-Only)
# =========================================
# process {
#     # Status Logic Only
# }

# =========================================
# END Block: Generate Card & Finalization
# =========================================
end {
    Write-Host "`n=== BitLocker Card Generation ==="
    Write-Log "INFO" "Generating status card for all fixed drives"
    
    # Define registry path for reading UsedSpaceOnly state
    $BitLockerStateStoragePath = "HKLM:\SOFTWARE\BitLockerManagement"
    $UsedSpaceOnlyStateValueName = "UsedSpaceOnly"
    
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
    if ($UpdateRecoveryKeys) {
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
    }
    else {
        Write-Log "INFO" "Skipping storage of recovery keys"
    }
    
    # Clear sensitive state
    Clear-Memory -VariableNames "RecoveryKeys"
    
    Write-Host "`n=== Complete ==="
    Write-Log "SUCCESS" "BitLocker status reporting completed"
}