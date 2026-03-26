#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 03-24-2026

    Note:
    03-24-2026: Manifest cross-referencing has been added, now checks each manifest bit
                against actual cert presence:
                  0x0040 → checks if Windows UEFI CA 2023 is in $dbCertsFound
                  0x0800 → checks if Microsoft Option ROM UEFI CA 2023 is in $dbCertsFound
                  0x1000 → checks if Microsoft UEFI CA 2023 is in $dbCertsFound
                  0x0004/0x4004 → checks $has2023InKek
                  0x0100 → checks if Event 1799 has occurred
                Addresses incorerct assumptions about Update Completion/Manifest.
                dbDefault now tracks which certs are found.
                Three-way logic for missing KEK (both State 4 with 1801 and State 5b without events):
                  dbIsOsWritable → Action Optional (KEK present, WU will handle it)
                  has1803 → Action Required (OEM blocker, key reset or firmware update genuinely needed)
                  No 1803 → Pending, opt-in can push KEK; tells you if opted in or not
                Added WindowsUEFICA2023Capable check and 2011 CA Revocation Cross-Check;
                  Source: https://github.com/cjee21/Check-UEFISecureBootVariables
    03-24-2026: Removed "Pending (1799)" as a distinct state - Event 1799 now falls
                through to the general Pending state. UEFICA2023Status='Updated' is
                the ground truth; age-based 1799 guessing was unnecessary.
                Added 1799→1808 informational note: when 1799 is latest and servicing
                confirms Updated but 1808 is absent from the log, annotates card/console
                that 1808 is expected on the next scheduled task cycle (runs at startup
                + every 12h). No nudge or wait — just an informational annotation.
                Fixed reboot correlation to show latest reboot (closest to 1799).
                Fixed cert name: 'Microsoft Corporation UEFI CA 2023' -> 'Microsoft
                UEFI CA 2023' (matching actual certificate CN).
                Fixed BucketConfidenceLevel extraction: restricted to Event 1801/1808
                only (1800 messages contain garbage metadata), added UpdateType: prefix
                cleanup, null out empty confidence values.
                Added Secure Boot servicing registry reads (UEFICA2023Status, Error,
                ErrorEvent, CanAttemptUpdateAfter from Servicing + DeviceAttributes).
                UEFICA2023Status='Updated' now serves as supplemental compliance signal
                alongside Event 1808. Added Get-Win32ErrorMessage for error code decoding.
                Added Get-AvailableUpdatesMeaning bitmask decoder (0x0004 KEK, 0x0040
                Windows UEFI CA, 0x0100 boot manager, 0x0800 Option ROM CA, 0x1000
                Microsoft UEFI CA, 0x4000 conditional on 2011 trust). Detects unknown bits.
                Enhanced Check-OptInStatus to also read AvailableUpdatesPolicy (GPO/MDM
                persistent trigger) and HighConfidenceOptOut (auto-deployment opt-out).
                Enhanced Get-CertUpdateEventStatus to extract BucketId,
                BucketConfidenceLevel, and SkipReason (KI_<number>) from event messages.
                Card now shows: Certificate Inventory (all 4 certs), Servicing status
                with error details, decoded AvailableUpdates bitmask, Rollout Tier
                (confidence level + skip reason), and enhanced Opt-In with policy/opt-out.
                Sources: MS KB5084567, Get-SecureBootCertInfo.ps1 (HorizonSecured),
                Detect-SecureBootCertUpdateStatus.ps1 (Microsoft Official).
    03-23-2026: Major event log expansion, now queries all 19 Secure Boot TPM-WMI event
                IDs per MS KB5016061, including firmware/error events (1795 firmware
                rejected write, 1796 unexpected error, 1797 prerequisite failure,
                1798 boot mgr not signed, 1802 blocked by known limitation, 1803
                PK-signed KEK not found). Color-coded event log summary in the status
                card with aggregated occurrence counts and timestamps.
                Fixed State 5 bug: "Action Optional" was shown for all has2023InDbDefault
                cases regardless of $dbIsOsWritable, now correctly gates on the flag.
                Fixed inconsistent $statusKey ('Pending' vs card showing 'Action Optional').
                Fixed trigger logic: Step 2.5 no longer re-triggers when Event 1800
                (reboot required) or 1799 (boot manager installed) is the latest state.
                These are in-progress states that need a reboot, not another push.
                Added distinct state handling for Event 1800 ("Pending Reboot") and
                Event 1799 ("Pending" with age-based reboot detection) in the state
                switch, replacing the generic "Pending" catch-all for these events.
    03-19-2026: Added Check-OptInStatus function, always checks telemetry and opt-in
                registry keys (AllowTelemetry, MaxTelemetryAllowed,
                MicrosoftUpdateManagedOptIn, AvailableUpdates) and surfaces result
                in the status card as "Opt-In Status" line.
                Added Trigger-SecureBootTask call after Enable opt-in sets registry keys.
                Increased UEFI variable buffer from 4 KB to 64 KB for large OEM db vars.
                Updated error hint text to include common Win32 error codes (122, 1314).
    03-18-2026: Added "Action Optional" state when UEFI db is OS-writable, downgrades
                Action Required to Action Optional (Windows will push cert automatically).
                Applied to both State 4 (Event 1801) and State 5 (Pending/no events) when
                cert is missing from db or only in dbDefault.
                Added "Audit Secure Boot management status" action, read-only check of
                telemetry keys (AllowTelemetry, MaxTelemetryAllowed), and opt-in keys
                (MicrosoftUpdateManagedOptIn, AvailableUpdates) without making changes..
    03-05-2026: Added passive UEFI variable attributes check for 'db'. This indicates the OS is Allowed to
                write directly to the UEFI cert db, which windows should then eventually update on its own, without
                a need to update the BIOS/Firmware individually (insightful for systems with no BIOS update).
                Integrated into core logic: Passive check always runs if Secure Boot Enabled.
    03-02-2026: Added the abillity to optionally store the status outputs under local storage.
                This outputs 2 files and bypasses the Ninja custom field storage logic.
    02-26-2026: Implemented additional checks for reliable Secure Boot detection.
                Fixed handling of UEFI variable Bytes as array; added parsing of
                db/dbx certificate contents with detailed logging.
                Added check for 'Windows UEFI CA 2023' in db and dbDefault via string match.
                Simplified cert logging to subjects only. Removed non-essential logs.
                Updated ActionRequired state to differentiate between firmware update
                and key reset based on dbDefault presence.
                Added automation to set AvailableUpdates registry key (0x5944) if 2023 cert
                in db but still 1801 (no 1808); updates fields to reflect triggered state.
                After setting reg key, wait 1 min and check for 1799. Update pending messages
                based on presence of 1799 (await 1808 ~15min) or not (await 1799 ~5min).
                Added BitLocker recommendation for key reset. Added OEM BIOS check and links
                for key reset guides.
                Added explicit trigger of Secure-Boot-Update scheduled task after setting reg key.
                Also utilize WinCsFlags.exe /apply if available for more precise config apply.
    02-24-2026: Initial creation. Reports Secure Boot state and 2023 certificate
                update status (Event 1808/1801) via NinjaRMM custom fields.
#>

<#
.SYNOPSIS
    Audits Secure Boot certificate rotation (Microsoft 2023 certs) across db,
    KEK, and dbDefault, and reports actionable status via NinjaRMM custom fields.
    Optionally enables or removes the Windows Update opt-in for Secure Boot management.

.DESCRIPTION
    Checks whether the machine supports UEFI Secure Boot, whether it is enabled,
    and (if enabled) performs a comprehensive audit:
      
      Certificate databases:
        - Parses db (allowed signatures), KEK (key exchange keys), dbx (revocations),
          and dbDefault (firmware defaults) for X509 certificates.
        - Checks for all four 2023 certificates Microsoft is rotating to:
            db:  Windows UEFI CA 2023, Microsoft UEFI CA 2023,
                 Microsoft Option ROM UEFI CA 2023
            KEK: Microsoft Corporation KEK 2K CA 2023
        - KEK is the trust authority that authorizes writes to db. If the 2023 KEK
          authority cert is missing, Windows Update cannot sign the payload needed
          to push new certs into db - even if UEFI attributes allow runtime writes.
      
      UEFI variable attributes (passive, read-only):
        - Uses GetFirmwareEnvironmentVariableExA (P/Invoke) with
          SeSystemEnvironmentPrivilege to read the db variable attributes under the
          EFI Image Security Database GUID.
        - Checks for RUNTIME_ACCESS (0x04) and TIME_BASED_AUTHENTICATED_WRITE_ACCESS (0x20).
        - Combined with the KEK 2023 check, determines whether Windows Update can
          effectively write to the BIOS cert db from the OS.
      
      Event log (TPM-WMI - 19 event IDs per MS KB5016061):
        - State events: 1808 (compliant), 1801 (action required), 1800 (reboot
          required), 1799 (boot manager installed)
        - Deployment events: 1043 (KEK updated), 1044 (Option ROM CA added),
          1045 (UEFI CA added), 1036 (DB applied), 1034 (DBX applied),
          1037 (2011 CA revoked), 1042 (Boot Manager SVN applied)
        - Blocker events: 1032 (BitLocker conflict), 1033 (vulnerable bootloader)
        - Firmware/error events: 1795 (firmware rejected write), 1796 (unexpected
          error), 1797 (2023 cert not in DB), 1798 (boot mgr not signed),
          1802 (blocked by known limitation), 1803 (PK-signed KEK not found)
        - Aggregated summary with occurrence counts displayed in the status card.
      
      Servicing registry (HKLM:\...\SecureBoot\Servicing):
        - UEFICA2023Status: definitive compliance state ("Updated" = done)
        - UEFICA2023Error / UEFICA2023ErrorEvent: last error code + event ID
        - CanAttemptUpdateAfter (DeviceAttributes): next allowed attempt time
        - OEM manufacturer, model, firmware version/date
      
      AvailableUpdates bitmask decoding:
        - Decodes each bit into human-readable pending update descriptions
        - Reads both AvailableUpdates (volatile) and AvailableUpdatesPolicy (GPO/MDM persistent)
        - Detects HighConfidenceOptOut (auto-deployment opt-out flag)
      
      Rollout metadata (from event messages):
        - BucketId: Microsoft's device grouping hash
        - BucketConfidenceLevel: "High Confidence" (auto-eligible) vs "Action Required" (manual)
        - SkipReason: KI_<number> known firmware issue IDs
      
      Scheduled task:
        - Checks whether \Microsoft\Windows\PI\Secure-Boot-Update exists.
      
      Automation (when 2023 cert is in db but OS hasn't acknowledged via 1808):
        - Sets AvailableUpdates + MicrosoftUpdateManagedOptIn (0x5944)
        - Runs WinCsFlags.exe /apply if available
        - Triggers the Secure-Boot-Update scheduled task
        - Waits and checks for post-trigger event progression (1799 -> 1808)
    
    Outputs an HTML status card and a searchable plain-text summary to NinjaRMM
    custom fields (or local files via -SaveStatusLocal).
    
    The eight possible output states are:
      1. Not Applicable    - Non-UEFI or unsupported hardware
      2. Disabled          - UEFI capable but Secure Boot is off
      3. Compliant         - Secure Boot on, Event 1808 or UEFICA2023Status='Updated'
                             confirmed (BIOS certs updated)
      4. Action Required   - 2023 certs missing and Windows cannot write to the BIOS db
                             (UEFI attributes or KEK authority missing); OEM firmware
                             update or manual key reset required
      5. Action Optional   - 2023 certs missing (or in dbDefault only), but the UEFI db
                             is OS-writable (attributes + KEK both present); Windows
                             Update will push the cert automatically, or a manual BIOS
                             update / key reset can expedite
      6. Pending Reboot    - Event 1800 detected; reboot required to continue the update
      7. Pending           - 2023 cert in db or dbDefault but rotation not yet complete;
                             OS update triggered where applicable
      8. Pending (Trigger) - OS-side update triggered; monitoring for event progression,
                             with reboot detection if stalled

.PARAMETER StatusCardFieldName
    NinjaRMM WYSIWYG custom field name for the HTML status card.
    Defaults to "SecureBootCertStatusCard" or env:secureBootStatusCardField.

.PARAMETER PlainTextFieldName
    NinjaRMM text custom field name for the plain-text summary.
    Defaults to "SecureBootCertStatus" or env:secureBootPlainTextField.

.PARAMETER SaveStatusLocal
    If specified, saves the plain-text status to a local text file and the HTML card
    to a local HTML file, in addition to any NinjaRMM field updates. Useful for
    non-NinjaRMM environments.

.PARAMETER SecureBootAction
    Optional action to take in addition to the certificate audit (which always runs).
    ValidateSet: "Enable opt-in for SecureBoot management",
                 "Remove opt-in for SecureBoot management",
                 "Audit SecureBoot management status"
      
      - Enable opt-in for SecureBoot management
            Sets required telemetry to minimum (AllowTelemetry=1,
            MaxTelemetryAllowed=1, per-user ShowedToastAtLevel=1), then sets
            MicrosoftUpdateManagedOptIn=0x5944 and AvailableUpdates=0x5944 to
            opt-in and trigger Secure Boot cert updates via Windows Update.
            If 1808 is already present (compliant), the script still follows
            through but notes that enablement was not strictly necessary.
      
      - Remove opt-in for SecureBoot management
            Removes telemetry enforcement keys (AllowTelemetry,
            MaxTelemetryAllowed) and removes MicrosoftUpdateManagedOptIn to
            opt out of Secure Boot management via Windows Update. Does NOT
            remove AvailableUpdates (already-triggered updates should complete).
      
      - Audit SecureBoot management status
            Read-only check of the current opt-in and telemetry configuration.
            Reports the state of AllowTelemetry, MaxTelemetryAllowed,
            MicrosoftUpdateManagedOptIn, and AvailableUpdates registry keys
            without making any changes. Useful for verifying whether a device
            is properly configured for Windows Update to manage Secure Boot
            certificates.

.PARAMETER IncludeDefaultHive
    Switch: Include the Default user profile template (C:\Users\Default) when applying
    per-user telemetry keys. Only effective when running as SYSTEM. Default: $false.
#>

[CmdletBinding()]
param(
    # Ninja custom field names          Ninja Variable Resolution                                             Fallback
    [string]$StatusCardFieldName = $(if ($env:secureBootStatusCardField)  { $env:secureBootStatusCardField }  else { "SecureBootCertStatusCard" }), # Optional Ninja Script Variable; String
    [string]$PlainTextFieldName  = $(if ($env:secureBootPlainTextField)   { $env:secureBootPlainTextField }   else { "SecureBootCertStatus" }),     # Optional Ninja Script Variable; String
    
    # Other options                 Ninja Variable Resolution                                             Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true }), # Ninja Script Variable; Checkbox
    [switch]$SaveStatusLocal = $(if ($env:saveStatusLocal) { [Convert]::ToBoolean($env:saveStatusLocal) } else { $false }), # Ninja Script Variable; Checkbox
    
    # Secure Boot opt-in action     Ninja Variable Resolution                                             Fallback
    [ValidateSet('Enable opt-in for SecureBoot management','Remove opt-in for SecureBoot management','Audit SecureBoot management status')]
    [string]$SecureBootAction = $(if ($env:securebootAction) { $env:securebootAction } else { 'Audit SecureBoot management status' }), # Optional Ninja Script Variable; Drop-down
    [switch]$IncludeDefaultHive = $(if ($env:includeDefaultHive) { [Convert]::ToBoolean($env:includeDefaultHive) } else { $true }),    # Ninja Script Variable; Checkbox
    
    # Card customization options
    [string]$CardTitle              = "Secure Boot",        # Default title
    [string]$CardIcon               = "fas fa-shield",      # Default icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default",            # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius       = "10px",               # Default border radius
    [string]$CardSeparationMargin   = "0 8px"               # Default distance between cards
)

# =========================================
# BEGIN Block: Initialization & Functions
# =========================================
begin {
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`nAdministrator privileges required"
        exit 1
    }
    Write-Host "`nRunning as Administrator"
    
    #######################
    # Helper Functions
    #######################
    
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
            $logDir = "$systemDrive\Logs\SecureBoot"
            $logFile = Join-Path $logDir "SecureBootStatus.log"
            
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
    
    # Helper function: Write a value to a NinjaRMM text custom field
    # Suppresses verbose/information streams and falls back to positional params if named params fail
    function Invoke-NinjaPropertySet {
        param(
            [string]$FieldName,
            [string]$Value
        )
        $NinjaPropertyCommand = 'Ninja-Property-Set'
        if (-not (Get-Command $NinjaPropertyCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPropertyCommand' not found; cannot update field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            try {
                Ninja-Property-Set -Name $FieldName -Value $Value | Out-Null
            }
            catch {
                Ninja-Property-Set $FieldName $Value | Out-Null
            }
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Write HTML to a NinjaRMM WYSIWYG custom field via piped input
    function Invoke-NinjaPropertySetPiped {
        param(
            [string]$FieldName,
            [string]$Html
        )
        $NinjaPipedCommand = 'Ninja-Property-Set-Piped'
        if (-not (Get-Command $NinjaPipedCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPipedCommand' not found; cannot update WYSIWYG field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            $Html | Ninja-Property-Set-Piped -Name $FieldName
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Parse UEFI signature database (db/dbx) for X509 certificates
    function Parse-UefiSignatureDatabase {
        param (
            [byte[]]$Bytes
        )
        
        $certs = @()
        $X509_GUID = [Guid]::new("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
        $offset = 0
        
        while ($offset -lt $Bytes.Length) {
            $start = $offset
            $guidBytes = [byte[]]$Bytes[$offset..($offset + 15)]
            if ($guidBytes.Length -ne 16) {
                Write-Log "WARNING" "Invalid GUID length at offset $($offset): $($guidBytes.Length)"
                break
            }
            $guid = [Guid]::new($guidBytes)
            $offset += 16
            
            $listSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            $headerSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            $sigSize = [BitConverter]::ToUInt32($Bytes, $offset)
            $offset += 4
            
            if ($guid -ne $X509_GUID) {
                # Skip non-X509 lists
                $offset = $start + $listSize
                continue
            }
            
            # Skip header (usually 0)
            $offset += $headerSize
            
            # Calculate number of signatures
            $remaining = $listSize - 28 - $headerSize
            if ($remaining -lt 0 -or ($remaining % $sigSize -ne 0 -and $sigSize -ne 0)) {
                Write-Log "WARNING" "Invalid signature list size at offset $($start): remaining=$remaining, sigSize=$sigSize"
                $offset = $start + $listSize
                continue
            }
            $numSigs = if ($sigSize -eq 0) { 0 } else { $remaining / $sigSize }
            
            for ($i = 0; $i -lt $numSigs; $i++) {
                $sigBytes = [byte[]]$Bytes[$offset..($offset + $sigSize - 1)]
                $offset += $sigSize
                
                # EFI_SIGNATURE_DATA: GUID (16 bytes) + cert data
                if ($sigBytes.Length -lt 16) {
                    Write-Log "WARNING" "Signature data too short at offset $($offset - $sigSize): Length $($sigBytes.Length)"
                    continue
                }
                $ownerGuidBytes = [byte[]]$sigBytes[0..15]
                $ownerGuid = [Guid]::new($ownerGuidBytes)
                $certBytes = [byte[]]$sigBytes[16..($sigBytes.Length - 1)]
                
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)
                    $certs += $cert
                }
                catch {
                    Write-Log "WARNING" "Failed to parse certificate at offset $($offset - $sigSize): $($_.Exception.Message)"
                }
            }
        }
        
        return $certs
    }
    
    # Helper function: Check if Secure Boot is enabled on this machine
    # Returns: 'Enabled', 'Disabled', or 'NotApplicable' (non-UEFI / exception thrown)
    # Uses direct UEFI variable access to bypass Windows validation failures (e.g., 1801 logic)
    function Get-SecureBootStatus {
        try {
            # Step 1: Check SetupMode
            $setupModeBytes = (Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop).Bytes
            if ($setupModeBytes.Count -eq 0) { throw "SetupMode is empty" }
            $setupMode = $setupModeBytes[0]
            Write-Log "INFO" "SetupMode: $setupMode"
            
            if ($setupMode -eq 1) {
                # Setup Mode (no PK installed) - Secure Boot is disabled, but variables are accessible
                return 'Disabled'
            }
            elseif ($setupMode -eq 0) {
                # User Mode (PK installed) - Check SecureBoot state
                $secureBootBytes = (Get-SecureBootUEFI -Name SecureBoot -ErrorAction Stop).Bytes
                if ($secureBootBytes.Count -eq 0) { throw "SecureBoot is empty" }
                $secureBoot = $secureBootBytes[0]
                
                if ($secureBoot -eq 1) {
                    # Enabled - Validate all core variables exist and are non-empty
                    "PK","KEK","db","dbx" | ForEach-Object {
                        $var = Get-SecureBootUEFI -Name $_ -ErrorAction Stop
                        if ($var.Bytes.Count -eq 0) {
                            throw "UEFI variable '$_' is empty"
                        }
                    }
                    return 'Enabled'
                }
                else {
                    # SecureBoot is 0 - Disabled
                    return 'Disabled'
                }
            }
            else {
                throw "Unexpected SetupMode value: $setupMode"
            }
        }
        catch {
            Write-Log "INFO" "Get-SecureBootUEFI exception: $($_.Exception.Message)"
            if ($_.Exception.Message -match "Cmdlet not supported") {
                # Runtime services not exposed (likely non-UEFI)
                return 'NotApplicable'
            }
            elseif ($_.Exception.Message -match "Unable to set proper privileges") {
                # Token privilege issue
                return 'NotApplicable'
            }
            else {
                # Other exceptions (e.g., broken variable interface)
                return 'NotApplicable'
            }
        }
    }
    
    ###########
    # Sources #
    ###########
    # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#appendix-b--secure-boot-apis
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/modify-firmware-environment-values
    # https://superuser.com/questions/1045279/use-bcdedit-to-configure-pxe-boot-as-default-boot-option
    # https://www.powershellgallery.com/packages/Set-Privilege/1.0.1/Content/Set-Privilege.ps1
    # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea
    # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa
    # https://github.com/perturbed-platypus/UEFIReadCPP/blob/master/uefiCPP/uefiCPP.cpp
    # https://tools.thehacker.recipes/mimikatz/modules/privilege/sysenv
    # https://www.powershellgallery.com/packages/HP.ClientManagement/1.7.2/Content/HP.UEFI.psm1
    # https://wikileaks.org/ciav7p1/cms/page_26968084.html
    # https://docs.system-transparency.org/st-1.3.0/docs/reference/efi-variables/
    
    # New Helper function: Get UEFI variable attributes (passive check)
    # P/Invoke setup for GetFirmwareEnvironmentVariableExA and token privilege management
    Add-Type -MemberDefinition @"
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint GetFirmwareEnvironmentVariableExA(
            string lpName,
            string lpGuid,
            byte[] pBuffer,
            uint nSize,
            ref uint pdwAttributes
        );
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle
        );
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out long lpLuid
        );
        
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
        );
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES {
            public uint PrivilegeCount;
            public long Luid;
            public uint Attributes;
        }
"@ -Namespace Win32 -Name NativeMethods
    
    # Helper function: Enable SeSystemEnvironmentPrivilege for the current process token
    # Required before calling GetFirmwareEnvironmentVariableExA (Error 1314 without it)
    function Enable-SeSystemEnvironmentPrivilege {
        $tokenHandle = [IntPtr]::Zero
        try {
            $processHandle = [Win32.NativeMethods]::GetCurrentProcess()
            # TOKEN_ADJUST_PRIVILEGES (0x20) | TOKEN_QUERY (0x08)
            if (-not [Win32.NativeMethods]::OpenProcessToken($processHandle, 0x0028, [ref]$tokenHandle)) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Log "WARNING" "OpenProcessToken failed: Win32 error $err"
                return $false
            }
            
            $luid = [long]0
            if (-not [Win32.NativeMethods]::LookupPrivilegeValue($null, "SeSystemEnvironmentPrivilege", [ref]$luid)) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Log "WARNING" "LookupPrivilegeValue failed: Win32 error $err"
                return $false
            }
            
            $tp = New-Object Win32.NativeMethods+TOKEN_PRIVILEGES
            $tp.PrivilegeCount = 1
            $tp.Luid = $luid
            $tp.Attributes = 2  # SE_PRIVILEGE_ENABLED
            
            if (-not [Win32.NativeMethods]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Log "WARNING" "AdjustTokenPrivileges failed: Win32 error $err"
                return $false
            }
            
            # AdjustTokenPrivileges returns true even if not all privileges assigned (error 1300)
            $lastErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($lastErr -eq 1300) {
                Write-Log "WARNING" "SeSystemEnvironmentPrivilege not held by this process token"
                return $false
            }
            
            Write-Log "INFO" "SeSystemEnvironmentPrivilege enabled successfully"
            return $true
        }
        finally {
            if ($tokenHandle -ne [IntPtr]::Zero) {
                [Win32.NativeMethods]::CloseHandle($tokenHandle) | Out-Null
            }
        }
    }
    
    # Utilize the invoke import
    function Get-UefiVariableAttributes {
        param (
            [string]$VarName = "db",
            [string]$Guid = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"  # EFI_IMAGE_SECURITY_DATABASE_GUID (for db/dbx)
        )
        
        # Enable SeSystemEnvironmentPrivilege (required for UEFI variable access)
        $privEnabled = Enable-SeSystemEnvironmentPrivilege
        if (-not $privEnabled) {
            Write-Log "WARNING" "Could not enable SeSystemEnvironmentPrivilege; UEFI attributes check may fail"
        }
        
        $buffer = New-Object byte[] 65536  # 64 KB - Dell/OEM db can exceed 4 KB
        $attributes = [uint32]0
        $result = [Win32.NativeMethods]::GetFirmwareEnvironmentVariableExA(
            $VarName,
            $Guid,
            $buffer,
            $buffer.Length,
            [ref]$attributes
        )
        
        if ($result -eq 0) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "ERROR" "Failed to get $VarName attributes. Error: $errorCode (1=Invalid Function/legacy BIOS; 5=Access Denied; 122=Buffer too small; 1314=Privilege not held)"
            return $null
        }
        
        Write-Log "INFO" ("{0} attributes: 0x{1:X8}" -f $VarName, $attributes)
        
        # Interpret attributes
        $hasRuntimeAccess = ($attributes -band 0x00000004) -ne 0  # OS can access at runtime
        $hasTimeBasedAuth = ($attributes -band 0x00000020) -ne 0  # Authenticated writes supported (Windows handles signing)
        $hasAppendWrite   = ($attributes -band 0x00000040) -ne 0  # Append write mode (not always reported in stored attributes)
        
        Write-Log "INFO" "Runtime Access: $hasRuntimeAccess (OS can access UEFI var at runtime)"
        Write-Log "INFO" "Time-Based Authenticated Write: $hasTimeBasedAuth (Windows can sign and push updates)"
        if ($hasAppendWrite) { Write-Log "INFO" "Append Write: True (firmware reports append mode)" }
        
        if ($hasRuntimeAccess -and $hasTimeBasedAuth) {
            Write-Log "SUCCESS" "$VarName is runtime-writable via authenticated updates`n    Windows is CAPABLE of (and eventually will) update the cert without a manual BIOS upgrade"
        }
        else {
            Write-Log "WARNING" "$VarName may not be writable from Windows (missing Runtime Access or Authenticated Write)"
        }
        
        return $attributes
    }
    
    # -----------------------------------------------
    # Secure Boot Event ID Reference (Microsoft-Windows-TPM-WMI)
    # Source: https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
    # -----------------------------------------------
    # State / progress events:
    #   1801 = Certs available but not applied (action required)
    #   1800 = Reboot required to continue
    #   1799 = Boot manager (signed with 2023 cert) installed
    #   1808 = Fully updated - all certs + boot manager applied (compliant)
    #
    # Certificate deployment events (success):
    #   1043 = KEK updated with KEK CA 2023
    #   1044 = Option ROM CA 2023 added to DB
    #   1045 = UEFI CA 2023 added to DB
    #   1036 = DB variable applied
    #   1034 = DBX variable applied
    #   1037 = 2011 CA revoked from DBX (Mitigation 3)
    #   1042 = Boot Manager SVN applied to DBX (Mitigation 4)
    #
    # Blocker / warning events:
    #   1032 = BitLocker conflict (would enter recovery)
    #   1033 = Vulnerable bootloader in EFI partition
    #
    # Firmware / prerequisite error events:
    #   1795 = Firmware returned an error (rejected the write)
    #   1796 = Unexpected error during variable update (Windows retries on reboot)
    #   1797 = Windows UEFI CA 2023 not in DB (prerequisite failure)
    #   1798 = Boot manager not signed with 2023 cert (DBX update blocked)
    #   1802 = Update blocked - known firmware/hardware limitation
    #   1803 = PK-signed KEK not found for this device (OEM hasn't provided signed KEK)
    # -----------------------------------------------
    
    # Human-readable descriptions for each event ID
    $script:SecureBootEventDescriptions = @{
        # State events
        1801 = 'Certs available but not applied'
        1800 = 'Reboot required to continue'
        1799 = 'Boot manager installed'
        1808 = 'Fully updated (all certs + boot manager)'
        # Deployment success events
        1043 = 'KEK updated with KEK CA 2023'
        1044 = 'Option ROM CA 2023 added to DB'
        1045 = 'UEFI CA 2023 added to DB'
        1036 = 'DB variable applied'
        1034 = 'DBX variable applied'
        1037 = '2011 CA revoked from DBX (Mitigation 3)'
        1042 = 'Boot Manager SVN applied to DBX (Mitigation 4)'
        # Blocker events
        1032 = 'BitLocker conflict'
        1033 = 'Vulnerable bootloader in EFI partition'
        # Firmware / prerequisite errors
        1795 = 'Firmware returned an error'
        1796 = 'Unexpected update error (will retry on reboot)'
        1797 = 'UEFI CA 2023 not in DB (prerequisite failure)'
        1798 = 'Boot manager not signed with 2023 cert'
        1802 = 'Update blocked (known firmware limitation)'
        1803 = 'PK-signed KEK not found (OEM issue)'
    }
    
    # All event IDs we query for (18 total per MS KB5016061)
    $script:SecureBootEventIds = @(
        1032, 1033, 1034, 1036, 1037, 1042, 1043, 1044, 1045,
        1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1808
    )
    
    # Helper function: Query ALL Secure Boot events from the System event log
    # Returns a hashtable with:
    #   Status       - Compliant / ActionRequired / Pending (based on most recent state event)
    #   EventId      - Most recent state event ID
    #   EventTime    - Timestamp of most recent state event
    #   EventMessage - Human-readable description
    #   AllEvents    - Full list of parsed events (for summary)
    #   EventSummary - Aggregated list: @{ Id; Description; Count; FirstSeen; LastSeen }
    function Get-CertUpdateEventStatus {
        $rawEvents = $null
        
        # Primary method: Get-WinEvent
        try {
            $rawEvents = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = $script:SecureBootEventIds
            } -ErrorAction Stop
            Write-Log "INFO" "Get-WinEvent succeeded: $(@($rawEvents).Count) event(s) found"
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                Write-Log "INFO" "Get-WinEvent: No matching Secure Boot events found"
                $rawEvents = @()
            }
            else {
                Write-Log "WARNING" "Get-WinEvent failed: $($_.Exception.Message). Attempting Get-EventLog fallback."
                try {
                    $rawEvents = Get-EventLog -LogName System -Source 'Microsoft-Windows-TPM-WMI' `
                        -InstanceId $script:SecureBootEventIds -ErrorAction Stop
                    Write-Log "INFO" "Get-EventLog fallback succeeded: $(@($rawEvents).Count) event(s) found"
                }
                catch {
                    Write-Log "WARNING" "Get-EventLog fallback also failed: $($_.Exception.Message)"
                    $rawEvents = @()
                }
            }
        }
        
        $rawEvents = @($rawEvents)
        
        # Normalize events to a common format, extracting BucketId/Confidence/SkipReason from message text
        $parsedEvents = foreach ($ev in $rawEvents) {
            $id   = if ($null -ne $ev.Id) { $ev.Id } else { $ev.InstanceId }
            $time = if ($null -ne $ev.TimeCreated) { $ev.TimeCreated } else { $ev.TimeGenerated }
            $msg  = if ($null -ne $ev.Message) { $ev.Message } else { '' }
            
            # Extract BucketId, BucketConfidenceLevel, SkipReason from event message (1801/1808 carry these)
            $bucketId    = $null
            $confidence  = $null
            $skipReason  = $null
            if ($msg -match 'BucketId:\s*(.+?)(\r|\n|$)')             { $bucketId   = $matches[1].Trim() }
            if ($msg -match 'BucketConfidenceLevel:\s*(.+?)(\r|\n|$)') { $confidence = $matches[1].Trim() }
            if ($msg -match 'SkipReason:\s*(KI_\d+)')                 { $skipReason = $matches[1] }
            
            [PSCustomObject]@{
                Id          = [int]$id
                Time        = [datetime]$time
                Description = if ($script:SecureBootEventDescriptions.ContainsKey([int]$id)) { $script:SecureBootEventDescriptions[[int]$id] } else { "Unknown event $id" }
                BucketId    = $bucketId
                Confidence  = $confidence
                SkipReason  = $skipReason
            }
        }
        
        # Sort chronologically (oldest first for display, newest first for state)
        $parsedEvents = @($parsedEvents | Sort-Object -Property Time)
        
        # Build aggregated summary: group by ID, count occurrences, track first/last seen
        $eventSummary = @()
        if ($parsedEvents.Count -gt 0) {
            $grouped = $parsedEvents | Group-Object -Property Id
            foreach ($group in ($grouped | Sort-Object { ($_.Group | Select-Object -First 1).Time })) {
                $sorted = $group.Group | Sort-Object Time
                $eventSummary += [PSCustomObject]@{
                    Id          = [int]$group.Name
                    Description = $sorted[0].Description
                    Count       = $group.Count
                    FirstSeen   = $sorted[0].Time
                    LastSeen    = $sorted[-1].Time
                }
            }
        }
        
        # Log the summary
        if ($eventSummary.Count -gt 0) {
            Write-Log "INFO" "Event log summary:"
            foreach ($entry in ($eventSummary | Sort-Object FirstSeen)) {
                $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
                Write-Log "INFO" ("  {0}  [{1}] {2} ({3}x)" -f $timeStr, $entry.Id, $entry.Description, $entry.Count)
            }
        }
        
        # Determine state from the most recent STATE event (1808 > 1800 > 1801 > 1799)
        # These are the events that indicate overall deployment status
        $stateEventIds = @(1799, 1800, 1801, 1808)
        $stateEvents = @($parsedEvents | Where-Object { $stateEventIds -contains $_.Id } | Sort-Object Time -Descending)
        
        if ($stateEvents.Count -eq 0 -and $parsedEvents.Count -eq 0) {
            return @{
                Status       = 'Pending'
                EventId      = $null
                EventTime    = $null
                EventMessage      = 'No Secure Boot certificate events found in System log'
                AllEvents         = @()
                EventSummary      = @()
                BucketId          = $null
                Confidence        = $null
                SkipReason        = $null
                RebootCorrelation = $null
            }
        }
        
        # If we have deployment events (1043-1045, 1036, etc.) but no state events,
        # certs are being applied but no state conclusion yet
        if ($stateEvents.Count -eq 0) {
            $latest = $parsedEvents | Select-Object -Last 1
            return @{
                Status       = 'Pending'
                EventId      = $latest.Id
                EventTime    = $latest.Time
                EventMessage      = 'Deployment events found but no state events (1801/1808) yet'
                AllEvents         = $parsedEvents
                EventSummary      = $eventSummary
                BucketId          = $null
                Confidence        = $null
                SkipReason        = $null
                RebootCorrelation = $null
            }
        }
        
        $latestState = $stateEvents[0]
        
        switch ($latestState.Id) {
            1808 {
                $status = 'Compliant'
                $msg    = 'Fully updated - all certs + boot manager applied (Event 1808)'
            }
            1800 {
                $status = 'Pending'
                $msg    = 'Reboot required to continue (Event 1800)'
            }
            1801 {
                $status = 'ActionRequired'
                $msg    = 'Certs available but not applied (Event 1801)'
            }
            1799 {
                $status = 'Pending'
                $msg    = 'Boot manager signed with UEFI CA 2023 installed successfully (Event 1799)'
            }
            default {
                $status = 'Pending'
                $msg    = "Event $($latestState.Id) - treating as Pending"
            }
        }
        
        Write-Log "INFO" "Most recent state event: ID $($latestState.Id) at $($latestState.Time)"
        
        # Extract BucketId/Confidence from 1801 or 1808 events only (1800/1799 don't carry meaningful bucket metadata)
        $bucketEvent = $stateEvents | Where-Object { $null -ne $_.BucketId -and $_.Id -in @(1801, 1808) } | Select-Object -First 1
        if ($null -ne $bucketEvent) {
            # Clean up Confidence: strip "UpdateType:" prefix if present (e.g., "UpdateType:ActionRequired" → "ActionRequired")
            if ($bucketEvent.Confidence -match '^UpdateType:(.*)$') {
                $bucketEvent.Confidence = $matches[1].Trim()
            }
            # If confidence is empty/whitespace after cleanup, null it out
            if ([string]::IsNullOrWhiteSpace($bucketEvent.Confidence)) {
                $bucketEvent.Confidence = $null
            }
            Write-Log "INFO" "Bucket: $($bucketEvent.BucketId)"
            if ($null -ne $bucketEvent.Confidence) {
                Write-Log "INFO" "Confidence: $($bucketEvent.Confidence)"
            }
            if ($null -ne $bucketEvent.SkipReason) {
                Write-Log "WARNING" "SkipReason: $($bucketEvent.SkipReason) (Known firmware issue)"
            }
        }
        
        # Detect 1800 → 1799 progression (reboot between them confirms the sequence)
        $rebootCorrelation = $null
        $ev1800 = $parsedEvents | Where-Object { $_.Id -eq 1800 } | Sort-Object Time -Descending | Select-Object -First 1
        $ev1799 = $parsedEvents | Where-Object { $_.Id -eq 1799 } | Sort-Object Time -Descending | Select-Object -First 1
        if ($null -ne $ev1800 -and $null -ne $ev1799 -and $ev1799.Time -gt $ev1800.Time) {
            $rebootCheck = Get-RebootsBetweenTimes -After $ev1800.Time -Before $ev1799.Time
            if ($rebootCheck.Found) {
                $bootTimeStr = $rebootCheck.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                Write-Log "INFO" "Reboot detected between 1800 ($($ev1800.Time.ToString('HH:mm'))) and 1799 ($($ev1799.Time.ToString('HH:mm'))): boot at $bootTimeStr"
                $rebootCorrelation = @{
                    Event1800Time = $ev1800.Time
                    Event1799Time = $ev1799.Time
                    BootTimes     = $rebootCheck.BootTimes
                    BootCount     = $rebootCheck.Count
                    Confirmed     = $true
                }
            }
            else {
                Write-Log "INFO" "1800 ($($ev1800.Time.ToString('HH:mm'))) → 1799 ($($ev1799.Time.ToString('HH:mm'))) detected, but no reboot found between them"
                $rebootCorrelation = @{
                    Event1800Time = $ev1800.Time
                    Event1799Time = $ev1799.Time
                    BootTimes     = @()
                    BootCount     = 0
                    Confirmed     = $false
                }
            }
        }
        
        return @{
            Status            = $status
            EventId           = $latestState.Id
            EventTime         = $latestState.Time
            EventMessage      = $msg
            AllEvents         = $parsedEvents
            EventSummary      = $eventSummary
            BucketId          = if ($bucketEvent) { $bucketEvent.BucketId } else { $null }
            Confidence        = if ($bucketEvent) { $bucketEvent.Confidence } else { $null }
            SkipReason        = if ($bucketEvent) { $bucketEvent.SkipReason } else { $null }
            RebootCorrelation = $rebootCorrelation
        }
    }
    
    # Helper function: Check for recent post-trigger events (1808, 1799) in last N minutes
    # Returns: 'Compliant' (1808 found), 'Pending1808' (1799 found, awaiting 1808),
    #          or 'Pending' (neither found yet)
    function Check-PostTriggerEvents {
        param (
            [int]$Minutes = 5
        )
        $startTime = (Get-Date).AddMinutes(-$Minutes)
        
        # Check for 1808 first (best case - already fully compliant)
        try {
            $ev1808 = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = 1808
                StartTime    = $startTime
            } -ErrorAction Stop
            if ($ev1808.Count -gt 0) { return 'Compliant' }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to check for 1808: $($_.Exception.Message)"
            }
        }
        
        # Check for 1799 (boot manager installed, awaiting 1808)
        try {
            $ev1799 = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = 1799
                StartTime    = $startTime
            } -ErrorAction Stop
            if ($ev1799.Count -gt 0) { return 'Pending1808' }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to check for 1799: $($_.Exception.Message)"
            }
        }
        
        return 'Pending'
    }
    
    # Helper function: Set the AvailableUpdates + MicrosoftUpdateManagedOptIn registry keys to trigger OS-side update
    function Set-SecureBootUpdateRegKey {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $regValue = 0x5944  # Bitmask to trigger all updates / opt-in magic value
        
        try {
            RegistryShouldBe -KeyPath $regPath -Name "MicrosoftUpdateManagedOptIn" -Value $regValue
            RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $regValue
            Write-Log "SUCCESS" "Set $regPath opt-in + trigger keys to 0x5944"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to set registry key: $($_.Exception.Message)"
            return $false
        }
    }
    
    # Helper function: Apply WinCS feature key if WinCsFlags.exe is available
    function Apply-WinCsFeatureKey {
        $winCsPath = "$env:SystemRoot\System32\WinCsFlags.exe"
        if (Test-Path $winCsPath) {
            try {
                & $winCsPath /apply --key "F33E0C8E002" | Out-Null
                Write-Log "SUCCESS" "Applied WinCS feature key F33E0C8E002 via WinCsFlags.exe"
                return $true
            }
            catch {
                Write-Log "ERROR" "Failed to apply WinCS key: $($_.Exception.Message)"
                return $false
            }
        }
        else {
            Write-Log "INFO" "WinCsFlags.exe not found; reg key should push this through still"
            return $false
        }
    }
    
    # Helper function: Trigger the Secure Boot update scheduled task
    function Trigger-SecureBootTask {
        try {
            Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction Stop
            Write-Log "SUCCESS" "Triggered Secure-Boot-Update scheduled task"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to trigger Secure-Boot-Update task: $($_.Exception.Message)"
            return $false
        }
    }
    
    # Helper function: Check Secure Boot opt-in and telemetry configuration status (read-only)
    # Returns: hashtable with IsOptedIn, TelemetryMeetsMin, AvailableUpdatesSet, Summary,
    #          AvailableUpdatesPolicy, HighConfidenceOptOut, decoded bitmask meanings, and raw values
    function Check-OptInStatus {
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        $secureBootPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $allowTelemetry = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
        $maxTelemetry   = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
        $optIn          = (Get-ItemProperty -Path $secureBootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
        $available      = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty "AvailableUpdates" -ErrorAction SilentlyContinue)
        
        # AvailableUpdatesPolicy: GPO/MDM-driven persistent trigger (survives reboots, unlike AvailableUpdates)
        $availablePolicy = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdatesPolicy" -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty "AvailableUpdatesPolicy" -ErrorAction SilentlyContinue)
        
        # HighConfidenceOptOut: Opt-out flag for Microsoft's auto-deployment to high-confidence devices
        $highConfOptOut  = (Get-ItemProperty -Path $secureBootPath -Name "HighConfidenceOptOut" -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty "HighConfidenceOptOut" -ErrorAction SilentlyContinue)
        
        # Telemetry meets minimum if AllowTelemetry >= 1 or is not set (OS default allows it)
        $telemetryMeetsMin = ($null -eq $allowTelemetry) -or ($allowTelemetry -ge 1)
        $isOptedIn         = $optIn -eq 0x5944
        $availableSet      = ($null -ne $available -and $available -ne 0)
        $policySet         = ($null -ne $availablePolicy -and $availablePolicy -ne 0)
        
        # Decode AvailableUpdates bitmask (use whichever is set; policy takes precedence)
        $effectiveAvailable = if ($policySet) { $availablePolicy } elseif ($availableSet) { $available } else { 0 }
        $availableMeaning   = if ($effectiveAvailable -ne 0) { Get-AvailableUpdatesMeaning -Value $effectiveAvailable } else { @() }
        
        # Determine summary
        if ($isOptedIn -and $telemetryMeetsMin) {
            $summary = 'Enabled'
        }
        elseif ($isOptedIn -and -not $telemetryMeetsMin) {
            $summary = 'Blocked'  # Opted in but telemetry too low
        }
        else {
            $summary = 'Not enabled'
        }
        
        return @{
            IsOptedIn              = $isOptedIn
            TelemetryMeetsMin      = $telemetryMeetsMin
            AvailableUpdatesSet    = $availableSet
            AllowTelemetry         = $allowTelemetry
            MaxTelemetry           = $maxTelemetry
            OptInValue             = $optIn
            AvailableUpdates       = $available
            AvailableUpdatesPolicy = $availablePolicy
            AvailableUpdatesPolicySet = $policySet
            HighConfidenceOptOut   = $highConfOptOut
            AvailableUpdatesMeaning = $availableMeaning
            EffectiveAvailable     = $effectiveAvailable
            Summary                = $summary
        }
    }
    
    # Helper function: Convert a Win32 or HRESULT error code to a human-readable message
    # Returns: string with the error message, or the hex code if unknown
    function Get-Win32ErrorMessage {
        param ([uint32]$ErrorCode)
        try {
            # Only low 16 bits matter for Win32Exception
            $win32 = $ErrorCode -band 0xFFFF
            $ex = [System.ComponentModel.Win32Exception]::new([int]$win32)
            return $ex.Message
        }
        catch {
            return ('0x{0:X}' -f $ErrorCode)
        }
    }
    
    # Helper function: Read Secure Boot servicing registry state
    # Returns: hashtable with UEFICA2023Status, Error, ErrorEvent, ErrorMessage, CanAttemptUpdateAfter
    # Source: HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
    function Get-SecureBootServicingStatus {
        $servPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
        $attrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes"
        
        $result = @{
            UEFICA2023Status           = $null
            WindowsUEFICA2023Capable   = $null   # 0=not in DB, 1=cert in DB, 2=cert in DB + booting from 2023 boot mgr
            UEFICA2023Error            = $null
            UEFICA2023ErrorHex         = $null
            UEFICA2023ErrorMessage     = $null
            UEFICA2023ErrorEvent       = $null
            UEFICA2023ErrorEventDesc   = $null
            CanAttemptUpdateAfter      = $null
            OEMManufacturerName        = $null
            OEMModelNumber             = $null
            FirmwareVersion            = $null
            FirmwareReleaseDate        = $null
        }
        
        # --- Servicing status ---
        $serv = Get-ItemProperty -Path $servPath -ErrorAction SilentlyContinue
        if ($null -ne $serv) {
            # UEFICA2023Status: "Updated" = compliant, other values = in progress or error
            if ($serv.PSObject.Properties.Match("UEFICA2023Status").Count -gt 0) {
                $result.UEFICA2023Status = $serv.UEFICA2023Status
            }

            # WindowsUEFICA2023Capable: 0=not in DB, 1=cert in DB, 2=cert in DB + booting from 2023 boot manager
            if ($serv.PSObject.Properties.Match("WindowsUEFICA2023Capable").Count -gt 0) {
                $result.WindowsUEFICA2023Capable = [int]$serv.WindowsUEFICA2023Capable
            }

            # UEFICA2023Error: Win32 error code from last failed attempt
            if ($serv.PSObject.Properties.Match("UEFICA2023Error").Count -gt 0 -and $null -ne $serv.UEFICA2023Error) {
                $rawError = [uint32]$serv.UEFICA2023Error
                $result.UEFICA2023Error = $rawError
                $result.UEFICA2023ErrorHex = ('0x{0:X}' -f $rawError)
                if ($rawError -ne 0) {
                    $result.UEFICA2023ErrorMessage = Get-Win32ErrorMessage -ErrorCode $rawError
                }
            }
            
            # UEFICA2023ErrorEvent: maps to the event ID that describes the failure
            if ($serv.PSObject.Properties.Match("UEFICA2023ErrorEvent").Count -gt 0 -and $null -ne $serv.UEFICA2023ErrorEvent) {
                $errorEvent = [int]$serv.UEFICA2023ErrorEvent
                $result.UEFICA2023ErrorEvent = $errorEvent
                $result.UEFICA2023ErrorEventDesc = if ($script:SecureBootEventDescriptions.ContainsKey($errorEvent)) {
                    $script:SecureBootEventDescriptions[$errorEvent]
                } else {
                    "Unknown event $errorEvent"
                }
            }
        }
        
        # --- Device attributes ---
        $attr = Get-ItemProperty -Path $attrPath -ErrorAction SilentlyContinue
        if ($null -ne $attr) {
            if ($attr.PSObject.Properties.Match("OEMManufacturerName").Count -gt 0)  { $result.OEMManufacturerName = $attr.OEMManufacturerName }
            if ($attr.PSObject.Properties.Match("OEMModelNumber").Count -gt 0)       { $result.OEMModelNumber = $attr.OEMModelNumber }
            if ($attr.PSObject.Properties.Match("FirmwareVersion").Count -gt 0)      { $result.FirmwareVersion = $attr.FirmwareVersion }
            if ($attr.PSObject.Properties.Match("FirmwareReleaseDate").Count -gt 0)  { $result.FirmwareReleaseDate = $attr.FirmwareReleaseDate }
            
            # CanAttemptUpdateAfter: FILETIME (byte[] or long) - next allowed update attempt
            if ($attr.PSObject.Properties.Match("CanAttemptUpdateAfter").Count -gt 0 -and $null -ne $attr.CanAttemptUpdateAfter) {
                try {
                    $raw = $attr.CanAttemptUpdateAfter
                    if ($raw -is [byte[]]) {
                        $filetime = [BitConverter]::ToInt64($raw, 0)
                    } else {
                        $filetime = [long]$raw
                    }
                    if ($filetime -gt 0) {
                        $result.CanAttemptUpdateAfter = [DateTime]::FromFileTime($filetime)
                    }
                }
                catch {
                    Write-Log "WARNING" "Could not convert CanAttemptUpdateAfter FILETIME to DateTime"
                }
            }
        }
        
        return $result
    }
    
    # Helper function: Decode AvailableUpdates bitmask into human-readable meanings
    # Source: Get-SecureBootCertInfo.ps1 (HorizonSecured) and MS KB5084567
    # Returns: array of strings describing each set bit
    function Get-AvailableUpdatesMeaning {
        param ([int]$Value)
        
        if ($Value -eq 0) {
            return @('No pending Secure Boot updates')
        }
        
        $meaning = @()
        
        # KEK special case: both bits set together
        if (($Value -band 0x4004) -eq 0x4004) { $meaning += 'KEK needs to be updated' }
        if ($Value -band 0x0004)               { $meaning += 'Install Microsoft KEK 2023 signed by OEM PK' }
        if ($Value -band 0x0040)               { $meaning += 'Apply Windows UEFI CA 2023 to DB' }
        if ($Value -band 0x0100)               { $meaning += 'Install boot manager signed with UEFI CA 2023' }
        if ($Value -band 0x0800)               { $meaning += 'Apply Microsoft Option ROM UEFI CA 2023' }
        if ($Value -band 0x1000)               { $meaning += 'Apply Microsoft UEFI CA 2023' }
        # 0x4000 = conditional qualifier (apply only if UEFI CA 2011 trusted) — always present, not displayed
        
        # Detect undocumented bits
        $knownBits = 0x0004 -bor 0x0040 -bor 0x0100 -bor 0x0800 -bor 0x1000 -bor 0x4000 -bor 0x4004
        $unknownBits = $Value -band (-bnot $knownBits)
        if ($unknownBits -ne 0) {
            $meaning += ('Unknown update bits: 0x{0:X}' -f $unknownBits)
        }
        
        return $meaning
    }
    
    # Helper function: Find system boot events between two timestamps
    # Uses Kernel-General Event 12 (system startup marker) to detect reboots
    # Returns: @{ Found = $true/$false; BootTimes = @([datetime]...); Count = int }
    function Get-RebootsBetweenTimes {
        param (
            [Parameter(Mandatory)][datetime]$After,
            [Parameter(Mandatory)][datetime]$Before
        )
        $bootTimes = @()
        try {
            $boots = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-Kernel-General'
                Id           = 12
                StartTime    = $After
                EndTime      = $Before
            } -ErrorAction Stop
            $bootTimes = @($boots | ForEach-Object { $_.TimeCreated } | Sort-Object)
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "WARNING" "Failed to query boot events: $($_.Exception.Message)"
            }
        }
        return @{
            Found     = $bootTimes.Count -gt 0
            BootTimes = $bootTimes
            Count     = $bootTimes.Count
        }
    }
    
    # Helper function: Check if a system reboot is pending and return the source(s)
    # Returns: hashtable @{ Pending = $true/$false; Sources = @('Windows Update', 'Component Servicing') }
    function Get-PendingRebootStatus {
        $sources = @()
        
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $sources += 'Windows Update'
        }
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $sources += 'Component Servicing'
        }
        
        return @{
            Pending = $sources.Count -gt 0
            Sources = $sources
        }
    }
    
    # Helper function: Check if running as SYSTEM
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY\*" -or $id.IsSystem
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
        
        # --- Special-case Binary values to avoid noisy / unreliable array comparison ---
        if ($Type -eq 'Binary') {
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
                        
            if ($null -eq $current) {
                Write-Log "VERBOSE" "Creating $Name (Binary)"
                New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
            }
            else {
                Write-Log "VERBOSE" "Updating $Name (Binary)"
                Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
            }
            
            # Don’t fight PowerShell’s Binary comparison semantics here – treat as success
            Write-Log "VERBOSE" "$Name confirmed Binary value (length: $($Value.Length))"
            return
        }
        
        # --- Standard retry logic for non-Binary types ---
        function Test-RegistryValueEqual {
            param(
                $Current,
                $Desired
            )
            # For non-binary types, simple scalar comparison is fine
            return ($Current -ceq $Desired)
        }
        
        $attempt = 0
        do {
            $attempt++
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
            if (-not $valuesMatch) {
                if ($null -eq $current) {
                    Write-Log "VERBOSE" "Creating $Name = $Value"
                    New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                }
                else {
                    Write-Log "VERBOSE" "Updating $Name from $current to $Value"
                    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
                }
            }
            
            Start-Sleep -Milliseconds 800
            
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            $valuesMatch = Test-RegistryValueEqual -Current $current -Desired $Value
            
        }
        while (-not $valuesMatch -and $attempt -lt 5)
        
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
                
        if (Test-RegistryValueEqual -Current $final -Desired $Value) {
            Write-Log "VERBOSE" "$Name confirmed $Value"
        }
        else {
            Write-Log "WARNING" "$Name failed to set to $Value"
        }
    }
    
    # Helper function: Retrieve user profiles and their NTUSER hive paths
    function Get-UserHive {
        [CmdletBinding()]
        param (
            [Parameter()]
            [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
            [String]$Type = "All",
            [Parameter()]
            [String[]]$ExcludedUsers,
            [Parameter()]
            [switch]$IncludeDefault
        )
        
        $Patterns = switch ($Type) {
            "AzureAD"        { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All"            { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" }
        }
        
        $UserProfiles = foreach ($Pattern in $Patterns) {
            Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } |
                Select-Object @{
                    Name       = "SID"
                    Expression = { $_.PSChildName }
                }, @{
                    Name       = "Username"
                    Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" }
                }, @{
                    Name       = "Domain"
                    Expression = {
                        if ($_.PSChildName -match "S-1-12-1-(\d+-?){4}$") { "AzureAD" } else { $null }
                    }
                }, @{
                    Name       = "UserHive"
                    Expression = { "$($_.ProfileImagePath)\NTUSER.DAT" }
                }, @{
                    Name       = "Path"
                    Expression = { $_.ProfileImagePath }
                }
        }
        
        if ($IncludeDefault) {
            $DefaultProfile = "" | Select-Object Username, SID, UserHive, Path, Domain
            $DefaultProfile.Username = "Default"
            $DefaultProfile.Domain   = $env:COMPUTERNAME
            $DefaultProfile.SID      = "DefaultProfile"
            $DefaultProfile.UserHive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
            $DefaultProfile.Path     = "$env:SystemDrive\Users\Default"
            
            $UserProfiles = @($UserProfiles) + @(
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.Username }
            )
        }
        
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            $AllAccounts = Get-WmiObject -Class "win32_UserAccount"
        }
        else {
            $AllAccounts = Get-CimInstance -ClassName "win32_UserAccount"
        }
        
        $CompleteUserProfiles = $UserProfiles | ForEach-Object {
            $SID         = $_.SID
            $Win32Object = $AllAccounts | Where-Object { $_.SID -like $SID }
            
            if ($Win32Object) {
                $Win32Object | Add-Member -NotePropertyName UserHive -NotePropertyValue $_.UserHive -Force
                $Win32Object | Add-Member -NotePropertyName Path     -NotePropertyValue $_.Path     -Force
                $Win32Object
            }
            else {
                [PSCustomObject]@{
                    Name     = $_.Username
                    Domain   = $_.Domain
                    SID      = $_.SID
                    UserHive = $_.UserHive
                    Path     = $_.Path
                }
            }
        }
        
        $CompleteUserProfiles | Where-Object { $ExcludedUsers -notcontains $_.Name }
    }
    
    # Helper function: Enable required telemetry for Windows Update Secure Boot management
    # Sets machine-level AllowTelemetry + MaxTelemetryAllowed, and per-user ShowedToastAtLevel
    function Enable-RequiredTelemetry {
        Write-Log "INFO" "Setting telemetry to minimum 'Required' level for Secure Boot management"
        
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        
        # Machine-level: AllowTelemetry = 1 (Required), unless already >= 3 (Full)
        $currentAllow = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
        if ($currentAllow -ge 3) {
            Write-Log "INFO" "AllowTelemetry already set to $currentAllow (optional+required); skipping"
        }
        else {
            RegistryShouldBe -KeyPath $dataCollectionPath -Name "AllowTelemetry" -Value 1
        }
        
        # Machine-level: MaxTelemetryAllowed = 1 (Required), unless already >= 3
        $currentMax = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
        if ($currentMax -ge 3) {
            Write-Log "INFO" "MaxTelemetryAllowed already set to $currentMax (optional+required); skipping"
        }
        else {
            RegistryShouldBe -KeyPath $dataCollectionPath -Name "MaxTelemetryAllowed" -Value 1
        }
        
        # Per-user: ShowedToastAtLevel = 1 across all user hives
        Write-Log "INFO" "Retrieving user profiles for per-user telemetry keys"
        $isSystem = Test-IsSystem
        
        if ($isSystem) {
            $hives = Get-UserHive -Type 'All' -IncludeDefault:([bool]$IncludeDefaultHive)
        }
        else {
            Write-Log "INFO" "Not running as SYSTEM; applying per-user key for current user only"
            $hives = @(
                [PSCustomObject]@{
                    Name     = $env:USERNAME
                    Domain   = $env:USERDOMAIN
                    SID      = 'CurrentUser'
                    UserHive = $null
                    Path     = $env:USERPROFILE
                }
            )
        }
        
        $loaded = @()
        
        foreach ($hive in $hives) {
            $sid      = $hive.SID
            $userHive = $hive.UserHive
            $label    = if ($hive.Name) { $hive.Name } else { $sid }
            
            if ($isSystem -and $sid -ne 'CurrentUser') {
                $regRoot = "HKEY_USERS\$sid"
                
                # Load hive if not mounted
                if (-not (Test-Path "Registry::$regRoot")) {
                    if ($userHive -and (Test-Path $userHive)) {
                        try {
                            Write-Log "VERBOSE" "Loading hive for $label"
                            reg.exe LOAD "HKEY_USERS\$sid" "$userHive" 2>&1 | Out-Null
                            $loaded += $sid
                        }
                        catch {
                            Write-Log "WARNING" "Failed to load hive for $label. Skipping."
                            continue
                        }
                    }
                    else {
                        Write-Log "WARNING" "Hive file not found for $label. Skipping."
                        continue
                    }
                }
                
                $diagPath = "Registry::$regRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
            }
            else {
                $diagPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
            }
            
            # ShowedToastAtLevel: skip if already >= 3
            $currentToast = (Get-ItemProperty -Path $diagPath -Name "ShowedToastAtLevel" -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty "ShowedToastAtLevel" -ErrorAction SilentlyContinue)
            if ($currentToast -ge 3) {
                Write-Log "INFO" "ShowedToastAtLevel for $label already $currentToast; skipping"
            }
            else {
                Write-Log "INFO" "Setting ShowedToastAtLevel for $label"
                RegistryShouldBe -KeyPath $diagPath -Name "ShowedToastAtLevel" -Value 1
            }
        }
        
        # Unload any hives we loaded
        if ($loaded.Count -gt 0) {
            foreach ($sid in $loaded) {
                [gc]::Collect()
                Start-Sleep -Seconds 1
                try {
                    Start-Process -FilePath "cmd.exe" `
                                -ArgumentList "/C reg.exe UNLOAD HKU\$sid" `
                                -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
                    Write-Log "VERBOSE" "Unloaded hive for $sid"
                }
                catch {
                    Write-Log "WARNING" "Failed to unload hive for $sid. $_"
                }
            }
        }
        
        Write-Log "SUCCESS" "Required telemetry configuration complete"
    }
    
    # Helper function: Remove telemetry enforcement keys (restore to OS defaults)
    function Remove-TelemetryEnforcement {
        Write-Log "INFO" "Removing telemetry enforcement keys (restoring to OS defaults)"
        
        $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        
        if (Test-Path $dataCollectionPath) {
            $collectionKey = Get-ItemProperty -Path $dataCollectionPath -ErrorAction SilentlyContinue
            
            if ($collectionKey.AllowTelemetry) {
                try {
                    Remove-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction Stop
                    Write-Log "SUCCESS" "Removed AllowTelemetry enforcement"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove AllowTelemetry: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log "INFO" "AllowTelemetry not present; nothing to remove"
            }
            
            if ($collectionKey.MaxTelemetryAllowed) {
                try {
                    Remove-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction Stop
                    Write-Log "SUCCESS" "Removed MaxTelemetryAllowed enforcement"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove MaxTelemetryAllowed: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log "INFO" "MaxTelemetryAllowed not present; nothing to remove"
            }
        }
        
        Write-Log "INFO" "Per-user ShowedToastAtLevel keys left as-is (default value is 1; no enforcement to remove)"
    }
    
    # Helper function: Set the Secure Boot opt-in gate AND trigger keys
    # Sets both MicrosoftUpdateManagedOptIn (opt-in gate) and AvailableUpdates (trigger bitmask)
    function Set-SecureBootOptInKeys {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $optInValue = 0x5944  # Microsoft Update managed opt-in magic value
        
        Write-Log "INFO" "Setting Secure Boot opt-in and trigger keys"
        RegistryShouldBe -KeyPath $regPath -Name "MicrosoftUpdateManagedOptIn" -Value $optInValue
        RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $optInValue
        Write-Log "SUCCESS" "Secure Boot opt-in keys set (MicrosoftUpdateManagedOptIn + AvailableUpdates = 0x5944)"
    }
    
    # Helper function: Remove the Secure Boot opt-in gate (opt out of Windows Update management)
    # Does NOT remove AvailableUpdates - already-triggered updates should complete
    function Remove-SecureBootOptInKeys {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $currentOptIn = (Get-ItemProperty -Path $regPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
        
        if ($currentOptIn) {
            try {
                Remove-ItemProperty -Path $regPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction Stop
                Write-Log "SUCCESS" "Removed MicrosoftUpdateManagedOptIn (opted out of Windows Update Secure Boot management)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove MicrosoftUpdateManagedOptIn: $($_.Exception.Message)"
            }
        }
        else {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn not present; already opted out"
        }
        
        Write-Log "INFO" "AvailableUpdates left as-is (already-triggered updates should complete)"
    }
    
    # Helper function: Get OEM manufacturer and matching key reset guide URL
    function Get-OemKeyResetGuide {
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS
            $manufacturer = $biosInfo.Manufacturer
            Write-Log "INFO" "BIOS Manufacturer: $manufacturer"
            
            if ($manufacturer -match "Dell") {
                return "https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios"
            }
            elseif ($manufacturer -match "HP|Hewlett-Packard") {
                return "https://support.hp.com/lv-en/document/ish_13070353-13070429-16"
            }
            elseif ($manufacturer -match "Lenovo") {
                return "https://pubs.lenovo.com/uefi_iot/secure_boot_config"
            }
            elseif ($manufacturer -match "ASUS") {
                return "https://www.asus.com/us/support/faq/1050047/"
            }
            elseif ($manufacturer -match "Microsoft") {
                return "https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e"
            }
            else {
                Write-Log "INFO" "No matching BIOS SecureBoot Key guide for manufacturer: $manufacturer"
                return $null
            }
        }
        catch {
            Write-Log "WARNING" "Failed to get BIOS manufacturer: $($_.Exception.Message)"
            return $null
        }
    }
    # Helper function: Get OEM manufacturer and matching key reset guide URL
    function Get-OemBIOSUpdateGuide {
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS
            $manufacturer = $biosInfo.Manufacturer
            Write-Log "INFO" "BIOS Manufacturer: $manufacturer"
            
            if ($manufacturer -match "Dell") {
                return "https://www.dell.com/support/kbdoc/en-us/000124211/dell-bios-updates"
            }
            elseif ($manufacturer -match "HP|Hewlett-Packard") {
                return "https://support.hp.com/us-en/document/ish_4129273-2331498-16"
            }
            elseif ($manufacturer -match "Lenovo") {
                return "https://support.lenovo.com/us/en/solutions/ht500008"
            }
            elseif ($manufacturer -match "ASUS") {
                return "https://www.asus.com/us/support/faq/1008276/"
            }
            elseif ($manufacturer -match "Microsoft") {
                return "https://support.microsoft.com/en-us/surface/download-drivers-and-firmware-for-surface-09bb2e09-2a4b-cb69-0951-078a7739e120"
                
            }
            else {
                Write-Log "INFO" "No matching BIOS Update guide for manufacturer: $manufacturer"
                return $null
            }
        }
        catch {
            Write-Log "WARNING" "Failed to get BIOS manufacturer: $($_.Exception.Message)"
            return $null
        }
    }
}

# =========================================
# PROCESS Block: Data Gathering & Logic
#   Steps 1–2.6: Secure Boot status, cert parsing, dbx cross-check,
#   event log, servicing registry, opt-in check, trigger logic
# =========================================
process {
    Write-Host "`n=== Secure Boot Certificate Status Check ==="
    
    # -----------------------------------------------
    # Step 1: Determine Secure Boot state
    # -----------------------------------------------
    Write-Log "INFO" "Checking Secure Boot UEFI status"
    $secureBoot = Get-SecureBootStatus
    Write-Log "INFO" "Secure Boot status: $secureBoot"
    
    # -----------------------------------------------
    # Step 1.5: If Enabled, parse db, KEK, and dbx certificates
    # -----------------------------------------------
    # The full set of 2023 certificates Microsoft is rotating to:
    #   db certs:  Windows UEFI CA 2023, Microsoft UEFI CA 2023, Microsoft Option ROM UEFI CA 2023
    #   KEK cert:  Microsoft Corporation KEK 2K CA 2023
    # KEK (Key Exchange Key) is the trust authority that authorizes writes to db.
    # When Windows Update pushes a signed update payload to write new certs into db,
    # the firmware verifies the payload signature against the KEK database.
    # If the 2023 KEK authority cert is missing, the firmware will reject the write
    # even if the UEFI attributes indicate db is runtime-writable.
    $updatedDbCertNames  = @(
        'Windows UEFI CA 2023',
        'Microsoft UEFI CA 2023',
        'Microsoft Option ROM UEFI CA 2023'
    )
    $updatedKekCertName  = 'Microsoft Corporation KEK 2K CA 2023'
    
    $has2023InDb        = $false
    $has2023InDbDefault = $false
    $has2023InKek       = $false
    $dbCertsFound       = @()   # Which 2023 db certs are present
    $scheduledTaskPresent = $false
    $dbIsOsWritable     = $false
    
    if ($secureBoot -eq 'Enabled') {
        # --- Parse db (allowed signatures) ---
        try {
            Write-Log "INFO" "Parsing db certificates"
            $dbBytes = (Get-SecureBootUEFI -Name db -ErrorAction Stop).Bytes
            $dbCerts = Parse-UefiSignatureDatabase -Bytes $dbBytes
            if ($dbCerts.Count -eq 0) {
                Write-Log "INFO" "No X509 certificates found in db"
            }
            else {
                foreach ($cert in $dbCerts) {
                    $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                    $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                    $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                    Write-Log "INFO" "db Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
                }
            }
        }
        catch {
            Write-Log "WARNING" "Failed to parse db: $($_.Exception.Message)"
        }
        
        # --- Parse KEK (key exchange keys - authorizes writes to db) ---
        try {
            Write-Log "INFO" "Parsing KEK certificates"
            $kekBytes = (Get-SecureBootUEFI -Name KEK -ErrorAction Stop).Bytes
            $kekCerts = Parse-UefiSignatureDatabase -Bytes $kekBytes
            if ($kekCerts.Count -eq 0) {
                Write-Log "INFO" "No X509 certificates found in KEK"
            }
            else {
                foreach ($cert in $kekCerts) {
                    $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                    $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                    $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                    Write-Log "INFO" "KEK Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
                }
            }
        }
        catch {
            Write-Log "WARNING" "Failed to parse KEK: $($_.Exception.Message)"
        }
        
        # --- Parse dbx (revocation list) ---
        try {
            Write-Log "INFO" "Parsing dbx certificates"
            $dbxBytes = (Get-SecureBootUEFI -Name dbx -ErrorAction Stop).Bytes
            $dbxCerts = Parse-UefiSignatureDatabase -Bytes $dbxBytes
            if ($dbxCerts.Count -eq 0) {
                Write-Log "INFO" "No X509 certificates found in dbx"
            }
            else {
                foreach ($cert in $dbxCerts) {
                    $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                    $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                    $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                    Write-Log "INFO" "dbx Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
                }
            }
        }
        catch {
            Write-Log "WARNING" "Failed to parse dbx: $($_.Exception.Message)"
        }
        
        # --- Cross-check: are any 2011 CAs revoked in DBX? (Stage 3 indicator) ---
        $ca2011RevokedInDbx = @()   # Which 2011 CAs appear in the revocation list
        try {
            $dbxRawText = [System.Text.Encoding]::ASCII.GetString($dbxBytes)
            $oldCAs = @(
                'Microsoft Corporation UEFI CA 2011'
                'Microsoft Windows Production PCA 2011'
            )
            foreach ($oldCA in $oldCAs) {
                if ($dbxRawText -match [regex]::Escape($oldCA)) {
                    $ca2011RevokedInDbx += $oldCA
                }
            }
            if ($ca2011RevokedInDbx.Count -gt 0) {
                Write-Log "INFO" "2011 CA revoked in dbx: $($ca2011RevokedInDbx -join ', ')"
            }
            else {
                Write-Log "INFO" "No 2011 CAs found in dbx (not yet revoked)"
            }
        }
        catch {
            Write-Log "WARNING" "Failed to cross-check 2011 CAs in dbx: $($_.Exception.Message)"
        }

        # --- Check for 2023 certs in db (check all 3 db-level certs) ---
        try {
            $dbRawText = [System.Text.Encoding]::ASCII.GetString($dbBytes)
            foreach ($certName in $updatedDbCertNames) {
                if ($dbRawText -match [regex]::Escape($certName)) {
                    $dbCertsFound += $certName
                }
            }
            $has2023InDb = $dbCertsFound.Count -gt 0
            if ($has2023InDb) {
                Write-Log "INFO" "2023 certs found in db: $($dbCertsFound -join ', ')"
            }
            else {
                Write-Log "INFO" "No 2023 certs found in db"
            }
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 certs in db: $($_.Exception.Message)"
        }
        
        # --- Check for 2023 KEK authority cert ---
        try {
            $kekRawText = [System.Text.Encoding]::ASCII.GetString($kekBytes)
            $has2023InKek = $kekRawText -match [regex]::Escape($updatedKekCertName)
            Write-Log "INFO" "2023 KEK authority cert ($updatedKekCertName): $(if ($has2023InKek) { 'Present' } else { 'Missing' })"
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 cert in KEK: $($_.Exception.Message)"
        }
        
        # --- If not in db, check dbDefault ---
        $dbDefaultCertsFound = @()   # Which 2023 certs are present in dbDefault
        if (-not $has2023InDb) {
            try {
                $dbDefaultBytes = (Get-SecureBootUEFI -Name dbDefault -ErrorAction Stop).Bytes
                $dbDefaultRawText = [System.Text.Encoding]::ASCII.GetString($dbDefaultBytes)
                foreach ($certName in $updatedDbCertNames) {
                    if ($dbDefaultRawText -match [regex]::Escape($certName)) {
                        $dbDefaultCertsFound += $certName
                    }
                }
                $has2023InDbDefault = $dbDefaultCertsFound.Count -gt 0
                if ($has2023InDbDefault) {
                    Write-Log "INFO" "2023 certs found in dbDefault: $($dbDefaultCertsFound -join ', ')"
                }
                else {
                    Write-Log "INFO" "No 2023 certs found in dbDefault"
                }
            }
            catch {
                Write-Log "WARNING" "Failed to check 2023 cert in dbDefault: $($_.Exception.Message)"
            }
        }
        
        # --- Check Secure-Boot-Update scheduled task existence ---
        Write-Host "`n === Secure Boot Update Task Check ==="
        if (Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\*" -TaskName "Secure-Boot-Update" -ErrorAction SilentlyContinue) {
            $scheduledTaskPresent = $true
            Write-Log "INFO" "Scheduled task '\Microsoft\Windows\PI\Secure-Boot-Update' is present"
        }
        else {
            Write-Log "WARNING" "Scheduled task '\Microsoft\Windows\PI\Secure-Boot-Update' is MISSING. Windows Update may not be able to apply Secure Boot certificate updates."
        }
        
        # --- Passive UEFI variable attributes check for 'db' ---
        Write-Host "`n === Windows UEFI DB Access Check ==="
        Write-Log "INFO" "Performing passive UEFI variable attributes check for 'db'"
        $dbAttributes = Get-UefiVariableAttributes -VarName "db"
        $uefiAllowsWrite = $null -ne $dbAttributes -and (($dbAttributes -band 0x00000004) -ne 0) -and (($dbAttributes -band 0x00000020) -ne 0)
        
        # db is truly OS-writable only if UEFI attributes allow it AND the 2023 KEK authority is present
        # (KEK authorizes the signed payload Windows Update uses to write to db)
        if ($uefiAllowsWrite -and $has2023InKek) {
            $dbIsOsWritable = $true
            Write-Log "INFO" "OS capable of writing to UEFI db: True (UEFI attributes + KEK authority both present)"
        }
        elseif ($uefiAllowsWrite -and -not $has2023InKek) {
            $dbIsOsWritable = $false
            Write-Log "WARNING" "UEFI attributes allow runtime writes, but 2023 KEK authority cert is missing. Windows Update cannot sign the payload - db is NOT effectively OS-writable."
        }
        else {
            $dbIsOsWritable = $false
            Write-Log "INFO" "OS capable of writing to UEFI db: False"
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2: Query event log (only when Secure Boot is Enabled)
    # -----------------------------------------------
    $certStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Log "INFO" "Secure Boot is enabled; querying event log for certificate update events"
        $certStatus = Get-CertUpdateEventStatus
        
        # Clarify when the event status contradicts actual cert state
        if ($certStatus.Status -eq 'ActionRequired' -and $has2023InDb) {
            Write-Log "INFO" "Certificate event status: Stale 1801 - 2023 cert is already in db; OS has not yet acknowledged via 1808"
        }
        else {
            Write-Log "INFO" "Certificate event status: $($certStatus.Status) - $($certStatus.EventMessage)"
        }
    }
    else {
        Write-Log "INFO" "Skipping event log check (Secure Boot is $secureBoot)"
    }
    
    # -----------------------------------------------
    # Step 2.1: Read Secure Boot servicing registry (only when Secure Boot is Enabled)
    # -----------------------------------------------
    $servicingStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host "`n === Secure Boot Servicing Registry ==="
        $servicingStatus = Get-SecureBootServicingStatus
        
        if ($null -ne $servicingStatus.UEFICA2023Status) {
            Write-Log "INFO" "UEFICA2023Status: $($servicingStatus.UEFICA2023Status)"
        }
        else {
            Write-Log "INFO" "UEFICA2023Status: Not set"
        }
        
        if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
            $capableDesc = switch ($servicingStatus.WindowsUEFICA2023Capable) {
                1 { 'Cert in DB' }
                2 { 'Cert in DB + booting from 2023 boot manager' }
                default { 'Cert not in DB' }
            }
            Write-Log "INFO" "WindowsUEFICA2023Capable: $($servicingStatus.WindowsUEFICA2023Capable) ($capableDesc)"
        }
        
        if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
            Write-Log "WARNING" "UEFICA2023Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
        }
        
        if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
            Write-Log "INFO" "UEFICA2023ErrorEvent: $($servicingStatus.UEFICA2023ErrorEvent) - $($servicingStatus.UEFICA2023ErrorEventDesc)"
        }
        
        if ($null -ne $servicingStatus.CanAttemptUpdateAfter) {
            $updateAfterStr = $servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm')
            if ($servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                Write-Log "WARNING" "CanAttemptUpdateAfter: $updateAfterStr (update delayed until this time)"
            }
            else {
                Write-Log "INFO" "CanAttemptUpdateAfter: $updateAfterStr (past - update can proceed)"
            }
        }
        
        # Use UEFICA2023Status as supplemental compliance signal
        if ($servicingStatus.UEFICA2023Status -eq 'Updated' -and $certStatus -and $certStatus.Status -ne 'Compliant') {
            Write-Log "INFO" "Servicing registry reports 'Updated' but event log status is '$($certStatus.Status)' - servicing confirms compliance"
        }
        
        # Log device attributes if available
        if ($null -ne $servicingStatus.OEMManufacturerName) {
            Write-Log "INFO" "OEM: $($servicingStatus.OEMManufacturerName) | Model: $($servicingStatus.OEMModelNumber) | FW: $($servicingStatus.FirmwareVersion)"
        }
        
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.25: Execute SecureBootAction if specified
    # -----------------------------------------------
    if ($SecureBootAction) {
        Write-Host "`n === Secure Boot Action: $SecureBootAction ==="
        
        if ($secureBoot -ne 'Enabled') {
            Write-Log "WARNING" "Secure Boot is '$secureBoot'; action '$SecureBootAction' requires Secure Boot to be enabled. Skipping action."
        }
        else {
            switch ($SecureBootAction) {
                'Enable opt-in for SecureBoot management' {
                    # Note if already compliant
                    if ($certStatus -and $certStatus.EventId -eq 1808) {
                        Write-Log "INFO" "Event 1808 already present (compliant). Enablement is not strictly necessary, but proceeding to ensure keys are set."
                    }
                    
                    # 1. Set required telemetry (machine + per-user)
                    Enable-RequiredTelemetry
                    
                    # 2. Set opt-in gate + trigger keys
                    Set-SecureBootOptInKeys
                    
                    # 3. Trigger Secure-Boot-Update scheduled task to kick off the update
                    Trigger-SecureBootTask
                    
                    Write-Log "SUCCESS" "Secure Boot opt-in, telemetry enablement, and scheduled-task run complete"
                }
                'Remove opt-in for SecureBoot management' {
                    if ($certStatus -and $certStatus.EventId -eq 1808) {
                        Write-Log "INFO" "Event 1808 present (compliant). Removal will opt out of future WU-managed updates, but the current cert rotation is already complete."
                    }
                    
                    # 1. Remove telemetry enforcement
                    Remove-TelemetryEnforcement
                    
                    # 2. Remove opt-in gate (leave AvailableUpdates alone)
                    Remove-SecureBootOptInKeys
                    
                    Write-Log "SUCCESS" "Secure Boot opt-out and telemetry enforcement removal complete"
                }
                'Audit SecureBoot management status' {
                    Write-Log "INFO" "Auditing Secure Boot management configuration (read-only)"
                    
                    # --- Machine-level telemetry ---
                    $dataCollectionPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
                    $allowTelemetry = (Get-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue |
                                       Select-Object -ExpandProperty "AllowTelemetry" -ErrorAction SilentlyContinue)
                    $maxTelemetry   = (Get-ItemProperty -Path $dataCollectionPath -Name "MaxTelemetryAllowed" -ErrorAction SilentlyContinue |
                                       Select-Object -ExpandProperty "MaxTelemetryAllowed" -ErrorAction SilentlyContinue)
                    
                    if ($null -eq $allowTelemetry) {
                        Write-Log "INFO" "AllowTelemetry: Not set (OS default)"
                    }
                    else {
                        $telemetryLabel = switch ($allowTelemetry) { 0 { 'Off' } 1 { 'Required' } 2 { 'Enhanced' } 3 { 'Full' } default { $allowTelemetry } }
                        Write-Log "INFO" "AllowTelemetry: $allowTelemetry ($telemetryLabel)"
                    }
                    
                    if ($null -eq $maxTelemetry) {
                        Write-Log "INFO" "MaxTelemetryAllowed: Not set (OS default)"
                    }
                    else {
                        $maxLabel = switch ($maxTelemetry) { 0 { 'Off' } 1 { 'Required' } 2 { 'Enhanced' } 3 { 'Full' } default { $maxTelemetry } }
                        Write-Log "INFO" "MaxTelemetryAllowed: $maxTelemetry ($maxLabel)"
                    }
                    
                    $telemetryMeetsMin = ($null -ne $allowTelemetry -and $allowTelemetry -ge 1) -or ($null -eq $allowTelemetry)
                    if (-not $telemetryMeetsMin) {
                        Write-Log "WARNING" "AllowTelemetry is 0 (Off) - Windows Update cannot manage Secure Boot certs"
                    }
                    
                    # --- Secure Boot opt-in keys ---
                    $secureBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
                    $optIn = (Get-ItemProperty -Path $secureBootPath -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue |
                              Select-Object -ExpandProperty "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue)
                    $available = (Get-ItemProperty -Path $secureBootPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue |
                                  Select-Object -ExpandProperty "AvailableUpdates" -ErrorAction SilentlyContinue)
                    
                    if ($optIn -eq 0x5944) {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: 0x5944 (Opted in to Windows Update Secure Boot management)"
                    }
                    elseif ($null -eq $optIn) {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: Not set (not opted in)"
                    }
                    else {
                        Write-Log "INFO" "MicrosoftUpdateManagedOptIn: $optIn (unexpected value)"
                    }
                    
                    if ($available -eq 0x5944) {
                        Write-Log "INFO" "AvailableUpdates: 0x5944 (update trigger set)"
                    }
                    elseif ($null -eq $available) {
                        Write-Log "INFO" "AvailableUpdates: Not set (no trigger)"
                    }
                    else {
                        Write-Log "INFO" "AvailableUpdates: $available"
                    }
                    
                    # --- Summary ---
                    $isOptedIn = $optIn -eq 0x5944
                    if ($isOptedIn -and $telemetryMeetsMin) {
                        Write-Log "SUCCESS" "Secure Boot management via Windows Update: ENABLED (opted in + telemetry meets minimum)"
                    }
                    elseif ($isOptedIn -and -not $telemetryMeetsMin) {
                        Write-Log "WARNING" "Secure Boot management via Windows Update: OPT-IN SET but telemetry is too low (AllowTelemetry=0)"
                    }
                    else {
                        Write-Log "INFO" "Secure Boot management via Windows Update: NOT ENABLED (opt-in key not set)"
                    }
                }
            }
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.3: Check opt-in status (always, after any action has run)
    # -----------------------------------------------
    $optInStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host "`n === Opt-In Status Check ==="
        $optInStatus = Check-OptInStatus
        
        $telemetryLabel = if ($null -eq $optInStatus.AllowTelemetry) { 'Not set (OS default)' }
                          else { switch ($optInStatus.AllowTelemetry) { 0 { '0 (Off)' } 1 { '1 (Required)' } 2 { '2 (Enhanced)' } 3 { '3 (Full)' } default { $optInStatus.AllowTelemetry } } }
        Write-Log "INFO" "AllowTelemetry: $telemetryLabel"
        
        if ($optInStatus.IsOptedIn) {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn: 0x5944 (opted in)"
        }
        else {
            Write-Log "INFO" "MicrosoftUpdateManagedOptIn: $(if ($null -eq $optInStatus.OptInValue) { 'Not set' } else { $optInStatus.OptInValue }) (not opted in)"
        }
        
        if ($optInStatus.AvailableUpdatesSet) {
            $avHex = '0x{0:X}' -f $optInStatus.AvailableUpdates
            Write-Log "INFO" "AvailableUpdates: $avHex (trigger set)"
        }
        else {
            Write-Log "INFO" "AvailableUpdates: $(if ($null -eq $optInStatus.AvailableUpdates) { 'Not set' } else { $optInStatus.AvailableUpdates })"
        }
        
        # AvailableUpdatesPolicy (GPO/MDM-driven, persists across reboots)
        if ($optInStatus.AvailableUpdatesPolicySet) {
            $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
            Write-Log "INFO" "AvailableUpdatesPolicy: $apHex (GPO/MDM policy set)"
        }
        elseif ($null -ne $optInStatus.AvailableUpdatesPolicy) {
            Write-Log "INFO" "AvailableUpdatesPolicy: $($optInStatus.AvailableUpdatesPolicy)"
        }
        
        # HighConfidenceOptOut
        if ($null -ne $optInStatus.HighConfidenceOptOut) {
            if ($optInStatus.HighConfidenceOptOut -ne 0) {
                Write-Log "WARNING" "HighConfidenceOptOut: $($optInStatus.HighConfidenceOptOut) - device is opted OUT of auto-deployment"
            } else {
                Write-Log "INFO" "HighConfidenceOptOut: 0 (not opted out)"
            }
        }
        
        # Decoded bitmask meaning
        if ($optInStatus.AvailableUpdatesMeaning.Count -gt 0 -and $optInStatus.EffectiveAvailable -ne 0) {
            Write-Log "INFO" "Requested updates: $($optInStatus.AvailableUpdatesMeaning -join '; ')"
        }
        
        switch ($optInStatus.Summary) {
            'Enabled'     { Write-Log "SUCCESS" "Windows Update Secure Boot management: Enabled" }
            'Blocked'     { Write-Log "WARNING" "Windows Update Secure Boot management: Opted in but telemetry too low (AllowTelemetry=0)" }
            'Not enabled' { Write-Log "INFO" "Windows Update Secure Boot management: Not enabled (opt-in key not set)" }
        }
        Write-Host ""
    }
    
    # -----------------------------------------------
    # Step 2.5: Automate registry trigger if needed
    # -----------------------------------------------
    $triggeredOsUpdate = $false
    $postTriggerState  = $null
    # Trigger conditions (when servicing hasn't already confirmed Updated):
    #   A) 2023 cert is in db but OS hasn't confirmed via 1808 (stale 1801 or no events)
    #   B) Cert in dbDefault, KEK missing, no Event 1803 blocker — opt-in can push KEK + certs
    # Skip trigger if 1800 (reboot required) or 1799 (boot manager installed) - these are in-progress states
    # that re-triggering cannot advance; they need time, sometimes up to 9+ days
    $servicingAlreadyUpdated = ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated')
    $has1803InLog = ($null -ne $certStatus -and $null -ne $certStatus.AllEvents -and @($certStatus.AllEvents | Where-Object { $_.Id -eq 1803 }).Count -gt 0)
    $canTrigger = $secureBoot -eq 'Enabled' -and -not $servicingAlreadyUpdated -and $certStatus.EventId -notin @(1808, 1800, 1799)
    $triggerReasonA = $canTrigger -and $has2023InDb
    $triggerReasonB = $canTrigger -and -not $has2023InDb -and ($has2023InDbDefault -or -not $has2023InKek) -and -not $has1803InLog
    if ($triggerReasonA -or $triggerReasonB) {
        if ($triggerReasonA -and $certStatus.Status -eq 'ActionRequired') {
            Write-Log "INFO" "2023 cert in db but stale 1801; attempting to trigger OS update"
        }
        elseif ($triggerReasonA) {
            Write-Log "INFO" "2023 cert in db but no events logged; attempting to trigger OS update"
        }
        else {
            Write-Log "INFO" "KEK/certs missing (no 1803 blocker); setting opt-in to let Windows Update push KEK + certs"
        }
        $setReg     = Set-SecureBootUpdateRegKey
        $appliedWcs = Apply-WinCsFeatureKey
        $triggeredOsUpdate = $setReg -or $appliedWcs
        if ($triggeredOsUpdate) {
            $taskTriggered = Trigger-SecureBootTask
            if ($taskTriggered) {
                Write-Log "INFO" "Waiting 60 seconds to check for post-trigger events"
                Start-Sleep -Seconds 60
                $postTriggerState = Check-PostTriggerEvents -Minutes 2  # Check last 2 min for safety
                Write-Log "INFO" "Post-trigger event state: $postTriggerState"
                
                # Re-check servicing registry - it's the definitive signal
                $postTriggerServicing = Get-SecureBootServicingStatus
                if ($postTriggerServicing.UEFICA2023Status -eq 'Updated') {
                    Write-Log "INFO" "Servicing registry now reports 'Updated' - overriding to Compliant"
                    $postTriggerState = 'Compliant'
                    $servicingStatus  = $postTriggerServicing
                }
            }
        }
    }
    
    # -----------------------------------------------
    # Step 2.6: 1799 without 1808 — informational note
    #           Servicing confirms Updated but 1808 hasn't appeared in the event log.
    #           The Secure-Boot-Update task runs at startup + every 12 hours and will
    #           produce 1808 on its next cycle. No action needed — just annotate.
    # -----------------------------------------------
    $pending1808Note = $false
    if ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1799 -and $servicingAlreadyUpdated) {
        $pending1808Note = $true
        Write-Log "INFO" "Event 1799 is latest, servicing confirms Updated — 1808 expected on next scheduled task cycle"
    }
    
}

# =========================================
# END Block: State Mapping, Card Building & Output
#   Steps 3–6: Final state resolution, HTML/local card,
#   NinjaRMM custom field writes, console summary
# =========================================
end {
    # -----------------------------------------------
    # Step 3: Map to one of the 7 final states
    # -----------------------------------------------
    # Pre-compute cert labels for clear messaging
    $dbCertLabel = if ($dbCertsFound.Count -gt 0) {
        ($dbCertsFound | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
    }
    else { 'None' }
    $dbDefaultCertLabel = if ($dbDefaultCertsFound.Count -gt 0) {
        ($dbDefaultCertsFound | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
    }
    else { 'None' }
    
    $cardIcon        = "fas fa-shield-alt"  # Same icon for all states; color differentiates them
    $eventRowHtml    = $null                # Omitted unless Secure Boot is Enabled
    
    switch ($true) {
      
        # State 1: Not Applicable (non-UEFI / unsupported hardware)
        ($secureBoot -eq 'NotApplicable') {
            $statusKey     = 'NotApplicable'
            $cardIconColor = '#6C757D'
            $statusRowHtml = '<i class="fas fa-ban" style="color:#6C757D;"></i> Not Applicable'
            $detailRowHtml = 'This machine does not support UEFI Secure Boot<br />(Legacy BIOS or unsupported environment).<br />Certificate update compliance is not applicable.'
            $plainText     = '[N/A] Secure Boot not supported (non-UEFI). Certificate check skipped.'
            $statusEmoji = '❔'
            break
        }
        
        # State 2: Disabled (UEFI capable but Secure Boot is off)
        ($secureBoot -eq 'Disabled') {
            $statusKey     = 'Disabled'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Disabled'
            $detailRowHtml = 'UEFI Secure Boot is supported but currently disabled.<br />Certificate rotation compliance is not applicable<br />until Secure Boot is enabled.'
            $plainText     = '⚠️ Secure Boot disabled. Certificate update check not applicable until Secure Boot is enabled.'
            $statusEmoji = '⚠️'
            break
        }
        
        # State 3: Compliant (Secure Boot enabled + Event 1808 found OR UEFICA2023Status == Updated)
        ($secureBoot -eq 'Enabled' -and ($certStatus.Status -eq 'Compliant' -or ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated'))) {
            $statusKey     = 'Compliant'
            $cardIconColor = '#26A644'
            
            # Check if some certs are still missing (pending reboot to apply)
            $missingDbCerts = @($updatedDbCertNames | Where-Object { $dbCertsFound -notcontains $_ })
            $hasPending1800 = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
            $certsPendingReboot = ($missingDbCerts.Count -gt 0 -and $hasPending1800)
            
            if ($certsPendingReboot) {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant <span style="color:#F0AD4E;">(reboot pending)</span>'
                $missingShort  = ($missingDbCerts | ForEach-Object { $_ -replace 'Microsoft ', '' -replace 'Windows ', '' }) -join ', '
                $detailRowHtml = "2023 Secure Boot update confirmed by servicing registry.<br />Pending reboot to apply remaining certs:<br />    $missingShort"
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Servicing: Updated <span style="color:#F0AD4E;">| Latest event: 1800 (reboot required)</span>'
                $plainText     = "✅ Secure Boot Enabled. Compliant (UEFICA2023Status=Updated). Reboot pending for $($missingDbCerts.Count) cert(s)."
            }
            elseif ($certStatus.Status -eq 'Compliant') {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.<br />No action required.'
                $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event 1808 detected at ' + $eventTime
                $plainText     = '✅ Secure Boot Enabled. Certificates up to date in BIOS (Event 1808). Compliant.'
            }
            else {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.<br />No action required.'
                # Compliant via servicing registry (UEFICA2023Status=Updated) without Event 1808 in log
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Servicing status: Updated'
                $plainText     = '✅ Secure Boot Enabled. Certificates up to date (UEFICA2023Status=Updated). Compliant.'
            }
            $statusEmoji = '✅'
            break
        }
        
        # State 4: Action Required (Secure Boot enabled + Event 1801 found)
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'ActionRequired') {
            $statusKey     = 'ActionRequired'
            $cardIconColor = '#D9534F'
            $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#D9534F;"></i> Event 1801 detected at ' + $eventTime
            
            $oemKeyGuide = Get-OemKeyResetGuide
            $bitlockerNote = '<br /><br />Suspend BitLocker or have recovery keys handy for <br />each enabled volume before resetting keys.'
            $bitlockerNotePlain = " Suspend BitLocker or have recovery keys for each enabled volume before resetting keys."
            
            if ($oemKeyGuide) {
                $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
                $guidePlain = "`nSee BIOS Secure Boot key guide in Status Card." 
            }
            else {
                $guideHtml = ''
                $guidePlain = ''
            }
            
            if ($has2023InDb) {
                $detailRowHtml = 'Windows has applied 2023 Secure Boot certificates<br />but the OS-side validation is stuck on 1801.<br />2023 certs in db; OS update triggered via reg key<br />to resolve before June 2026 deadline.'
                $plainText     = '❌ Secure Boot Enabled. 2023 certs in db but OS stuck on 1801; triggered reg update. Pending Windows Update rotation'
            }
            elseif ($has2023InDbDefault) {
                # Check for Event 1803 (PK-signed KEK not available) — the definitive OEM blocker
                $has1803 = ($null -ne $certStatus.AllEvents -and @($certStatus.AllEvents | Where-Object { $_.Id -eq 1803 }).Count -gt 0)
                
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable — Windows Update will handle it
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />but not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = "⚠️ Secure Boot Enabled. dbDefault has $dbDefaultCertLabel; Windows will push to db, or reset keys to apply now."
                    $statusEmoji = '⚠️'
                }
                elseif ($has1803) {
                    # Event 1803 confirms OEM has NOT provided a PK-signed KEK
                    # This is a genuine blocker — key reset or OEM firmware update required
                    $detailRowHtml = "KEK 2K CA 2023 not available — OEM has not provided a<br />PK-signed KEK update (Event 1803).<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Wait for OEM firmware update that includes KEK 2023<br />• Reset Secure Boot keys in BIOS to apply from defaults" + $bitlockerNote + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required.'
                }
                else {
                    # KEK missing but no 1803 — Windows Update may be able to push the KEK
                    # via the 0x4004 bit in AvailableUpdates. Opt-in is the first step.
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in (0x4004 bit)."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in yet.</b> Run this script in Update mode<br />to enable opt-in and trigger the KEK + cert deployment.'
                        $plainText     = "⚠️ Secure Boot Enabled. dbDefault: $dbDefaultCertLabel. KEK 2023 pending. Not opted in — run Update mode."
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = "⚠️ Secure Boot Enabled. dbDefault: $dbDefaultCertLabel. KEK 2023 pending. Opted in — waiting for WU."
                    }
                    $statusEmoji = '⚠️'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault - firmware update or OS-driven update needed
                $has1803 = ($null -ne $certStatus.AllEvents -and @($certStatus.AllEvents | Where-Object { $_.Id -eq 1803 }).Count -gt 0)
                $oemBiosGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosGuide) {
                    $biosGuideHtml = '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $biosGuideHtml = ''
                }
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable — Windows Update will handle everything
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update will eventually push the cert automatically,<br />or a manual BIOS update can be applied.' + $biosGuideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing; Windows will eventually update the BIOS db directly, or push a BIOS update if available.'
                    $statusEmoji = '⚠️'
                }
                elseif ($has1803) {
                    # Event 1803 confirms OEM blocker — KEK not available, cert not in defaults
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />OEM has not provided a PK-signed KEK update (Event 1803).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support. Update before June 2026.' + $biosGuideHtml
                    $plainText     = '❌ Secure Boot Enabled. 2023 cert missing, OEM KEK not available (1803). BIOS update required.'
                    $statusEmoji = '❌'
                }
                else {
                    # No cert in db/dbDefault but no 1803 either — opt-in may resolve via Windows Update
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br /><br /><b>Not opted in yet.</b> Run this script in Update mode<br />to enable opt-in. Windows Update may deliver KEK + certs.' + $biosGuideHtml
                        $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing, KEK missing. Not opted in — run Update mode to enable.'
                    }
                    else {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br />Opt-in is enabled — Windows Update may deliver KEK + certs.<br />If no progress, a BIOS update may be needed.' + $biosGuideHtml
                        $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing, KEK missing. Opted in — waiting for WU. BIOS update may be needed.'
                    }
                    $statusEmoji = '⚠️'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            break
        }
        
        # State 5a: Pending Reboot (Event 1800 - reboot required to continue)
        ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1800 -and -not $postTriggerState) {
            $statusKey     = 'Pending'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Reboot'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-redo" style="color:#F0AD4E;"></i> Event 1800 detected at ' + $eventTime
            $detailRowHtml = 'Secure Boot certificate update is in progress.<br />A system reboot is required to continue the update.<br />Reboot the machine to allow the update to proceed.'
            $plainText     = '⚠️ Secure Boot Enabled. Reboot required to continue certificate update (Event 1800).'
            $statusEmoji   = '⚠️'
            $rebootStatus  = Get-PendingRebootStatus
            if ($rebootStatus.Pending) {
                $sourceList = $rebootStatus.Sources -join ', '
                $detailRowHtml += '<br /><br />Reboot pending from: ' + $sourceList
            }
            break
        }
        
        # State 5b: Pending (Secure Boot enabled, no state events or only non-state events)
        # Sub-branches based on whether 2023 cert exists in db or dbDefault
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Pending' -and -not $postTriggerState) {
            $eventRowHtml  = '<i class="fas fa-search" style="color:#F0AD4E;"></i> No certificate update events (1808/1801) found'
            
            if ($has2023InDb) {
                # 2023 cert already in active db but no events logged - possibly pre-installed by firmware or manually added
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = '2023 Secure Boot certificate is present in the active db<br />but no completion events (1808/1801) were logged.<br />Cert may have been pre-installed by firmware.<br />Awaiting Windows Update to finalize validation.'
                $plainText     = '⚠️ Secure Boot Enabled. 2023 cert in db but no events logged. Waiting for Windows Update to finalize. Pending probable reboot.'
            }
            elseif ($has2023InDbDefault) {
                # 2023 cert in firmware defaults but not deployed - Windows Update or key reset can resolve
                $oemKeyGuide = Get-OemKeyResetGuide
                $bitlockerNote = '<br /><br />Suspend BitLocker or have recovery keys handy for <br />each enabled volume before resetting keys.'
                $bitlockerNotePlain = " Suspend BitLocker or have recovery keys for each enabled volume before resetting keys."
                if ($oemKeyGuide) {
                    $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
                    $guidePlain = "`nSee BIOS Secure Boot key guide in Status Card"
                }
                else {
                    $guideHtml = ''
                    $guidePlain = ''
                }
                $cardIconColor = '#F0AD4E'
                # Check for Event 1803 (PK-signed KEK not available)
                $has1803 = ($null -ne $certStatus.AllEvents -and @($certStatus.AllEvents | Where-Object { $_.Id -eq 1803 }).Count -gt 0)
                
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = "⚠️ Secure Boot Enabled. dbDefault: $dbDefaultCertLabel; Windows will push to db, or reset keys to apply now."
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - Windows capable of updating BIOS db'
                }
                elseif ($has1803) {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = "KEK 2K CA 2023 not available — OEM has not provided a<br />PK-signed KEK update (Event 1803).<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Wait for OEM firmware update that includes KEK 2023<br />• Reset Secure Boot keys in BIOS to apply from defaults" + $bitlockerNote + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required.'
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> Event 1803 - OEM KEK blocker'
                    $statusEmoji = '❌'
                }
                else {
                    # KEK missing but no 1803 — opt-in can push KEK
                    $statusKey     = 'Pending'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in yet.</b> Run this script in Update mode<br />to enable opt-in and trigger the KEK + cert deployment.'
                        $plainText     = "⚠️ Secure Boot Enabled. dbDefault: $dbDefaultCertLabel. KEK pending. Not opted in — run Update mode."
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = "⚠️ Secure Boot Enabled. dbDefault: $dbDefaultCertLabel. KEK pending. Opted in — waiting for WU."
                    }
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - KEK pending via Windows Update'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault - firmware update or OS-driven update needed
                $oemBiosUpdateGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosUpdateGuide) {
                    $guideHtml = '<br /><a href="' + $oemBiosUpdateGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $guideHtml = ''
                }
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update may push the cert automatically,<br />or a manual BIOS update can be applied.' + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing; Windows can update BIOS db directly, or push BIOS update.'
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - Windows capable of updating BIOS db'
                    $statusEmoji = '⚠️'
                }
                else {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support before Windows Update<br />can complete the rotation. Update before June 2026.' + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. 2023 cert missing from db and dbDefault. OEM BIOS/firmware update required.'
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> No events - BIOS lacks 2023 certificate support'
                    $statusEmoji = '❌'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            break
        }
        
        # Fallback: unexpected state combination
        default {
            $statusKey     = 'Unknown'
            $cardIconColor = '#6C757D'
            $statusRowHtml = '<i class="fas fa-question-circle" style="color:#6C757D;"></i> Unknown'
            $detailRowHtml = 'An unexpected state was encountered. Review script output for details.'
            $plainText     = '❔ Secure Boot certificate status could not be determined.'
            $statusEmoji = '❔'
        }
    }
    
    # Override for triggered OS update based on post-trigger state
    # Servicing registry is re-checked after trigger - if it says Updated, that's definitive.
    if ($postTriggerState) {
        switch ($postTriggerState) {
            'Compliant' {
                # Servicing confirmed Updated, or 1808 appeared
                $statusKey     = 'Compliant'
                $cardIconColor = '#26A644'
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = 'Triggered OS-side update.<br />2023 certificates successfully applied to BIOS firmware.<br />No action required.'
                $plainText     = '✅ Secure Boot Enabled. Triggered OS update; confirmed compliant. Certificates up to date.'
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Confirmed compliant after trigger'
                $statusEmoji = '✅'
            }
            'Pending1808' {
                # 1799 found - update is in progress
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = 'Triggered OS-side update.<br />Boot manager installed (Event 1799).<br />Update in progress - servicing will confirm when complete.'
                $plainText     = '⚠️ Secure Boot Enabled. Triggered OS update; boot manager installed. Update in progress.'
                $eventRowHtml  = '<i class="fas fa-cog" style="color:#F0AD4E;"></i> Boot manager installed; update in progress'
                $statusEmoji = '⚠️'
            }
            default {
                # No events yet - update may need a reboot to proceed
                $rebootStatus = Get-PendingRebootStatus
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusEmoji = '⚠️'
                if ($rebootStatus.Pending) {
                    $sourceList = $rebootStatus.Sources -join ', '
                    Write-Log "INFO" "Reboot pending from: $sourceList"
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Reboot'
                    $detailRowHtml = 'Triggered OS-side update.<br />A system reboot is pending (' + $sourceList + ').<br />Reboot may be required before update can proceed.'
                    $plainText     = '⚠️ Secure Boot Enabled. Triggered OS update; reboot pending (' + $sourceList + ').'
                    if ($plainText.Length -gt 200) {
                        $plainText = $plainText.Substring(0, 197) + '...'
                    }
                    $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Triggered - reboot pending (' + $sourceList + ')'
                }
                else {
                    Write-Log "INFO" "No pending reboot detected; update may still be processing"
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = 'Triggered OS-side update.<br />Update is processing - servicing will confirm when complete.'
                    $plainText     = '⚠️ Secure Boot Enabled. Triggered OS update; processing.'
                    $eventRowHtml  = '<i class="fas fa-cog" style="color:#F0AD4E;"></i> Triggered - processing'
                }
            }
        }
    }
    
    Write-Log "INFO" "Resolved final state: $statusKey"
    
    # -----------------------------------------------
    # Step 4: Build the HTML status card
    # -----------------------------------------------
    $cardProperties = [ordered]@{
        'Secure Boot' = $statusRowHtml
        'Detail'      = $detailRowHtml
    }
    if ($null -ne $eventRowHtml) {
        $cardProperties['Last Event'] = $eventRowHtml
    }
    # Event log summary (deployment timeline)
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $certStatus.EventSummary.Count -gt 0) {
        $summaryLines = @()
        foreach ($entry in ($certStatus.EventSummary | Sort-Object FirstSeen)) {
            $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
            # Color-code by event type
            $color = switch ($entry.Id) {
                1808  { '#26A644' }  # green - compliant
                1801  { '#D9534F' }  # red - action required
                1800  { '#F0AD4E' }  # amber - reboot needed
                1032  { '#D9534F' }  # red - blocker
                1033  { '#D9534F' }  # red - blocker
                1795  { '#D9534F' }  # red - firmware error
                1796  { '#D9534F' }  # red - unexpected error
                1797  { '#D9534F' }  # red - prerequisite failure
                1798  { '#D9534F' }  # red - boot mgr not signed
                1802  { '#D9534F' }  # red - blocked by known issue
                1803  { '#D9534F' }  # red - OEM KEK issue
                default { '#5BC0DE' } # blue - deployment progress
            }
            $summaryLines += "<span style='color:$color;'>$timeStr &nbsp; [$($entry.Id)] $($entry.Description) ($($entry.Count)x)</span>"
        }
        # Inject reboot correlation annotation if 1800 → reboot → 1799 was detected
        if ($null -ne $certStatus.RebootCorrelation) {
            $rc = $certStatus.RebootCorrelation
            if ($rc.Confirmed) {
                $bootTimeStr = $rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                $summaryLines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;<i class='fas fa-sync-alt' style='color:#5BC0DE;'></i> Reboot at $bootTimeStr bridged 1800 &rarr; 1799</span>"
            }
            else {
                $summaryLines += "<span style='color:#F0AD4E;'>&nbsp;&nbsp;&nbsp;<i class='fas fa-question-circle' style='color:#F0AD4E;'></i> 1800 &rarr; 1799 detected but no reboot found between them</span>"
            }
        }
        # Inject 1799 pending-1808 note
        if ($pending1808Note) {
            $summaryLines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;<i class='fas fa-info-circle' style='color:#5BC0DE;'></i> 1808 expected on next scheduled task cycle</span>"
        }
        $cardProperties['Event Log'] = $summaryLines -join '<br />'
    }
    # Certificate inventory (all four 2023 certs - only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        $certLines = @()
        # db certs
        foreach ($certName in $updatedDbCertNames) {
            $present = $dbCertsFound -contains $certName
            $icon    = if ($present) { '<i class="fas fa-check-circle" style="color:#26A644;"></i>' } else { '<i class="fas fa-times-circle" style="color:#D9534F;"></i>' }
            $label   = ($certName -replace 'Microsoft Corporation ', '' -replace 'Microsoft ', '')
            $certLines += "$icon $label"
        }
        # KEK cert
        $kekIcon = if ($has2023InKek) { '<i class="fas fa-check-circle" style="color:#26A644;"></i>' } else { '<i class="fas fa-times-circle" style="color:#D9534F;"></i>' }
        $certLines += "$kekIcon KEK 2K CA 2023"
        # 2011 CA revocation status (Stage 3)
        if ($ca2011RevokedInDbx.Count -gt 0) {
            foreach ($revokedCA in $ca2011RevokedInDbx) {
                $rLabel = $revokedCA -replace 'Microsoft Corporation ', '' -replace 'Microsoft ', ''
                $certLines += "<i class='fas fa-ban' style='color:#5BC0DE;'></i> $rLabel <span style='color:#888;'>(revoked in dbx)</span>"
            }
        }
        $cardProperties['Certificates'] = $certLines -join '<br />'
    }
    # Servicing status (only when Secure Boot is Enabled and servicing data exists)
    if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
        $servParts = @()
        # UEFICA2023Status
        if ($null -ne $servicingStatus.UEFICA2023Status) {
            $servIcon = if ($servicingStatus.UEFICA2023Status -eq 'Updated') { '<i class="fas fa-check-circle" style="color:#26A644;"></i>' } else { '<i class="fas fa-info-circle" style="color:#F0AD4E;"></i>' }
            $servParts += "$servIcon Service Status: $($servicingStatus.UEFICA2023Status)"
        }
        if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
            $capVal = $servicingStatus.WindowsUEFICA2023Capable
            $capDesc = switch ($capVal) {
                1 { 'Cert in DB' }
                2 { 'Cert in DB + 2023 boot manager' }
                default { 'Not in DB' }
            }
            $capIcon = if ($capVal -ge 2) { '<i class="fas fa-check-circle" style="color:#26A644;"></i>' } elseif ($capVal -eq 1) { '<i class="fas fa-info-circle" style="color:#5BC0DE;"></i>' } else { '<i class="fas fa-times-circle" style="color:#D9534F;"></i>' }
            $servParts += "$capIcon Boot Manager: $capDesc"
        }
        # Error info
        if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
            # If the Full line is longer than 
            $servParts += "<i class='fas fa-exclamation-triangle' style='color:#D9534F;'></i> Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
        }
        if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
            $servParts += "<i class='fas fa-info-circle' style='color:#D9534F;'></i> Error Event: [$($servicingStatus.UEFICA2023ErrorEvent)] $($servicingStatus.UEFICA2023ErrorEventDesc)"
        }
        # CanAttemptUpdateAfter
        if ($null -ne $servicingStatus.CanAttemptUpdateAfter) {
            $updateAfterStr = $servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm')
            if ($servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                $servParts += "<i class='fas fa-clock' style='color:#F0AD4E;'></i> Next attempt after: $updateAfterStr"
            }
        }
        if ($servParts.Count -gt 0) {
            $cardProperties['Servicing'] = $servParts -join '<br />'
        }
    }
    # AvailableUpdates bitmask decoded (only when set and non-zero)
    # Cross-reference manifest bits against actual cert inventory to determine what's truly applied
    if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
        $avHex  = '0x{0:X}' -f $optInStatus.EffectiveAvailable
        $source = if ($optInStatus.AvailableUpdatesPolicySet) { 'Policy' } else { 'Registry' }
        $avVal  = $optInStatus.EffectiveAvailable
        
        # Check each manifest bit against actual cert presence
        $manifestPending = @()
        if (($avVal -band 0x0004) -or ($avVal -band 0x4004)) {
            if (-not $has2023InKek) { $manifestPending += 'KEK 2K CA 2023' }
        }
        if ($avVal -band 0x0040) {
            if ($dbCertsFound -notcontains 'Windows UEFI CA 2023') { $manifestPending += 'Windows UEFI CA 2023' }
        }
        if ($avVal -band 0x0800) {
            if ($dbCertsFound -notcontains 'Microsoft Option ROM UEFI CA 2023') { $manifestPending += 'Option ROM UEFI CA 2023' }
        }
        if ($avVal -band 0x1000) {
            if ($dbCertsFound -notcontains 'Microsoft UEFI CA 2023') { $manifestPending += 'UEFI CA 2023' }
        }
        # Boot manager bit (0x0100) — if 1799 has occurred, boot manager is installed
        if ($avVal -band 0x0100) {
            $has1799 = ($null -ne $certStatus -and $certStatus.EventId -eq 1799) -or
                       ($null -ne $certStatus -and $null -ne $certStatus.AllEvents -and ($certStatus.AllEvents | Where-Object { $_.Id -eq 1799 }))
            if (-not $has1799) { $manifestPending += 'Boot manager (2023-signed)' }
        }
        
        $allApplied = ($manifestPending.Count -eq 0)
        $pendingReboot = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
        
        if ($allApplied) {
            $headerNote = " <span style='color:#26A644;'>(all applied)</span>"
        }
        elseif ($pendingReboot) {
            $headerNote = " <span style='color:#F0AD4E;'>(pending reboot for $($manifestPending.Count) cert$(if ($manifestPending.Count -ne 1) {'s'}))</span>"
        }
        else {
            $headerNote = " <span style='color:#F0AD4E;'>($($manifestPending.Count) pending)</span>"
        }
        $meaningLines = @("<i class='fas fa-info-circle' style='color:#5BC0DE;'></i> $avHex ($source)$headerNote")
        foreach ($m in $optInStatus.AvailableUpdatesMeaning) {
            $meaningLines += "&nbsp;&nbsp;&bull; $m"
        }
        # If certs are pending, list which ones
        if ($manifestPending.Count -gt 0) {
            $meaningLines += "<span style='color:#F0AD4E;'>&nbsp;&nbsp;<i class='fas fa-exclamation-triangle' style='color:#F0AD4E;'></i> Still needed: $($manifestPending -join ', ')</span>"
            if ($pendingReboot) {
                $meaningLines += "<span style='color:#F0AD4E;'>&nbsp;&nbsp;<i class='fas fa-sync-alt' style='color:#F0AD4E;'></i> Reboot pending (Event 1800) to apply remaining certs</span>"
            }
        }
        $sectionLabel = if ($allApplied) { 'Update Manifest' } else { 'Pending Updates' }
        $cardProperties[$sectionLabel] = $meaningLines -join '<br />'
    }
    # Bucket / confidence (from event message metadata)
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
        $confColor = switch -Wildcard ($certStatus.Confidence) {
            '*High*'   { '#26A644' }
            '*Action*' { '#D9534F' }
            default    { '#5BC0DE' }
        }
        $bucketHtml = "<span style='color:$confColor;'>$($certStatus.Confidence)</span>"
        if ($null -ne $certStatus.SkipReason) {
            $bucketHtml += " &nbsp;<i class='fas fa-exclamation-triangle' style='color:#D9534F;'></i> $($certStatus.SkipReason)"
        }
        $cardProperties['Rollout Tier'] = $bucketHtml
    }
    # Scheduled task status (only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        if ($scheduledTaskPresent) {
            $cardProperties['Update Task'] = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Secure-Boot-Update task present'
        }
        else {
            $cardProperties['Update Task'] = '<i class="fas fa-exclamation-triangle" style="color:#D9534F;"></i> Secure-Boot-Update task missing'
        }
    }
    # Opt-in status (only when Secure Boot is Enabled and check ran)
    if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
        $optInParts = @()
        switch ($optInStatus.Summary) {
            'Enabled' {
                $optInParts += '<i class="fas fa-check-circle" style="color:#26A644;"></i> WU Secure Boot management enabled'
            }
            'Blocked' {
                $optInParts += '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Opted in but telemetry too low (AllowTelemetry=0)'
            }
            'Not enabled' {
                $optInParts += '<i class="fas fa-info-circle" style="color:#6C757D;"></i> WU Secure Boot management not enabled'
            }
        }
        if ($null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
            $optInParts += '<i class="fas fa-ban" style="color:#D9534F;"></i> HighConfidenceOptOut is set'
        }
        if ($optInStatus.AvailableUpdatesPolicySet) {
            $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
            $optInParts += "<i class='fas fa-building' style='color:#5BC0DE;'></i> AvailableUpdatesPolicy: $apHex (GPO/MDM)"
        }
        $cardProperties['Opt-In Status'] = $optInParts -join '<br />'
    }
    
    $cardInfo = [PSCustomObject]$cardProperties
    
    $cardHtml = Get-NinjaOneInfoCard `
        -Title $CardTitle `
        -Data $cardInfo `
        -Icon $CardIcon `
        -BackgroundGradient $CardBackgroundGradient `
        -BorderRadius $CardBorderRadius `
        -IconColor $cardIconColor
    
    # -----------------------------------------------
    # Step 5: Write fields to NinjaRMM
    # -----------------------------------------------
    if ($SaveStatusLocal) {
        # For local HTML, replace FontAwesome <i> icons with emoji equivalents
        # FA tags are empty (e.g. <i class="fas fa-check-circle" style="..."></i>) so strip and prepend emoji
        $faPattern = '<i\s+class="fas[^"]*"[^>]*>\s*</i>\s*'
        $localStatusRowHtml = ($statusRowHtml -replace $faPattern, '').Trim()
        $localStatusRowHtml = $statusEmoji + ' ' + $localStatusRowHtml
        $localCardProperties = [ordered]@{
            'Secure Boot' = $localStatusRowHtml
            'Detail'      = ($detailRowHtml -replace $faPattern, '').Trim()
        }
        if ($null -ne $eventRowHtml) {
            $localCardProperties['Last Event'] = ($eventRowHtml -replace $faPattern, '').Trim()
        }
        # Event log summary for local card (plain text)
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $certStatus.EventSummary.Count -gt 0) {
            $localSummaryLines = @()
            foreach ($entry in ($certStatus.EventSummary | Sort-Object FirstSeen)) {
                $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
                $localSummaryLines += "$timeStr  [$($entry.Id)] $($entry.Description) ($($entry.Count)x)"
            }
            # Reboot correlation annotation
            if ($null -ne $certStatus.RebootCorrelation) {
                $rc = $certStatus.RebootCorrelation
                if ($rc.Confirmed) {
                    $bootTimeStr = $rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                    $localSummaryLines += "   ↳ Reboot at $bootTimeStr bridged 1800 → 1799"
                }
                else {
                    $localSummaryLines += "   ↳ 1800 → 1799 detected but no reboot found between them"
                }
            }
            # 1799 pending-1808 note
            if ($pending1808Note) {
                $localSummaryLines += "   ↳ 1808 expected on next scheduled task cycle"
            }
            $localCardProperties['Event Log'] = $localSummaryLines -join "`n"
        }
        # Certificate inventory
        if ($secureBoot -eq 'Enabled') {
            $localCertLines = @()
            foreach ($certName in $updatedDbCertNames) {
                $present = $dbCertsFound -contains $certName
                $icon    = if ($present) { '✅' } else { '❌' }
                $label   = ($certName -replace 'Microsoft Corporation ', '' -replace 'Microsoft ', '')
                $localCertLines += "$icon $label"
            }
            $kekIcon = if ($has2023InKek) { '✅' } else { '❌' }
            $localCertLines += "$kekIcon KEK 2K CA 2023"
            if ($ca2011RevokedInDbx.Count -gt 0) {
                foreach ($revokedCA in $ca2011RevokedInDbx) {
                    $rLabel = $revokedCA -replace 'Microsoft Corporation ', '' -replace 'Microsoft ', ''
                    $localCertLines += "🚫 $rLabel (revoked in dbx)"
                }
            }
            $localCardProperties['Certificates'] = $localCertLines -join "`n"
        }
        # Servicing status
        if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
            $localServParts = @()
            if ($null -ne $servicingStatus.UEFICA2023Status) {
                $servIcon = if ($servicingStatus.UEFICA2023Status -eq 'Updated') { '✅' } else { 'ℹ️' }
                $localServParts += "$servIcon UEFICA2023: $($servicingStatus.UEFICA2023Status)"
            }
            if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
                $capVal = $servicingStatus.WindowsUEFICA2023Capable
                $capDesc = switch ($capVal) { 1 { 'Cert in DB' }; 2 { 'Cert in DB + 2023 boot manager' }; default { 'Not in DB' } }
                $capIcon = if ($capVal -ge 2) { '✅' } elseif ($capVal -eq 1) { 'ℹ️' } else { '❌' }
                $localServParts += "$capIcon Boot Manager: $capDesc"
            }
            if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
                $localServParts += "⚠️ Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
            }
            if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
                $localServParts += "ℹ️ Error Event: [$($servicingStatus.UEFICA2023ErrorEvent)] $($servicingStatus.UEFICA2023ErrorEventDesc)"
            }
            if ($null -ne $servicingStatus.CanAttemptUpdateAfter -and $servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                $localServParts += "⏳ Next attempt after: $($servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm'))"
            }
            if ($localServParts.Count -gt 0) {
                $localCardProperties['Servicing'] = $localServParts -join "`n"
            }
        }
        # AvailableUpdates decoded (cross-referenced against actual certs)
        if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
            $avHex  = '0x{0:X}' -f $optInStatus.EffectiveAvailable
            $source = if ($optInStatus.AvailableUpdatesPolicySet) { 'Policy' } else { 'Registry' }
            
            if ($allApplied) {
                $localHeaderNote = ' (all applied)'
            }
            elseif ($pendingReboot) {
                $localHeaderNote = " (pending reboot for $($manifestPending.Count) cert$(if ($manifestPending.Count -ne 1) {'s'}))"
            }
            else {
                $localHeaderNote = " ($($manifestPending.Count) pending)"
            }
            $localMeaningLines = @("$avHex ($source)$localHeaderNote")
            foreach ($m in $optInStatus.AvailableUpdatesMeaning) {
                $localMeaningLines += "  • $m"
            }
            if ($manifestPending.Count -gt 0) {
                $localMeaningLines += "⚠️ Still needed: $($manifestPending -join ', ')"
                if ($pendingReboot) {
                    $localMeaningLines += "🔄 Reboot pending (Event 1800) to apply remaining certs"
                }
            }
            $localSectionLabel = if ($allApplied) { 'Update Manifest' } else { 'Pending Updates' }
            $localCardProperties[$localSectionLabel] = $localMeaningLines -join "`n"
        }
        # Bucket / confidence
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
            $bucketText = $certStatus.Confidence
            if ($null -ne $certStatus.SkipReason) {
                $bucketText += " ⚠️ $($certStatus.SkipReason)"
            }
            $localCardProperties['Rollout Tier'] = $bucketText
        }
        # Scheduled task
        if ($secureBoot -eq 'Enabled') {
            if ($scheduledTaskPresent) {
                $localCardProperties['Update Task'] = '✅ Secure-Boot-Update task present'
            } else {
                $localCardProperties['Update Task'] = '⚠️ Secure-Boot-Update task missing'
            }
        }
        # Opt-in status
        if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
            $localOptParts = @()
            switch ($optInStatus.Summary) {
                'Enabled'     { $localOptParts += '✅ WU Secure Boot management enabled' }
                'Blocked'     { $localOptParts += '⚠️ Opted in but telemetry too low (AllowTelemetry=0)' }
                'Not enabled' { $localOptParts += 'ℹ️ WU Secure Boot management not enabled' }
            }
            if ($null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
                $localOptParts += '🚫 HighConfidenceOptOut is set'
            }
            if ($optInStatus.AvailableUpdatesPolicySet) {
                $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
                $localOptParts += "🏢 AvailableUpdatesPolicy: $apHex (GPO/MDM)"
            }
            $localCardProperties['Opt-In Status'] = $localOptParts -join "`n"
        }
        
        $localCardInfo = [PSCustomObject]$localCardProperties
        
        $localCardTitle = "🛡️ Secure Boot Status Card"
        
        $localCardHtml = Get-NinjaOneInfoCard `
            -Title $localCardTitle `
            -Data $localCardInfo `
            -Icon $CardIcon `
            -BackgroundGradient $CardBackgroundGradient `
            -BorderRadius $CardBorderRadius `
            -IconColor $cardIconColor
        
        # -----------------------------------------------
        # Step 5.5: Save status locally if enabled
        # -----------------------------------------------
        $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
        $logDir = "$systemDrive\Logs\SecureBoot"
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            catch {
                Write-Log "ERROR" "Failed to create local log directory: $($_.Exception.Message)"
            }
        }
        $txtFile = Join-Path $logDir "SecureBootStatus.txt"
        $htmlFile = Join-Path $logDir "SecureBootStatusCard.html"
        try {
            $plainText | Out-File -FilePath $txtFile -Encoding utf8 -Force
            $localCardHtml | Out-File -FilePath $htmlFile -Encoding utf8 -Force
            Write-Log "SUCCESS" "Saved status to local files: $txtFile and $htmlFile"
            #Write-Host "`nSaved local status files:`n- Text: $txtFile`n- HTML: $htmlFile"
            #Write-Host "`nLocal Text Status Content:"
            #Get-Content $txtFile | Write-Host
        }
        catch {
            Write-Log "ERROR" "Failed to save local status files: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "`n=== Writing NinjaRMM Custom Fields ==="
        
        Write-Log "INFO" "Writing status card to '$StatusCardFieldName'"
        try {
            Invoke-NinjaPropertySetPiped -FieldName $StatusCardFieldName -Html $cardHtml
            Write-Log "SUCCESS" "Status card written to '$StatusCardFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to write status card: $($_.Exception.Message)"
        }
        
        Write-Log "INFO" "Writing plain-text status to '$PlainTextFieldName'"
        try {
            Invoke-NinjaPropertySet -FieldName $PlainTextFieldName -Value $plainText
            Write-Log "SUCCESS" "Plain-text status written to '$PlainTextFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to write plain-text status: $($_.Exception.Message)"
        }
    }
    
    # -----------------------------------------------
    # Step 6: Console summary
    # -----------------------------------------------
    Write-Host "`n--- SECURE BOOT CERTIFICATE STATUS ---"
    Write-Host "Secure Boot : $secureBoot"
    Write-Host "Final State : $statusKey"
    Write-Host "Plain Text  : $plainText"
    if ($certStatus -and -not $triggeredOsUpdate) {
        Write-Host "Event Detail: $($certStatus.EventMessage)"
    }
    if ($secureBoot -eq 'Enabled') {
        Write-Host "KEK 2023    : $(if ($has2023InKek) { 'Present' } else { 'Missing' })"
        Write-Host "DB 2023     : $(if ($has2023InDb) { $dbCertsFound -join ', ' } else { 'None found' })"
        Write-Host "Update Task : $(if ($scheduledTaskPresent) { 'Present' } else { 'Missing' })"
        Write-Host "OS Writable : $dbIsOsWritable"
        Write-Host "Opt-In      : $(if ($null -ne $optInStatus) { $optInStatus.Summary } else { 'N/A' })"
        if ($null -ne $servicingStatus -and $null -ne $servicingStatus.UEFICA2023Status) {
            Write-Host "Servicing   : $($servicingStatus.UEFICA2023Status)"
            if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
                $capDesc = switch ($servicingStatus.WindowsUEFICA2023Capable) { 1 { 'Cert in DB' }; 2 { 'Cert in DB + 2023 boot mgr' }; default { 'Not in DB' } }
                Write-Host "Boot Mgr    : $capDesc (Capable=$($servicingStatus.WindowsUEFICA2023Capable))"
            }
            if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
                Write-Host "Serv Error  : $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
            }
            if ($null -ne $servicingStatus.CanAttemptUpdateAfter -and $servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
                Write-Host "Next Attempt: $($servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm'))"
            }
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.Confidence) {
            Write-Host "Confidence  : $($certStatus.Confidence)"
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.SkipReason) {
            Write-Host "Skip Reason : $($certStatus.SkipReason)"
        }
        if ($null -ne $certStatus -and $null -ne $certStatus.RebootCorrelation) {
            $rc = $certStatus.RebootCorrelation
            if ($rc.Confirmed) {
                Write-Host "Reboot Link : 1800 → reboot ($($rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm'))) → 1799 (confirmed)"
            }
            else {
                Write-Host "Reboot Link : 1800 → 1799 (no reboot found between them)"
            }
        }
        if ($pending1808Note) {
            Write-Host "1808 Status : Expected on next scheduled task cycle (servicing confirms Updated)"
        }
        if ($null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
            $manifestLabel = if ($allApplied) { 'Manifest    :' } else { 'Pending     :' }
            Write-Host "$manifestLabel $($optInStatus.AvailableUpdatesMeaning -join '; ')"
            if ($manifestPending.Count -gt 0) {
                Write-Host "Still Needed: $($manifestPending -join ', ')$(if ($pendingReboot) { ' (reboot pending)' })"
            }
        }
        if ($null -ne $optInStatus -and $null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
            Write-Host "HC Opt-Out  : Yes"
        }
        if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) {
            Write-Host "Policy      : 0x$($optInStatus.AvailableUpdatesPolicy.ToString('X')) (GPO/MDM)"
        }
    }
    Write-Host "--------------------------------------`n"
    
    Write-Host "=== Complete ==="
    Write-Log "SUCCESS" "Secure Boot certificate status check completed"
}
