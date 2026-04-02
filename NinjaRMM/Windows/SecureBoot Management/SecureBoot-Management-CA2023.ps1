#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 04-01-2026

    Note:
    04-01-2026; Addressed a small, out of place HTML cosmetic bug, with the
                "What is this?" a tag link not processing through the build-*
                pipeline. Examples how to handle additional title info dynamically.
                CSS modification so a tags do not have underlining for HTML cards.
                SecureBootAction no longer writes AvailableUpdates.
                SVN Enforcement sub-section always visible for better insight.
                Addressed inconsist reporting & accuracies between Passive & Enforce.
                Cosmetic clarity and fine-tuning UI states/instances.
                Improved WU Opt-In reporting to show only when needed.
                Addressed a bug with Build-UpdatesSection that left persitent pending-
                updates after all stages have been applied (causing confusion).
                Has2023InDb now specifically checks for Windows UEFI CA 2023.
                Identifies other 2023 certs in a new supplemental step, sets bitmask,
                checks for added cert data after, warning and continuing on.
                  During my testing of this, it worked flawlessly, setting the
                  Update bits, triggering the task, firing events the events.
                  No reboots were needed in my testing when applying
                Removed Get-ShortCertName, caused too much confusion.
    03-31-2026: Stage 3+4 prerequisite gate (Test-SvnStagePrerequisites): prevents
                mitigations 3 (0x80) and 4 (0x200) from executing unless Stage 1+2
                are VERIFIED complete. Two-signal validation per stage:
                  Stage 1: cert physically in db (ground truth) AND 0x40 bit consumed
                  Stage 2: Event 1799/1808 confirmed AND 0x100 bit consumed
                Reboot detection: Event 1800 or unconfirmed Mitigation 2 blocks gate.
                Used by both Invoke-SvnEnforcement (active gate) and passive safety check.
                SVN Enforcement Repair (Repair-SvnEnforcement): detects prematurely
                triggered Stage 3+4 bits in AvailableUpdates and clears them before
                the next reboot processes them. Checks reversibility: if Events 1037
                (2011 CA revoked) or 1042 (SVN applied) have already fired, DBX is
                modified and cannot be undone from Windows - provides OEM-specific
                BIOS key reset guidance. Runs in both Enforce and Passive modes.
                Post-enforcement safety check: after Invoke-SvnEnforcement, if
                mitigations 3+4 were Blocked but their bits exist in the manifest
                (from this run or a prior run), Repair-SvnEnforcement clears them.
                Passive mode safety check: even in audit-only mode, scans for
                premature Stage 3+4 bits and clears them to prevent damage on reboot.
                Invoke-SvnEnforcement gate refactored: replaced simple Event 1800
                check with full Test-SvnStagePrerequisites call for Mitigation 3+4
                (ground truth + manifest + reboot), with detailed gate logging.
    03-30-2026: SVN Enforcement engine (Invoke-SvnEnforcement): applies KB5025885 /
                CVE-2023-24932 enterprise deployment guidance mitigations 1-4 when $EnforceSvnCompliance = 'Enforce SVN', only
                when applicable (stages 1-2 are fully complete with no pending updates, etc).
                Each mitigation writes AvailableUpdates bitmask + triggers Secure-Boot-Update
                task: Mitigation 1 (0x40, DB cert), Mitigation 2 (0x100, Boot manager),
                Mitigation 3 (0x80, revoke PCA 2011 in DBX), Mitigation 4 (0x200, apply SVN).
                Gate logic: Mits 3+4 block on Event 1800 (pending cert reboot) and check
                pre-existing completion via DBX presence / event 1037/1042 before applying.
                Enforcement results include per-mitigation BlockedReason for card display.
                Passive enforcement mode: detects "previously enforced" when events 1037/1042
                predate Microsoft's June 26 2026 enforcement date.
                SVN reboot-pending detection refactored from unreliable DBX SVN byte comparison
                to boot-time cross-reference (Win32_OperatingSystem.LastBootUpTime vs event
                timestamps). Cmdlet path (FirmwareSVN < StagedSVN) preserved as supplemental.
                Cert inventory now uses three-state icons: green (confirmed via 1799/1808),
                blue (pending - manifest bit set but OS hasn't confirmed), red (absent and
                not pending). Cross-references AvailableUpdates manifest bits per-cert.
                PCA 2011 revocation line: ban icon color reflects state (green=complete,
                blue=pending reboot, yellow=unknown). Inline "(revoked in dbx - pending
                reboot)" replaces separate indented line.
                Updates section simplified: "No Updates Pending (all applied)" when fully
                applied, otherwise "Pending (header note)" with bullet list. Registry hex
                value moved to Write-Log only (not displayed on card).
                Update manifest enrichment: gate widened to include event-confirmed mitigations
                (1037/1042) even without registry opt-in. Fresh AvailableUpdates re-read +
                event-based OR-ing of 0x0080/0x0200 ensures manifest accuracy.
                Detail text now appends SVN summary: "Reboot required to complete SVN firmware
                updates" / "No action required" / "SVN updates pending - awaiting Microsoft
                rollout (June 2026 - 2027)". Replaces static "No action required" when SVN
                needs action. Fixed stale 1801 detail text that incorrectly claimed "OS update
                triggered via reg key" in Audit mode.
                Rollout Tier: formats multi-value comma-separated confidence as numbered list,
                strips "3P " prefix, single char entries present "Under Observation - More Data Needed".
                Fixed Get-DbxSignatureData offset bug: was reading byte 0 instead of byte 32
                for SVN signature data extraction (critical bug).
                Major refactoring: extracted 15+ helper functions to eliminate ~550 lines of
                duplicated HTML/plain-text card rendering. Build-* functions accept -Format
                'Html'|'Local' parameter - single source of truth for every card section
                (Certificates, Servicing, Updates, SVN Compliance, Enforcement, Rollout Tier,
                Update Task, Opt-In, Event Log). Supporting helpers: Format-CardIcon (unified
                FA/emoji renderer), Test-HasSecureBootEvent, Get-LatestSecureBootEvent,
                Get-ShortCertName, Test-SvnRebootPending, Get-OemGuide (merged KeyReset +
                BIOSUpdate into one parameterized function).
                Major Local card re-implementation & formatting to match Ninja 1:1.
    03-27-2026: SVN (Security Version Number) compliance, full implementation.
                Uses Get-SecureBootSVN cmdlet (February 2025 KB5077241+) when available,
                with raw DBX byte parsing fallback for all devices (pre-KB5077241).
                Raw DBX extracts BootMgr SVN from EFI_CERT_SHA256_GUID signature entries
                using hex offsets (major at 36-39, minor at 40-43).
                Compares live DBX SVN against DBXUpdateSVN.bin staging file
                (System32\SecureBootUpdates) to detect pending SVN updates.
                SVN progression: 0.0 (none) → 2.0 (PCA 2011 revoked) → 7.0 (full).
                Three-way display: Compliant / Pending (2011 not yet revoked) /
                Non-compliant. "Not compliant" with FirmwareSVN 0.0 is expected
                pre-Stage 3 when PCA 2011 hasn't been revoked yet.
                Rollout timeline:
                  Stage 1 (May 2024)  : 2023 certs added to db via Windows Update
                  Stage 2 (Feb 2025)  : 2023 boot manager deployed, SVN cmdlet added
                  Stage 3 (est. 2026) : PCA 2011 revoked in dbx, SVN enforcement begins
                  Stage 4 (est. 2027) : Full enforcement - 2011 certs removed from db
                Added Get-SecureBootUEFI -Decoded parameter support (KB5077241+) for
                richer cert parsing without raw byte fallback.
                SVN Compliance card section now appears after Pending Updates.
                Sources: garlin's SecureBoot-CA-2023-Updates scripts,
                  microsoft/secureboot_objects (GitHub)
    03-24-2026: Manifest cross-referencing has been added, now checks each manifest bit
                against actual cert presence:
                  0x0040 -> checks if Windows UEFI CA 2023 is in $dbCertsFound
                  0x0800 -> checks if Microsoft Option ROM UEFI CA 2023 is in $dbCertsFound
                  0x1000 -> checks if Microsoft UEFI CA 2023 is in $dbCertsFound
                  0x0004/0x4004 -> checks $has2023InKek
                  0x0100 -> checks if Event 1799 has occurred
                Addresses incorerct assumptions about Update Completion/Manifest.
                dbDefault now tracks which certs are found.
                Three-way logic for missing KEK (both State 4 with 1801 and State 5b without events):
                  dbIsOsWritable -> Action Optional (KEK present, WU will handle it)
                  has1803 -> Action Required (OEM blocker, key reset or firmware update genuinely needed)
                  No 1803 -> Pending, opt-in can push KEK; tells you if opted in or not
                Added WindowsUEFICA2023Capable check and 2011 CA Revocation Cross-Check;
                  Source: https://github.com/cjee21/Check-UEFISecureBootVariables
    03-24-2026: Removed "Pending (1799)" as a distinct state - Event 1799 now falls
                through to the general Pending state. UEFICA2023Status='Updated' is
                the ground truth; age-based 1799 guessing was unnecessary.
                Added 1799->1808 informational note: when 1799 is latest and servicing
                confirms Updated but 1808 is absent from the log, annotates card/console
                that 1808 is expected on the next scheduled task cycle (runs at startup
                + every 12h). No nudge or wait - just an informational annotation.
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
                Added distinct state handling for Event 1800 ("Pending Cert Reboot") and
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
          error), 1797 (Windows UEFI CA 2023 cert not in DB), 1798 (boot mgr not signed),
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
      1. Not Applicable         - Non-UEFI or unsupported hardware
      2. Disabled               - UEFI capable but Secure Boot is off
      3. Compliant              - Secure Boot on, Event 1808 or UEFICA2023Status='Updated'
                                  confirmed (BIOS certs updated)
      4. Action Required        - 2023 certs missing and Windows cannot write to the BIOS db
                                  (UEFI attributes or KEK authority missing); OEM firmware
                                  update or manual key reset required
      5. Action Optional        - 2023 certs missing (or in dbDefault only), but the UEFI db
                                  is OS-writable (attributes + KEK both present); Windows
                                  Update will push the cert automatically, or a manual BIOS
                                  update / key reset can expedite
      6. Pending Cert Reboot    - Event 1800 detected; reboot required to continue the update
      7. Pending                - 2023 cert in db or dbDefault but rotation not yet complete;
                                  OS update triggered where applicable
      8. Pending (Trigger)      - OS-side update triggered; monitoring for event progression,
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
      
      - Audit SecureBoot management status (default)
            Read-only check of the current opt-in and telemetry configuration.
            Reports the state of AllowTelemetry, MaxTelemetryAllowed,
            MicrosoftUpdateManagedOptIn, and AvailableUpdates registry keys
            without making any changes. No registry writes or task triggers.
            NOTE: Windows will NOT update CA2023 certificates without opt-in.
            To enable automatic deployment, set action to "Enable opt-in".

.PARAMETER EnforceSvnCompliance
      - Enforce SVN
          Follows through and applies (when aplicable & safe to do so) the SVN
          compliance steps from Microsoft KB5025885.
          NOTE: If you use BitLocker, make sure that your BitLocker recovery key
          has been backed-up. You can run the following command from an Administrator
          command prompt and note the 48-digit numerical password:
            manage-bde -protectors -get %systemdrive%
          
          Check out my Bitlocker Management & Status scripts at:
            https://github.com/SunshineSam/Scripts/tree/main/NinjaRMM/Windows/Bitlocker%20Management
            (compund condition for pending svn reboot output could work here)
          
      - Passive
          Does not enforce the SVN compliance, pending the Microsoft enforced dates
          of June 2026 for Step 3 & sometime in 2027 for the final step.
          For enterprise & environments, it is reccommended to enforce SVN for
          security purposes. Test 

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
    
    # SVN enforcement mode          Ninja Variable Resolution                                             Fallback
    # "Enforce SVN" = actively apply all 4 mitigations (DB cert, boot manager, 2011 revocation, SVN update)
    # "Passive" = audit only; report current stage; wait for Microsoft's scheduled enforcement (Step 3, June 2026 - Step 4, 2027)
    [ValidateSet('Enforce SVN','Passive')]
    [string]$EnforceSvnCompliance = $(if ($env:enforceSvnCompliance) { $env:enforceSvnCompliance } else { 'Passive' }), # Optional Ninja Script Variable; Drop-down
    
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
    # Log file path and header state are cached to avoid per-call overhead
    $script:LogFilePath     = $null
    $script:LogHeaderWritten = $false
    
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        
        # Output the log message to the console
        Write-Host "[$Level] $Message"
        
        # Save the log message to a file on the device if enabled
        if ($SaveLogToDevice) {
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            # Initialize log file path once
            if ($null -eq $script:LogFilePath) {
                $systemDrive = $env:SystemDrive
                if (-not $systemDrive) { $systemDrive = 'C:' }
                $logDir = "$systemDrive\Logs\SecureBoot"
                if (-not (Test-Path $logDir)) {
                    try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
                }
                $script:LogFilePath = Join-Path $logDir "SecureBootStatus.log"
            }
            
            # Write daily header once per session
            if (-not $script:LogHeaderWritten) {
                $today = Get-Date -Format 'yyyy-MM-dd'
                $header = "=== $today ==="
                try {
                    # Use StreamWriter with FileShare.ReadWrite to avoid locking issues
                    $sw = [System.IO.StreamWriter]::new($script:LogFilePath, $true, [System.Text.Encoding]::UTF8)
                    $sw.WriteLine("`r`n$header")
                    $sw.Close()
                }
                catch { }
                $script:LogHeaderWritten = $true
            }
            
            # Append log line with shared access
            try {
                $fs = [System.IO.FileStream]::new($script:LogFilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $sw = [System.IO.StreamWriter]::new($fs)
                $sw.WriteLine($logMessage)
                $sw.Close()
                $fs.Close()
            }
            catch { }
        }
    }
    
    # Helper function: Generate a standalone HTML document for local viewing (self-contained CSS)
    function Get-LocalHtmlDocument {
        param (
            [string]$Title,
            [PSCustomObject]$Data,
            [string]$AccentColor = '#26A644'
        )
        $sectionsHtml = [System.Text.StringBuilder]::new()
        foreach ($item in $Data.PSObject.Properties) {
            $sectionName = $item.Name
            $content = $item.Value
            [void]$sectionsHtml.Append(@"
            <div class="section">
                <div class="section-label">$sectionName</div>
                <div class="section-content">$content</div>
            </div>
"@)
        }
        return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$([System.Net.WebUtility]::HtmlEncode($Title))</title>
<style>
  :root {
    --accent: $AccentColor;
    --bg: #f5f6fa;
    --card-bg: #ffffff;
    --text: #272727;
    --muted: #6b7280;
    --border: #e5e7eb;
    --link: #447dcd;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #131313;
      --card-bg: #272727;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --border: #4a4a4a;
      --link: #447dcd;
    }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px;
    line-height: 1.5;
  }
  .card {
    max-width: 620px;
    margin: 0 auto;
    background: var(--card-bg);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.04);
    overflow: hidden;
  }
  .card-header {
    background: var(--accent);
    color: #fff;
    padding: 16px 20px;
    font-size: 18px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .card-body {
    padding: 4px 0;
  }
  .section {
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  .section:last-child {
    border-bottom: none;
  }
  .section-label {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .section-content {
    font-size: 14px;
    word-break: break-word;
  }
  .footer {
    text-align: center;
    padding: 10px 20px 14px;
    font-size: 11px;
    color: var(--muted);
  }
  a { color: var(--link); text-decoration-line: none; }
</style>
</head>
<body>
<div class="card">
  <div class="card-header">$([System.Net.WebUtility]::HtmlEncode($Title))</div>
  <div class="card-body">
$($sectionsHtml.ToString())
  </div>
  <div class="footer">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</div>
</body>
</html>
"@
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
    
    # Helper function: Test if a specific Secure Boot event ID exists in the event log
    # Replaces repeated pattern: @($certStatus.AllEvents | Where-Object { $_.Id -eq XXXX }).Count -gt 0
    function Test-HasSecureBootEvent {
        param (
            [object]$CertStatus,
            [int]$EventId
        )
        return ($null -ne $CertStatus -and $null -ne $CertStatus.AllEvents -and
                @($CertStatus.AllEvents | Where-Object { $_.Id -eq $EventId }).Count -gt 0)
    }
    
    # Helper function: Get the most recent occurrence of a specific Secure Boot event ID
    # Returns the event object or $null
    function Get-LatestSecureBootEvent {
        param (
            [object]$CertStatus,
            [int]$EventId
        )
        if ($null -eq $CertStatus -or $null -eq $CertStatus.AllEvents) { return $null }
        return $CertStatus.AllEvents | Where-Object { $_.Id -eq $EventId } | Sort-Object Time -Descending | Select-Object -First 1
    }
    
    # Helper function: Test if SVN reboot is pending (revocation or SVN update awaiting reboot)
    # Replaces repeated: ($null -ne $svnStatus -and ($svnStatus.RebootPending -or $svnStatus.RevocationAppliedPendingReboot))
    function Test-SvnRebootPending {
        param ([object]$SvnStatus)
        return ($null -ne $SvnStatus -and ($SvnStatus.RebootPending -or $SvnStatus.RevocationAppliedPendingReboot))
    }
    
    # Helper function: Get OEM guide URL by type (KeyReset or BIOSUpdate)
    # Consolidates Get-OemKeyResetGuide and Get-OemBIOSUpdateGuide
    function Get-OemGuide {
        param (
            [ValidateSet('KeyReset', 'BIOSUpdate')]
            [string]$GuideType
        )
        $urls = @{
            Dell      = @{ KeyReset = 'https://www.dell.com/support/kbdoc/en-us/000368610/how-to-update-secure-boot-active-database-from-bios'
                           BIOSUpdate = 'https://www.dell.com/support/kbdoc/en-us/000124211/dell-bios-updates' }
            HP        = @{ KeyReset = 'https://support.hp.com/lv-en/document/ish_13070353-13070429-16'
                           BIOSUpdate = 'https://support.hp.com/us-en/document/ish_4129273-2331498-16' }
            Lenovo    = @{ KeyReset = 'https://pubs.lenovo.com/uefi_iot/secure_boot_config'
                           BIOSUpdate = 'https://support.lenovo.com/us/en/solutions/ht500008' }
            ASUS      = @{ KeyReset = 'https://www.asus.com/us/support/faq/1050047/'
                           BIOSUpdate = 'https://www.asus.com/us/support/faq/1008276/' }
            Microsoft = @{ KeyReset = 'https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e'
                           BIOSUpdate = 'https://support.microsoft.com/en-us/surface/download-drivers-and-firmware-for-surface-09bb2e09-2a4b-cb69-0951-078a7739e120' }
        }
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS
            $manufacturer = $biosInfo.Manufacturer
            Write-Log "INFO" "BIOS Manufacturer: $manufacturer"
            foreach ($oem in $urls.Keys) {
                if ($manufacturer -match $(if ($oem -eq 'HP') { 'HP|Hewlett-Packard' } else { $oem })) {
                    return $urls[$oem][$GuideType]
                }
            }
            Write-Log "INFO" "No matching $GuideType guide for manufacturer: $manufacturer"
            return $null
        }
        catch {
            Write-Log "WARNING" "Failed to get BIOS manufacturer: $($_.Exception.Message)"
            return $null
        }
    }
    
    # Helper function: Build card section content for both HTML and plain-text formats
    # Returns formatted content lines using the appropriate icons and separators
    # $Format: 'Html' for FontAwesome icons + <br />, 'Local' for emoji + newline
    function Format-CardIcon {
        param (
            [string]$Type,     # check, times, warning, info, sync, ban, clock, eye, building, question
            [string]$Color,    # hex color e.g. '#26A644'
            [string]$Format    # 'Html' or 'Local'
        )
        if ($Format -eq 'Html') {
            $faClass = switch ($Type) {
                'check'    { 'fa-check-circle' }
                'times'    { 'fa-times-circle' }
                'warning'  { 'fa-exclamation-triangle' }
                'info'     { 'fa-info-circle' }
                'sync'     { 'fa-sync-alt' }
                'ban'      { 'fa-ban' }
                'clock'    { 'fa-clock' }
                'eye'      { 'fa-eye' }
                'building' { 'fa-building' }
                'question' { 'fa-question-circle' }
                'circle'   { 'fa-circle' }
                'cog'      { 'fa-cog' }
                default    { 'fa-question' }
            }
            return "<i class='fas $faClass' style='color:$Color;'></i>"
        }
        else {
            $emoji = switch ($Type) {
                'check'    { '✅' }
                'times'    { '❌' }
                'warning'  { '⚠️' }
                'info'     { 'ℹ️' }
                'sync'     { '🔄' }
                'ban'      { '🚫' }
                'clock'    { '⏳' }
                'eye'      { '👁️' }
                'building' { '🏢' }
                'question' { '❓' }
                'circle'   { '⚪' }
                'cog'      { '⚙️' }
                default    { '❔' }
            }
            return $emoji
        }
    }
    
    # Helper function: Replace FontAwesome <i> icons with emoji equivalents in HTML content
    # Uses the same icon-to-emoji mapping as Format-CardIcon.
    # Handles both quote styles: class='fas ...' (from Format-CardIcon) and class="fas ..." (inline HTML)
    function Convert-FaIconsToEmoji {
        param ([string]$Html)
        if ([string]::IsNullOrEmpty($Html)) { return $Html }
        $faEmojiMap = @{
            'fa-check-circle'          = '✅'
            'fa-times-circle'          = '❌'
            'fa-exclamation-triangle'  = '⚠️'
            'fa-exclamation-circle'    = '❕'
            'fa-info-circle'           = 'ℹ️'
            'fa-sync-alt'              = '🔄'
            'fa-ban'                   = '🚫'
            'fa-clock'                 = '⏳'
            'fa-eye'                   = '👁️'
            'fa-building'              = '🏢'
            'fa-question-circle'       = '﹖'
            'fa-circle'                = '⚪'
            'fa-cog'                   = '⚙️'
            'fa-calendar-check'        = '📅'
            'fa-calendar-times'        = '📅'
            'fa-redo'                  = '🔄'
            'fa-search'                = '🔍'
            'fa-arrow-up-right-from-square' = '🔗'
        }
        # Match <i class="fas fa-xxx" style="..."></i> or <i class='fas fa-xxx' style='...'></i>
        # The \s* after </i> consumes the trailing space, add one back after the emoji
        return [regex]::Replace($Html, "<i\s+class=['""]fas\s+(fa-[\w-]+)['""][^>]*>\s*</i>\s*", {
            param($m)
            $cls = $m.Groups[1].Value
            if ($faEmojiMap.ContainsKey($cls)) { "$($faEmojiMap[$cls]) " } else { '' }
        })
    }
    
    # Helper function: Join card lines with HTML line-break separator
    # Both Html (NinjaRMM) and Local (standalone HTML) render as HTML
    function Join-CardLines {
        param (
            [string[]]$Lines,
            [string]$Format  # 'Html' or 'Local' (both use <br />)
        )
        return $Lines -join '<br />'
    }
    
    # Helper function: Build certificate inventory section for card display
    function Build-CertInventorySection {
        param ([string]$Format)
        $lines = @()
        foreach ($certName in $updatedDbCertNames) {
            $present = $dbCertsFound -contains $certName
            $label   = $certName
            if ($present) {
                # Ground truth wins: cert is physically in db = green regardless of manifest bits
                $icon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            }
            elseif ($certsUnconfirmed -contains $label) {
                # Manifest bit set but cert not yet in db = blue (pending reboot/processing)
                $icon = Format-CardIcon -Type 'check' -Color '#3B82F6' -Format $Format
            }
            else {
                $icon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
            }
            $lines += "$icon $label"
        }
        # KEK cert
        if ($has2023InKek) {
            $kekIcon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
        }
        elseif ($certsUnconfirmed -contains 'KEK 2K CA 2023') {
            $kekIcon = Format-CardIcon -Type 'check' -Color '#3B82F6' -Format $Format
        }
        else {
            $kekIcon = Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format
        }
        $lines += "$kekIcon KEK 2K CA 2023"
        # 2011 CA revocation status
        if ($ca2011RevokedInDbx.Count -gt 0) {
            foreach ($revokedCA in $ca2011RevokedInDbx) {
                $rLabel = if ($revokedCA -match 'Production PCA') { 'PCA 2011' } elseif ($revokedCA -match 'UEFI CA') { 'UEFI CA 2011' } else { $revokedCA }
                if ($null -ne $svnStatus -and ($svnStatus.RevocationAppliedPendingReboot -or $svnStatus.RebootPending)) {
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#3B82F6' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx - <span style='color:#3B82F6;'>pending SVN reboot</span>)</span>"
                }
                elseif ($null -ne $svnStatus) {
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#26A644' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx)</span>"
                }
                else {
                    $rIcon = Format-CardIcon -Type 'ban' -Color '#F59E0B' -Format $Format
                    $lines += "$rIcon $rLabel <span style='color:#888;'>(revoked in dbx)</span>"
                }
            }
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build servicing status section for card display
    function Build-ServicingSection {
        param ([string]$Format)
        $parts = @()
        if ($null -ne $servicingStatus.UEFICA2023Status) {
            $icon = if ($servicingStatus.UEFICA2023Status -eq 'Updated') {
                Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            }
            else {
                Format-CardIcon -Type 'info' -Color '#F0AD4E' -Format $Format
            }
            $label = 'Service Status'
            $parts += "$icon ${label}: $($servicingStatus.UEFICA2023Status)"
        }
        if ($null -ne $servicingStatus.WindowsUEFICA2023Capable) {
            $capVal = $servicingStatus.WindowsUEFICA2023Capable
            $capDesc = switch ($capVal) { 1 { 'Cert in DB' }; 2 { 'Cert in DB + 2023 boot manager' }; default { 'Not in DB' } }
            $capIcon = if ($capVal -ge 2) { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format }
                       elseif ($capVal -eq 1) { Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format }
                       else { Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format }
            $parts += "$capIcon Boot Manager: $capDesc"
        }
        if ($null -ne $servicingStatus.UEFICA2023Error -and $servicingStatus.UEFICA2023Error -ne 0) {
            $errIcon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $parts += "$errIcon Error: $($servicingStatus.UEFICA2023ErrorHex) - $($servicingStatus.UEFICA2023ErrorMessage)"
        }
        if ($null -ne $servicingStatus.UEFICA2023ErrorEvent) {
            $eeIcon = Format-CardIcon -Type 'info' -Color '#D9534F' -Format $Format
            $parts += "$eeIcon Error Event: [$($servicingStatus.UEFICA2023ErrorEvent)] $($servicingStatus.UEFICA2023ErrorEventDesc)"
        }
        if ($null -ne $servicingStatus.CanAttemptUpdateAfter -and $servicingStatus.CanAttemptUpdateAfter -gt (Get-Date)) {
            $updateAfterStr = $servicingStatus.CanAttemptUpdateAfter.ToString('yyyy-MM-dd HH:mm')
            $clkIcon = Format-CardIcon -Type 'clock' -Color '#F0AD4E' -Format $Format
            $parts += "$clkIcon Next attempt after: $updateAfterStr"
        }
        if ($parts.Count -eq 0) { return $null }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build Updates/manifest section for card display
    function Build-UpdatesSection {
        param ([string]$Format)
        if ($allApplied -and -not $svnRebootForManifest) {
            $chk = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            return "$chk No Updates Pending <span style='color:#26A644;'>(all applied)</span>"
        }
        # Build header note
        if ($allApplied -and $svnRebootForManifest) {
            $hdrNote = " <span style='color:#3B82F6; font-size:0.85em;'>(all certs applied - pending SVN reboot)</span>"
        }
        elseif ($allApplied) {
            $hdrNote = " <span style='color:#26A644;'>(all applied)</span>"
        }
        elseif ($pendingReboot) {
            $certCount = $manifestPending.Count
            $s = if ($certCount -ne 1) { 's' } else { '' }
            $hdrNote = " <span style='color:#3B82F6;'>(pending cert reboot for $certCount cert$s)</span>"
        }
        else {
            $pc = $manifestPending.Count
            $hdrNote = " <span style='color:#F0AD4E;'>($pc pending)</span>"
        }
        $pendingIconColor = if ($svnRebootForManifest -or $pendingReboot) { '#3B82F6' } else { '#5BC0DE' }
        $pendIcon = Format-CardIcon -Type 'info' -Color $pendingIconColor -Format $Format
        $lines = @("$pendIcon Pending$hdrNote")
        foreach ($m in $enrichedMeaning) {
            $lines += "&nbsp;&nbsp;&bull; $m"
        }
        if ($manifestPending.Count -gt 0) {
            $warnIcon = Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format
            $lines += "<span style='color:#F0AD4E;'>$warnIcon Still needed: $($manifestPending -join ', ')</span>"
            if ($pendingReboot) {
                $syncIcon = Format-CardIcon -Type 'sync' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>$syncIcon Reboot pending (Event 1800) to apply remaining certs</span>"
            }
        }
        return Join-CardLines -Lines $lines -Format $Format
    }
    
    # Helper function: Build enforcement mitigation lines (shared by active and passive enforcement display)
    function Build-EnforcementMitigationLines {
        param (
            [string]$Format,
            [hashtable]$EnfResult,         # The enforcement result hashtable
            [bool]$SvnRebootPending        # Whether SVN reboot is pending
        )
        $mitigations = @(
            @{ Key = 'Mitigation1'; Label = 'Windows CA2023' }
            @{ Key = 'Mitigation2'; Label = 'Boot manager' }
            @{ Key = 'Mitigation3'; Label = '2011 revocation' }
            @{ Key = 'Mitigation4'; Label = 'SVN update' }
        )
        $rebootRequired = $EnfResult.RebootRequired
        $lines = @()
        foreach ($m in $mitigations) {
            $state = $EnfResult[$m.Key]
            $blockedReason = $EnfResult["$($m.Key)BlockedReason"]
            $isMit12 = $m.Key -in @('Mitigation1', 'Mitigation2')
            $isMit34 = $m.Key -in @('Mitigation3', 'Mitigation4')
            # Mit 1+2: show reboot pending when applied but overall reboot required
            $mit12RebootPending = ($isMit12 -and $rebootRequired -and $state -eq 'Applied')
            # Mit 3+4: show SVN reboot pending when already applied/applied but SVN reboot still needed
            $mit34SvnReboot = ($isMit34 -and $SvnRebootPending -and $state -in @('AlreadyApplied', 'Applied'))
            $mIcon = switch ($state) {
                'AlreadyApplied' { Format-CardIcon -Type 'check' -Color $(if ($mit34SvnReboot) { '#3B82F6' } else { '#26A644' }) -Format $Format }
                'Applied'        { Format-CardIcon -Type $(if ($mit12RebootPending) { 'sync' } else { 'check' }) -Color '#3B82F6' -Format $Format }
                'Blocked'        { Format-CardIcon -Type 'ban' -Color '#F59E0B' -Format $Format }
                'Failed'         { Format-CardIcon -Type 'times' -Color '#D9534F' -Format $Format }
                default          { Format-CardIcon -Type 'circle' -Color '#6B7280' -Format $Format }
            }
            $stateLabel = switch ($state) {
                'AlreadyApplied' {
                    if ($mit34SvnReboot) { "<span style='color:#3B82F6;'>Pending SVN reboot</span>" }
                    else { 'Complete' }
                }
                'Applied' {
                    if ($mit12RebootPending) { "<span style='color:#3B82F6;'>Reboot pending</span>" }
                    elseif ($mit34SvnReboot) { "<span style='color:#3B82F6;'>Pending SVN reboot</span>" }
                    else { 'Applied' }
                }
                'Blocked' {
                    if ($blockedReason) { "<span style='color:#F59E0B;'>$blockedReason</span>" }
                    else { 'Blocked' }
                }
                'Failed'  { 'Failed' }
                default   {
                    if ($isMit34) { "<span style='color:#6B7280;'>Awaiting enforcement (June 2026 - 2027)</span>" }
                    elseif ($isMit12) { "<span style='color:#6B7280;'>Not yet applied</span>" }
                    else { "<span style='color:#6B7280;'>Pending</span>" }
                }
            }
            $lines += "$mIcon $($m.Label): $stateLabel"
        }
        return $lines
    }
    
    # Helper function: Build SVN compliance section for card display
    function Build-SvnComplianceSection {
        param ([string]$Format)
        # Status icon and label
        if ($svnStatus.IsCompliant) {
            $svnIcon  = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            $svnLabel = $svnStatus.ComplianceStatus
        }
        elseif ($svnStatus.RebootPending) {
            $svnIcon  = Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format
            $svnLabel = 'Pending SVN reboot - firmware SVN update not yet applied'
        }
        elseif ($svnStatus.RevocationAppliedPendingReboot) {
            $svnIcon  = Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format
            $svnLabel = '2011 CA revocation pending reboot'
        }
        elseif ($svnStatus.RevocationPending) {
            $svnIcon  = Format-CardIcon -Type 'info' -Color '#3B82F6' -Format $Format
            $svnLabel = '2011 CA not yet revoked'
        }
        else {
            $svnIcon  = Format-CardIcon -Type 'warning' -Color '#5BC0DE' -Format $Format
            $svnLabel = $svnStatus.ComplianceStatus
        }
        $parts = @("$svnIcon $svnLabel")
        # SVN version details
        if ($svnStatus.Source -eq 'Raw DBX') {
            $parts += "DBX SVN: $(if ($svnStatus.DbxSVN) { $svnStatus.DbxSVN } else { 'Not present' })"
            if ($null -ne $svnStatus.WindowsUpdateSVN) {
                $parts += "Windows Update SVN: $($svnStatus.WindowsUpdateSVN)"
            }
        }
        else {
            $parts += "Firmware SVN: $($svnStatus.FirmwareSVN)"
            $parts += "Boot Manager SVN: $($svnStatus.BootManagerSVN)"
            $parts += "Staged SVN: $($svnStatus.StagedSVN)"
        }
        # SVN update pending
        if ($svnStatus.SvnUpdatePending) {
            $pendIcon = Format-CardIcon -Type 'clock' -Color '#F59E0B' -Format $Format
            $parts += "$pendIcon SVN update pending (DBXUpdateSVN.bin $($svnStatus.WindowsUpdateSVN) not yet in DBX)"
        }
        # Stage
        if ($null -ne $svnStatus.Stage) {
            $stagePR = $svnStatus.StageDetail -match 'pending SVN reboot'
            $stageIcon = switch ($svnStatus.Stage) {
                'Stage 4'   { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format }
                'Stage 3+4' { Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format }
                'Stage 3'   { if ($stagePR) { Format-CardIcon -Type 'sync' -Color '#F59E0B' -Format $Format } else { Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format } }
                'Stage 2'   { Format-CardIcon -Type 'clock' -Color '#3B82F6' -Format $Format }
                default     { Format-CardIcon -Type 'clock' -Color '#6B7280' -Format $Format }
            }
            $parts += "$stageIcon $($svnStatus.Stage): $($svnStatus.StageDetail)"
        }
        # Enforcement overview - always shown as a playbook status of where each mitigation stands
        $enfSvnReboot = Test-SvnRebootPending -SvnStatus $svnStatus
        # Mode indicator
        if ($EnforceSvnCompliance -eq 'Enforce SVN') {
            $modeIcon = Format-CardIcon -Type 'cog' -Color '#3B82F6' -Format $Format
            $parts += "$modeIcon Enforcement: Active"
            if ($enforceMissingOptIn) {
                $warnIcon = Format-CardIcon -Type 'warning' -Color '#F59E0B' -Format $Format
                $parts += "$warnIcon <span style='color:#F59E0B;'>WU opt-in not enabled. Set securebootAction to &quot;Enable opt-in&quot; for full deployment</span>"
            }
        }
        elseif ($EnforceSvnCompliance -eq 'Passive') {
            $eyeIcon = Format-CardIcon -Type 'eye' -Color '#6B7280' -Format $Format
            $parts += "$eyeIcon Enforcement: Passive (June 2026 - 2027) <span style=`"font-size:0.85em; color:#888;`">(last run)</span>"
        }
        else {
            $eyeIcon = Format-CardIcon -Type 'eye' -Color '#6B7280' -Format $Format
            $parts += "$eyeIcon Enforcement: Not configured (MS enforcement: June 2026 - 2027)"
        }
        $parts += '<b>SVN Enforcement</b>'
        if ($null -ne $svnEnforcementResult) {
            # Active enforcement just ran - use its results
            $parts += Build-EnforcementMitigationLines -Format $Format -EnfResult $svnEnforcementResult -SvnRebootPending $enfSvnReboot
        }
        else {
            # Build ground-truth status from available signals
            $has1799 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799)
            $has1808 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1808)
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            $pca2011Revoked = ($ca2011RevokedInDbx.Count -gt 0)
            $svnInDbx = ($null -ne $svnStatus.DbxSVN -and $svnStatus.DbxSVN -ne 0 -and $svnStatus.DbxSVN -ne '0.0')
            $rebootPending = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
            $bootMgrConfirmed = ($has1799 -or $has1808 -or ($null -ne $servicingStatus -and $servicingStatus.WindowsUEFICA2023Capable -ge 2))
            # Detect if stages 3+4 were pushed ahead of Microsoft's enforcement deadline
            $msEnforcementDate = [datetime]'2026-06-24'
            $ev1037 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1037
            $ev1042 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1042
            $previouslyEnforced = (($null -ne $ev1037 -and $ev1037.Time -lt $msEnforcementDate) -or
                                   ($null -ne $ev1042 -and $ev1042.Time -lt $msEnforcementDate))
            if ($previouslyEnforced) {
                $piIcon = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
                $parts += "&nbsp;&nbsp;&nbsp;&nbsp;<span style='color:#5BC0DE;'>$piIcon Previously enforced (ahead of schedule)</span>"
            }
            # Build a virtual enforcement result for consistent rendering
            $groundTruth = @{
                Mitigation1             = if ($has2023InDb) { 'AlreadyApplied' }
                                          else { $null }
                Mitigation2             = if ($bootMgrConfirmed) { 'AlreadyApplied' }
                                          elseif ($has2023InDb -and $rebootPending) { 'Applied' }
                                          else { $null }
                Mitigation3             = if ($pca2011Revoked -or $has1037) { 'AlreadyApplied' } else { $null }
                Mitigation4             = if ($svnInDbx -or $has1042) { 'AlreadyApplied' } else { $null }
                Mitigation1BlockedReason = $null
                Mitigation2BlockedReason = $null
                Mitigation3BlockedReason = $null
                Mitigation4BlockedReason = $null
                RebootRequired          = $rebootPending
            }
            $parts += Build-EnforcementMitigationLines -Format $Format -EnfResult $groundTruth -SvnRebootPending $enfSvnReboot
        }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build rollout tier / bucket section for card display
    function Build-RolloutTierSection {
        param ([string]$Format)
        $confValue = ($certStatus.Confidence).ToString().Trim()
        Write-Log "INFO" "Rollout Tier: confValue='$confValue' (length=$($confValue.Length))"
        # the array seems to be missing, but the lenght check is a catch all
        if ($confValue -in @('0', 'U', 'N', '') -or $confValue.Length -le 1 -or $confValue -match 'Under Observation|More Data Needed|No Data Observed|Action Required') {
            $content = "<span style='color:#888;'>Under Observation - More Data Needed</span>"
        }
        else {
            $confItems = $confValue -split ',\s*' | ForEach-Object { ($_ -replace '^3P\s+', '').Trim() }
            $confColor = switch -Wildcard ($confValue) { '*High*' { '#26A644' }; '*Action*' { '#D9534F' }; default { '#5BC0DE' } }
            if ($confItems.Count -gt 1) {
                $confLines = @()
                for ($i = 0; $i -lt $confItems.Count; $i++) {
                    $confLines += "&nbsp;&nbsp;&nbsp;&nbsp;$($i + 1). $($confItems[$i])"
                }
                $joined = Join-CardLines -Lines $confLines -Format $Format
                $content = "<span style='color:$confColor;'>$joined</span>"
            }
            else {
                $content = "<span style='color:$confColor;'>$($confItems[0])</span>"
            }
        }
        if ($null -ne $certStatus.SkipReason) {
            $warnIcon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            $content += " &nbsp;$warnIcon $($certStatus.SkipReason)"
        }
        return $content
    }
    
    # Helper function: Build update task section for card display
    function Build-UpdateTaskSection {
        param ([string]$Format)
        if ($scheduledTaskPresent) {
            $icon = Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format
            return "$icon Secure-Boot-Update task present"
        }
        else {
            $icon = Format-CardIcon -Type 'warning' -Color '#D9534F' -Format $Format
            return "$icon Secure-Boot-Update task missing"
        }
    }
    
    # Helper function: Build opt-in status section for card display
    function Build-OptInSection {
        param ([string]$Format)
        $parts = @()
        switch ($optInStatus.Summary) {
            'Enabled'     { $parts += "$(Format-CardIcon -Type 'check' -Color '#26A644' -Format $Format) WU Secure Boot management enabled" }
            'Blocked'     { $parts += "$(Format-CardIcon -Type 'warning' -Color '#F0AD4E' -Format $Format) Opted in but telemetry too low (AllowTelemetry=0)" }
            'Not enabled' { $parts += "$(Format-CardIcon -Type 'info' -Color '#6C757D' -Format $Format) WU Secure Boot management not enabled" }
        }
        if ($null -ne $optInStatus.HighConfidenceOptOut -and $optInStatus.HighConfidenceOptOut -ne 0) {
            $parts += "$(Format-CardIcon -Type 'ban' -Color '#D9534F' -Format $Format) HighConfidenceOptOut is set"
        }
        if ($optInStatus.AvailableUpdatesPolicySet) {
            $apHex = '0x{0:X}' -f $optInStatus.AvailableUpdatesPolicy
            $parts += "$(Format-CardIcon -Type 'building' -Color '#5BC0DE' -Format $Format) AvailableUpdatesPolicy: $apHex (GPO/MDM)"
        }
        return Join-CardLines -Lines $parts -Format $Format
    }
    
    # Helper function: Build event log summary section for card display
    function Build-EventLogSection {
        param ([string]$Format)
        $eventColorMap = @{
            1808 = '#26A644'; 1799 = '#26A644'; 1037 = '#26A644'; 1042 = '#26A644'
            1801 = '#F0AD4E'; 1800 = '#F0AD4E'
            1032 = '#D9534F'; 1033 = '#D9534F'; 1795 = '#D9534F'; 1796 = '#D9534F'
            1797 = '#D9534F'; 1798 = '#D9534F'; 1802 = '#D9534F'; 1803 = '#D9534F'
        }
        $lines = @()
        foreach ($entry in ($certStatus.EventSummary | Sort-Object LastSeen)) {
            $timeStr = $entry.LastSeen.ToString('yyyy-MM-dd HH:mm')
            $color = if ($eventColorMap.ContainsKey($entry.Id)) { $eventColorMap[$entry.Id] } else { '#5BC0DE' }
            $lines += "<span style='color:$color;'>$timeStr &nbsp; [$($entry.Id)] $($entry.Description) ($($entry.Count)x)</span>"
        }
        # Reboot correlation annotation
        if ($null -ne $certStatus.RebootCorrelation) {
            $rc = $certStatus.RebootCorrelation
            if ($rc.Confirmed) {
                $bootTimeStr = $rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm')
                $syncIcon = Format-CardIcon -Type 'sync' -Color '#5BC0DE' -Format $Format
                $lines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;$syncIcon Reboot at $bootTimeStr bridged 1800 &rarr; 1799</span>"
            }
            else {
                $qIcon = Format-CardIcon -Type 'question' -Color '#F0AD4E' -Format $Format
                $lines += "<span style='color:#F0AD4E;'>&nbsp;&nbsp;&nbsp;$qIcon 1800 &rarr; 1799 detected but no reboot found between them</span>"
            }
        }
        # 1799 pending-1808 note
        if ($pending1808Note) {
            $iIcon = Format-CardIcon -Type 'info' -Color '#5BC0DE' -Format $Format
            $lines += "<span style='color:#5BC0DE;'>&nbsp;&nbsp;&nbsp;$iIcon 1808 expected on next scheduled task cycle</span>"
        }
        return Join-CardLines -Lines $lines -Format $Format
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
    
    # Capability detection: KB5077241 (Feb 2025) added Get-SecureBootSVN and -Decoded parameter
    $script:HasDecodedParam = $false
    $script:HasSVNCmdlet    = $false
    try {
        $decodedParam = (Get-Command Get-SecureBootUEFI -ErrorAction Stop).Parameters.ContainsKey('Decoded')
        $script:HasDecodedParam = $decodedParam
    }
    catch { }
    try {
        $null = Get-Command Get-SecureBootSVN -ErrorAction Stop
        $script:HasSVNCmdlet = $true
    }
    catch { }
    if ($script:HasDecodedParam) { Write-Log  "INFO" "Get-SecureBootUEFI -Decoded parameter available (KB5077241+)" }
    if ($script:HasSVNCmdlet)    { Write-Log "INFO" "Get-SecureBootSVN cmdlet available (KB5077241+)" }
    
    # --- SVN (Security Version Number) functions ---
    # SVN tracks boot component revocation levels stored as EFI_CERT_SHA256_GUID entries in UEFI DBX.
    # Introduced with the Feb 2025 Secure Boot hardening rollout (KB5046714 -> KB5077241):
    #   Stage 1 (May 2024)  : 2023 certs added to db via Windows Update
    #   Stage 2 (Feb 2025)  : 2023 boot manager deployed, Get-SecureBootSVN cmdlet added (KB5077241)
    #   Stage 3 (est. 2026) : PCA 2011 revoked in dbx, SVN enforcement begins
    #   Stage 4 (est. 2027) : Full enforcement - 2011 certs removed from db
    # SVN progression: 0.0 (none) -> 2.0 (PCA 2011 revoked via DBXUpdate2024.bin) -> 7.0 (via DBXUpdateSVN.bin)
    # GUID prefixes for BootMgr, CDBoot, WDSMgr EFI files
    # Source: https://github.com/microsoft/secureboot_objects/blob/main/Archived/dbx_info_msft_4_09_24_svns.csv
    $script:EFI_BOOTMGR_DBXSVN_GUID = '01612B139DD5598843AB1C185C3CB2EB92'
    $script:EFI_CDBOOT_DBXSVN_GUID  = '019D2EF8E827E15841A4884C18ABE2F284'
    $script:EFI_WDSMGR_DBXSVN_GUID  = '01C2CA99C9FE7F6F4981279E2A8A535976'
    # SHA256 signature type GUID for raw byte parsing
    $script:EFI_CERT_SHA256_GUID = [Guid]::new("c1c41626-504c-4092-aca9-41f936934328")
    
    # Extract SVN version from a hex signature data string
    # Source: https://github.com/microsoft/secureboot_objects/blob/main/scripts/utility_functions.py
    function Get-SignatureDataSVN {
        param ([string]$SignatureData)
        try {
            $major = [int]::Parse($SignatureData.Substring(36, 4), [System.Globalization.NumberStyles]::HexNumber)
            $minor = [int]::Parse($SignatureData.Substring(40, 4), [System.Globalization.NumberStyles]::HexNumber)
            return '{0}.{1}' -f $major, $minor
        }
        catch { return $null }
    }
    
    # Read all SHA256 signature hex strings from raw UEFI database bytes
    function Get-DbxSignatureData {
        param ([byte[]]$Bytes)
        $sigDataList = @()
        $offset = 0
        while ($offset -lt $Bytes.Length) {
            $start = $offset
            if (($offset + 28) -gt $Bytes.Length) {
                break
            }
            $guidBytes = [byte[]]$Bytes[$offset..($offset + 15)]
            $guid = [Guid]::new($guidBytes)
            $offset += 16
            $listSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            $headerSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            $sigSize = [BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
            if ($listSize -eq 0 -or ($start + $listSize) -gt $Bytes.Length) {
                break
            }
            if ($guid -ne $script:EFI_CERT_SHA256_GUID) {
                $offset = $start + $listSize
                continue
            }
            $offset += $headerSize
            $remaining = $listSize - 28 - $headerSize
            if ($remaining -le 0 -or $sigSize -eq 0) { $offset = $start + $listSize;
                continue
            }
            $numSigs = [math]::Floor($remaining / $sigSize)
            for ($i = 0; $i -lt $numSigs; $i++) {
                if (($offset + $sigSize) -gt $Bytes.Length) {
                    break
                }
                $sigBytes = [byte[]]$Bytes[$offset..($offset + $sigSize - 1)]
                $offset += $sigSize
                # Skip first 16 bytes (SignatureOwner GUID), output only the hash data
                # Matches garlin's format: SignatureDataBytes[0x10..0x2F]
                # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
                if ($sigBytes.Length -gt 16) {
                    $hashBytes = [byte[]]$sigBytes[16..($sigBytes.Length - 1)]
                    $hexStr = ($hashBytes | ForEach-Object { $_.ToString('X2') }) -join ''
                    $sigDataList += $hexStr
                }
            }
        }
        return $sigDataList
    }
    
    # Read BootMgr SVN from raw UEFI DBX variable bytes
    # Adapted from garlin's Check_UEFI-CA2023.ps1 Get-SecureBootUEFI_DBXSVN
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    function Get-DbxBootMgrSVN {
        param ([byte[]]$DbxBytes)
        if ($null -eq $DbxBytes -or $DbxBytes.Length -eq 0) {
            return $null
        }
        $sigData = Get-DbxSignatureData -Bytes $DbxBytes
        $matches = @($sigData | Where-Object { $_ -match "^$($script:EFI_BOOTMGR_DBXSVN_GUID)" } | Sort-Object)
        if ($matches.Count -eq 0) {
            return $null
        }
        return Get-SignatureDataSVN $matches[-1]
    }
    
    # Read expected SVN from Windows Update staging file (DBXUpdateSVN.bin)
    # Source: https://github.com/microsoft/secureboot_objects
    function Get-WindowsUpdateSVN {
        $svnFile = "$env:SystemRoot\System32\SecureBootUpdates\DBXUpdateSVN.bin"
        if (-not (Test-Path $svnFile)) {
            return $null
        }
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($svnFile)
            $sigData = Get-DbxSignatureData -Bytes $fileBytes
            $matches = @($sigData | Where-Object { $_ -match "^$($script:EFI_BOOTMGR_DBXSVN_GUID)" })
            if ($matches.Count -eq 0) {
                return $null
            }
            return Get-SignatureDataSVN $matches[0]
        }
        catch {
            Write-Log "WARNING" "Failed to read DBXUpdateSVN.bin: $($_.Exception.Message)"
            return $null
        }
    }
    
    # Get Secure Boot SVN status - always reads raw DBX bytes, enriches with cmdlet if available
    # Raw DBX parsing provides pending update detection via DBXUpdateSVN.bin comparison
    # Get-SecureBootSVN cmdlet (KB5077241+) adds FirmwareSVN, BootManagerSVN, BootManagerPath
    # Adapted from garlin's Check_UEFI-CA2023.ps1
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    function Get-SecureBootSVNStatus {
        param ([byte[]]$DbxBytes)
        # Always read raw DBX for DBX SVN + pending update detection
        $currentSVN = if ($null -ne $DbxBytes -and $DbxBytes.Length -gt 0) {
            Get-DbxBootMgrSVN -DbxBytes $DbxBytes
        }
        else { $null }
        $windowsUpdateSVN = Get-WindowsUpdateSVN
        $svnPresent = ($null -ne $currentSVN)
        # Determine pending SVN update (Windows Update has higher SVN than current DBX)
        $svnUpdatePending = if ($null -ne $windowsUpdateSVN) {
            ($null -eq $currentSVN) -or ([version]$currentSVN -lt [version]$windowsUpdateSVN)
        }
        else { $false }
        # Try Get-SecureBootSVN cmdlet for richer info (KB5077241+)
        $cmdletResult = $null
        if ($script:HasSVNCmdlet) {
            try {
                $cmdletResult = Get-SecureBootSVN -ErrorAction Stop
            }
            catch {
                Write-Log "WARNING" "Get-SecureBootSVN failed: $($_.Exception.Message)"
            }
        }
        # Build result - cmdlet provides compliance/firmware info, raw DBX provides pending update detection
        if ($null -ne $cmdletResult) {
            $isCompliant = $cmdletResult.ComplianceStatus -match '^Compliant'
            return @{
                FirmwareSVN      = $cmdletResult.FirmwareSVN
                BootManagerSVN   = $cmdletResult.BootManagerSVN
                StagedSVN        = $cmdletResult.StagedSVN
                ComplianceStatus = $cmdletResult.ComplianceStatus
                BootManagerPath  = $cmdletResult.BootManagerPath
                IsCompliant      = $isCompliant
                Source           = 'Get-SecureBootSVN'
                DbxSVN           = $currentSVN
                WindowsUpdateSVN = $windowsUpdateSVN
                SvnUpdatePending = $svnUpdatePending
            }
        }
        # Raw DBX only - no cmdlet available
        # Note: SVN may not appear in DBX bytes until after reboot even if Event 1042 confirms (it does seem to show even with a pending SVN reboot in my testing)
        # the scheduled task processed the 0x200 bit - UEFI NVRAM writes can be deferred.
        $isCompliant = $svnPresent -and ($null -ne $windowsUpdateSVN) -and ([version]$currentSVN -ge [version]$windowsUpdateSVN)
        # Also treat as compliant if SVN is in DBX and there's no staging file to compare against
        if ($svnPresent -and $null -eq $windowsUpdateSVN) { $isCompliant = $true }
        $complianceStatus = if ($isCompliant) {
            'Compliant'
        }
        elseif (-not $svnPresent -and $null -eq $windowsUpdateSVN) {
            'SVN not yet in DBX (pending SVN reboot or not yet applied)'
        }
        elseif (-not $svnPresent) {
            'SVN not present in DBX'
        }
        else {
            "DBX SVN $currentSVN < staged $windowsUpdateSVN"
        }
        return @{
            FirmwareSVN      = if ($svnPresent) { $currentSVN } else { 'N/A' }
            BootManagerSVN   = 'N/A'
            StagedSVN        = if ($null -ne $windowsUpdateSVN) { $windowsUpdateSVN } else { 'N/A' }
            ComplianceStatus = $complianceStatus
            BootManagerPath  = $null
            IsCompliant      = $isCompliant
            Source           = 'Raw DBX'
            DbxSVN           = $currentSVN
            WindowsUpdateSVN = $windowsUpdateSVN
            SvnUpdatePending = $svnUpdatePending
        }
    }
    
    # Helper function: Parse UEFI database using -Decoded (KB5077241+) or fallback to raw byte parsing
    # Returns array of X509Certificate2 objects either way
    function Get-UefiDatabaseCerts {
        param (
            [string]$Name   # db, KEK, dbx, dbDefault
        )
        if ($script:HasDecodedParam) {
            try {
                $decoded = Get-SecureBootUEFI -Name $Name -Decoded -ErrorAction Stop
                # -Decoded (KB5077241+) returns flat objects with Subject, ValidFrom, ValidTo, etc.
                # These are NOT X509Certificate2 objects. Normalize them to match the interface
                # the downstream code expects (Subject, NotBefore, NotAfter).
                $entries = @($decoded)
                # -Decoded returns ALL signature entries: X509 certs (have Subject) AND
                # SHA256 hashes (no Subject). Filter to only entries with a Subject.
                $certs = @()
                foreach ($entry in $entries) {
                    if (-not [string]::IsNullOrWhiteSpace($entry.Subject)) {
                        $certObj = [PSCustomObject]@{
                            Subject   = $entry.Subject
                            NotBefore = if ($entry.ValidFrom) { [DateTime]$entry.ValidFrom } else { [DateTime]::MinValue }
                            NotAfter  = if ($entry.ValidTo)   { [DateTime]$entry.ValidTo }   else { [DateTime]::MaxValue }
                        }
                        $certs += $certObj
                    }
                }
                if ($certs.Count -gt 0) {
                    $skipped = $entries.Count - $certs.Count
                    if ($skipped -gt 0) { Write-Log "INFO" "$Name -Decoded: $($certs.Count) certs, $skipped hash entries skipped" }
                    return @{ Certs = $certs; Bytes = $null; UsedDecoded = $true }
                }
                Write-Log "INFO" "-Decoded returned no certificate entries for $Name ($($entries.Count) hash-only entries), falling back to raw parse"
            }
            catch {
                Write-Log "WARNING" "-Decoded failed for $Name ($($_.Exception.Message)), falling back to raw parse"
            }
        }
        # Fallback: raw byte parsing
        try {
            $uefiVar = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
            $bytes = $uefiVar.Bytes
            $certs = Parse-UefiSignatureDatabase -Bytes $bytes
            return @{ Certs = $certs; Bytes = $bytes; UsedDecoded = $false }
        }
        catch {
            Write-Log "WARNING" "Failed to read UEFI variable '$Name': $($_.Exception.Message)"
            return @{ Certs = @(); Bytes = $null; UsedDecoded = $false }
        }
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
    #   1045 = Microsoft UEFI CA 2023 added to DB
    #   1036 = DB variable applied
    #   1034 = DBX variable applied
    #   1037 = 2011 CA revoked in DBX (Mitigation 3)
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
        1045 = 'Microsoft UEFI CA 2023 added to DB'
        1036 = 'DB variable applied'
        1034 = 'DBX variable applied'
        1037 = '2011 CA revoked in DBX (Mitigation 3)'
        1042 = 'Boot Manager SVN applied to DBX (Mitigation 4)'
        # Blocker events
        1032 = 'BitLocker conflict'
        1033 = 'Vulnerable bootloader in EFI partition'
        # Firmware / prerequisite errors
        1795 = 'Firmware returned an error'
        1796 = 'Unexpected update error (will retry on reboot)'
        1797 = 'Windows UEFI CA 2023 not in DB (DBX prerequisite failure)'
        1798 = 'Boot manager not signed with 2023 cert'
        1802 = 'Update blocked (known firmware limitation)'
        1803 = 'PK-signed KEK not found (OEM issue)'
    }
    
    # All event IDs being query'd for (18 total per MS KB5016061)
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
            foreach ($entry in ($eventSummary | Sort-Object LastSeen)) {
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
        
        # If ther are deployment events (1043-1045, 1036, etc.) but no state events,
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
                $msg    = 'Boot manager signed with Windows UEFI CA 2023 installed successfully (Event 1799)'
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
            # Clean up Confidence: strip "UpdateType:" prefix if present (e.g., "UpdateType:ActionRequired" -> "ActionRequired")
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
        
        # Detect 1800 -> 1799 progression (reboot between them confirms the sequence)
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
                Write-Log "INFO" "1800 ($($ev1800.Time.ToString('HH:mm'))) -> 1799 ($($ev1799.Time.ToString('HH:mm'))) detected, but no reboot found between them"
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
        if ($Value -band 0x0080)               { $meaning += 'Revoke PCA 2011 in DBX (Mitigation 3)' }
        if ($Value -band 0x0100)               { $meaning += 'Install boot manager signed with Windows UEFI CA 2023' }
        if ($Value -band 0x0200)               { $meaning += 'Apply SVN to DBX firmware (Mitigation 4)' }
        if ($Value -band 0x0800)               { $meaning += 'Apply Microsoft Option ROM UEFI CA 2023' }
        if ($Value -band 0x1000)               { $meaning += 'Apply Microsoft UEFI CA 2023' }
        # 0x4000 = conditional qualifier (apply only if UEFI CA 2011 trusted) - always present, not displayed
        
        # Detect undocumented bits
        $knownBits = 0x0004 -bor 0x0040 -bor 0x0080 -bor 0x0100 -bor 0x0200 -bor 0x0800 -bor 0x1000 -bor 0x4000 -bor 0x4004
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
            
            # Don’t fight PowerShell’s Binary comparison semantics here - treat as success
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
        
        # Unload any hives that were loaded
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
    
    # Helper function: Set the Secure Boot opt-in gate key (MicrosoftUpdateManagedOptIn only)
    # Does NOT write AvailableUpdates - stage pushing is handled by EnforceSvnCompliance
    function Set-SecureBootOptInKeys {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $optInValue = 0x5944  # Microsoft Update managed opt-in magic value
        
        try {
            Write-Log "INFO" "Setting Secure Boot opt-in key (MicrosoftUpdateManagedOptIn)"
            RegistryShouldBe -KeyPath $regPath -Name "MicrosoftUpdateManagedOptIn" -Value $optInValue
            Write-Log "SUCCESS" "Secure Boot opt-in key set (MicrosoftUpdateManagedOptIn = 0x5944)"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to set opt-in key: $($_.Exception.Message)"
            return $false
        }
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
    
    # Legacy wrappers - delegate to unified Get-OemGuide function
    function Get-OemKeyResetGuide  { return Get-OemGuide -GuideType 'KeyReset' }
    function Get-OemBIOSUpdateGuide { return Get-OemGuide -GuideType 'BIOSUpdate' }
    
    # =======================================================================
    # SVN Stage Prerequisites Check (Test-SvnStagePrerequisites)
    # =======================================================================
    # GATE for Mitigation 3+4. Stage 1 + Stage 2 must be VERIFIED complete.
    # Used by Invoke-SvnEnforcement (gate) and Repair-SvnEnforcement (fix).
    #
    # Stage 1 (Mitigation 1 / 0x40): Add Windows UEFI CA 2023 to DB
    #   - Ground truth: $Has2023InDb (direct UEFI db read after 30s wait)
    #   - Manifest:     0x40 bit must be consumed (no longer in AvailableUpdates)
    #   - BOTH must pass: cert physically present AND OS finished processing
    #
    # Stage 2 (Mitigation 2 / 0x100): Install 2023-signed boot manager
    #   - Ground truth: Event 1799 (boot manager installed) or 1808 (compliant)
    #   - Manifest:     0x100 bit must be consumed (no longer in AvailableUpdates)
    #   - BOTH must pass: event confirmed AND OS finished processing
    #   - "Applied" status alone is NOT sufficient - only means triggered, not done
    #
    # Reboot check:
    #   - Event 1800 = cert deployment still in progress, reboot needed
    #   - Unverified Mitigation 2 (triggered but no 1799/1808) = treat as reboot needed
    #   - $CertStatus may predate enforcement, so 1800 is re-checked post-trigger
    #
    # ALL checks must pass. If ANY fails, Mitigation 3+4 are blocked.
    #
    # Returns hashtable: Stage1Done, Stage2Done, RebootPending, AllPrereqsMet,
    #   Stage3/4Applied (1037/1042 events), Stage3/4BitPending (0x80/0x200 in
    #   manifest), CurrentManifest, BlockReason.
    # =======================================================================
    function Test-SvnStagePrerequisites {
        param (
            [bool]$Has2023InDb,
            [hashtable]$CertStatus,
            [hashtable]$SvnEnforcementResult   # Optional - only set during active enforcement
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        # --- Event checks ---
        $has1799 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1799)
        $has1808 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1808)
        $has1037 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1037)
        $has1042 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1042)
        $has1800 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1800)
        
        # --- Manifest checks ---
        $currentAv = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
        if ($null -eq $currentAv) { $currentAv = 0 }
        
        $stage1BitPending = ($currentAv -band 0x0040) -ne 0   # DB cert (0x40) still in manifest
        $stage2BitPending = ($currentAv -band 0x0100) -ne 0   # Boot manager (0x100) still in manifest
        $stage3BitPending = ($currentAv -band 0x0080) -ne 0   # 2011 revocation (0x80) in manifest
        $stage4BitPending = ($currentAv -band 0x0200) -ne 0   # SVN update (0x200) in manifest
        
        # --- Stage 1: 2023 cert in UEFI db ---
        $stage1Done = $Has2023InDb -and -not $stage1BitPending
        $stage1Detail = if (-not $Has2023InDb) { 'Cert not in db' }
                        elseif ($stage1BitPending) { 'Cert in db but 0x40 still pending in manifest' }
                        else { 'Complete' }
        
        # --- Stage 2: Boot manager confirmed via event ---
        $bootMgrConfirmed = ($has1799 -or $has1808)
        $stage2Done = $bootMgrConfirmed -and -not $stage2BitPending
        $stage2Detail = if (-not $bootMgrConfirmed) { 'No 1799/1808 event (boot manager unconfirmed)' }
                        elseif ($stage2BitPending) { 'Event confirmed but 0x100 still pending in manifest' }
                        else { 'Complete' }
        
        # --- Reboot pending ---
        $rebootPending = $has1800
        if (-not $rebootPending -and $null -ne $SvnEnforcementResult -and $SvnEnforcementResult.Mitigation2 -eq 'Applied') {
            # Mitigation 2 was just triggered - if no confirmation event, treat as reboot pending
            $rebootPending = (-not $has1799 -and -not $has1808)
        }
        
        # --- Stage 3+4 status ---
        $stage3Applied = $has1037
        $stage4Applied = $has1042
        
        return @{
            Stage1Done        = $stage1Done
            Stage1Detail      = $stage1Detail
            Stage2Done        = $stage2Done
            Stage2Detail      = $stage2Detail
            RebootPending     = $rebootPending
            AllPrereqsMet     = ($stage1Done -and $stage2Done -and -not $rebootPending)
            Stage3Applied     = $stage3Applied      # 1037 event = DBX already modified
            Stage4Applied     = $stage4Applied      # 1042 event = SVN already in DBX
            Stage3BitPending  = $stage3BitPending   # 0x80 in manifest but no 1037 yet
            Stage4BitPending  = $stage4BitPending   # 0x200 in manifest but no 1042 yet
            CurrentManifest   = $currentAv
            BlockReason       = if ($rebootPending) { 'Enforce again after stages 1-2 complete' }
                                elseif (-not $stage1Done) { $stage1Detail }
                                elseif (-not $stage2Done) { $stage2Detail }
                                else { $null }
        }
    }
    
    # =======================================================================
    # SVN Enforcement Repair Function
    # =======================================================================
    # Checks if Stage 3+4 mitigations were prematurely triggered (before Stage
    # 1+2 were verified complete) and attempts to clear the pending bits from
    # AvailableUpdates before they are processed on the next reboot.
    #
    # REVERSIBILITY:
    #   - If 1037/1042 have NOT fired: bits 0x80/0x200 can be cleared from the
    #     registry. The scheduled task won't process them. DBX is untouched.
    #   - If 1037/1042 HAVE fired: DBX has already been modified. The only
    #     recovery is a BIOS "Restore Factory Keys" (OEM-dependent, removes
    #     all security protections). Cannot be done programmatically.
    #     Uses Get-OemKeyResetGuide to provide OEM-specific BIOS instructions.
    #
    # Source: KB5025885 - "After the mitigation is enabled on a device, it
    #   cannot be reverted if you continue to use Secure Boot on that device."
    # Source: Enterprise Deployment Guidance for CVE-2023-24932 - "If
    #   Mitigations 3 and/or 4 have been applied and the DBX is cleared,
    #   then reapplying mitigations 3 and/or 4 will be necessary."
    # =======================================================================
    function Repair-SvnEnforcement {
        param (
            [bool]$Has2023InDb,
            [hashtable]$CertStatus
        )
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        
        $result = [ordered]@{
            Action          = 'None'
            BitsCleared     = @()
            BitsFailed      = @()
            IrreversibleDbx = @()
            Detail          = ''
            OemKeyResetGuide = $null
            RebootAdvised   = $false
        }
        
        # Check prerequisites
        $prereqs = Test-SvnStagePrerequisites -Has2023InDb $Has2023InDb -CertStatus $CertStatus
        
        if ($prereqs.AllPrereqsMet) {
            $result.Action = 'None'
            $result.Detail = 'Stage 1+2 prerequisites are met. No repair needed.'
            Write-Log "INFO" "SVN Repair: Prerequisites met - no repair needed"
            return $result
        }
        
        # Check what Stage 3+4 state is in
        $needsRepair = $false
        
        # Stage 3: Check if 0x80 was set prematurely
        if ($prereqs.Stage3Applied) {
            # Event 1037 fired - DBX already modified, cannot undo from Windows
            $result.IrreversibleDbx += 'Mitigation 3 (PCA 2011 revocation in DBX - Event 1037 confirmed)'
            Write-Log "WARNING" "SVN Repair: Mitigation 3 already applied to DBX (Event 1037). Cannot revert from Windows."
            $needsRepair = $true
        }
        elseif ($prereqs.Stage3BitPending) {
            # 0x80 in manifest but no 1037 - can clear the bit before next reboot
            $needsRepair = $true
        }
        
        # Stage 4: Check if 0x200 was set prematurely
        if ($prereqs.Stage4Applied) {
            # Event 1042 fired - SVN already in DBX, cannot undo from Windows
            $result.IrreversibleDbx += 'Mitigation 4 (SVN update in DBX - Event 1042 confirmed)'
            Write-Log "WARNING" "SVN Repair: Mitigation 4 already applied to DBX (Event 1042). Cannot revert from Windows."
            $needsRepair = $true
        }
        elseif ($prereqs.Stage4BitPending) {
            # 0x200 in manifest but no 1042 - can clear the bit before next reboot
            $needsRepair = $true
        }
        
        if (-not $needsRepair) {
            $result.Action = 'None'
            $result.Detail = 'No Stage 3+4 bits pending or applied. Nothing to repair.'
            Write-Log "INFO" "SVN Repair: No Stage 3+4 activity detected"
            return $result
        }
        
        # Attempt to clear pending bits (only those not yet applied to DBX)
        $currentAv = $prereqs.CurrentManifest
        $bitsToRemove = 0
        
        if ($prereqs.Stage3BitPending -and -not $prereqs.Stage3Applied) {
            $bitsToRemove = $bitsToRemove -bor 0x0080
            Write-Log "INFO" "SVN Repair: Will clear Mitigation 3 bit (0x80) - not yet applied to DBX"
        }
        if ($prereqs.Stage4BitPending -and -not $prereqs.Stage4Applied) {
            $bitsToRemove = $bitsToRemove -bor 0x0200
            Write-Log "INFO" "SVN Repair: Will clear Mitigation 4 bit (0x200) - not yet applied to DBX"
        }
        
        if ($bitsToRemove -ne 0) {
            $newAv = $currentAv -band (-bnot $bitsToRemove)
            $oldHex = '0x{0:X}' -f $currentAv
            $newHex = '0x{0:X}' -f $newAv
            $removedHex = '0x{0:X}' -f $bitsToRemove
            Write-Log "INFO" "SVN Repair: Clearing bits $removedHex from AvailableUpdates ($oldHex -> $newHex)"
            
            try {
                Set-ItemProperty -Path $regPath -Name 'AvailableUpdates' -Value $newAv -Type DWord -Force
                # Verify the write
                $verifyAv = (Get-ItemProperty -Path $regPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                              Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
                if ($verifyAv -eq $newAv) {
                    Write-Log "SUCCESS" "SVN Repair: AvailableUpdates updated to $newHex (verified)"
                    if ($bitsToRemove -band 0x0080) { $result.BitsCleared += 'Mitigation 3 (0x80 - PCA 2011 revocation)' }
                    if ($bitsToRemove -band 0x0200) { $result.BitsCleared += 'Mitigation 4 (0x200 - SVN update)' }
                    $result.Action = 'BitsCleared'
                    $result.RebootAdvised = $true
                }
                else {
                    Write-Log "ERROR" "SVN Repair: Verification failed - AvailableUpdates is 0x$($verifyAv.ToString('X')), expected $newHex"
                    if ($bitsToRemove -band 0x0080) { $result.BitsFailed += 'Mitigation 3 (0x80)' }
                    if ($bitsToRemove -band 0x0200) { $result.BitsFailed += 'Mitigation 4 (0x200)' }
                    $result.Action = 'Failed'
                }
            }
            catch {
                Write-Log "ERROR" "SVN Repair: Failed to update AvailableUpdates: $($_.Exception.Message)"
                if ($bitsToRemove -band 0x0080) { $result.BitsFailed += 'Mitigation 3 (0x80)' }
                if ($bitsToRemove -band 0x0200) { $result.BitsFailed += 'Mitigation 4 (0x200)' }
                $result.Action = 'Failed'
            }
        }
        
        # Build summary
        $detailParts = @()
        if ($result.BitsCleared.Count -gt 0) {
            $detailParts += "Cleared pending bits: $($result.BitsCleared -join '; ')"
        }
        if ($result.BitsFailed.Count -gt 0) {
            $detailParts += "Failed to clear: $($result.BitsFailed -join '; ')"
        }
        if ($result.IrreversibleDbx.Count -gt 0) {
            $detailParts += "IRREVERSIBLE (already in DBX): $($result.IrreversibleDbx -join '; ')"
            $detailParts += 'Recovery requires a BIOS Secure Boot key reset (Restore Factory Keys)'
            # Look up OEM-specific key reset guide
            $oemGuide = Get-OemKeyResetGuide
            if ($oemGuide) {
                $result.OemKeyResetGuide = $oemGuide
                $detailParts += "OEM Key Reset Guide: $oemGuide"
                Write-Log "INFO" "SVN Repair: OEM key reset guide available: $oemGuide"
            }
            else {
                $detailParts += 'No OEM-specific key reset guide found. Check BIOS setup for "Restore Factory Keys" or "Reset Secure Boot Keys".'
            }
            Write-Log "ERROR" "SVN Repair: DBX modifications are irreversible from Windows. BIOS Secure Boot key reset required."
        }
        $detailParts += "Prerequisites not met: $($prereqs.BlockReason)"
        $result.Detail = $detailParts -join '. '
        
        Write-Log "INFO" "SVN Repair result: $($result.Detail)"
        return $result
    }
    
    # =======================================================================
    # SVN Enforcement Function
    # =======================================================================
    # Applies the KB5025885 Secure Boot hardening mitigations (CVE-2023-24932 enterprise deployment guidance).
    # Each mitigation is a specific AvailableUpdates bitmask value + scheduled task trigger.
    # The function is idempotent - it checks current state before each step and skips
    # mitigations that have already been applied.
    #
    # Mitigation 1 (0x40)  : Add Windows UEFI CA 2023 cert to DB
    # Mitigation 2 (0x100) : Install 2023-signed boot manager
    # Mitigation 3 (0x80)  : Revoke PCA 2011 in DBX - blocks old boot managers
    # Mitigation 4 (0x200) : Apply SVN update to firmware DBX - prevents rollback
    #
    # Combined Mitigation 3+4 (0x280) per CVE-2023-24932 enterprise guidance - single reboot.
    #
    # Source: https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    # Source: https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
    # =======================================================================
    function Invoke-SvnEnforcement {
        param (
            [bool]$Has2023InDb,
            [bool]$Has2023InKek,
            [hashtable]$SvnStatus,
            [hashtable]$CertStatus,
            [byte[]]$DbxBytes,
            [array]$Ca2011RevokedInDbx,
            [string[]]$DbCertsFound = @()
        )
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $results = [ordered]@{
            Mitigation1 = $null   # DB cert
            Mitigation2 = $null   # Boot manager
            Mitigation3 = $null   # 2011 revocation
            Mitigation4 = $null   # SVN update
            Mitigation1BlockedReason = $null
            Mitigation2BlockedReason = $null
            Mitigation3BlockedReason = $null
            Mitigation4BlockedReason = $null
            RebootRequired = $false
            SupplementaryCertsAttempted = $false
            ActionsApplied = @()
            ActionsSkipped = @()
        }
        
        # --- Pre-flight checks ---
        Write-Log "INFO" "SVN Enforcement: Evaluating current mitigation state"
        
        # Check for Event 1803 (OEM blocker) - if present, enforcement cannot proceed past Mitigation 1
        $has1803 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1803)
        if ($has1803) {
            Write-Log "WARNING" "Event 1803 detected - OEM has not provided PK-signed KEK. Enforcement limited."
        }
        
        # Detect which mitigations are already complete
        $has1037 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1037)
        $has1042 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1042)
        $has1808 = ($null -ne $CertStatus -and $CertStatus.EventId -eq 1808)
        
        # Boot manager check - Event 1799 indicates boot manager was installed
        $has1799 = (Test-HasSecureBootEvent -CertStatus $CertStatus -EventId 1799)
                    
        # Check if 2011 CA is already revoked in DBX (Mitigation 3 complete without needing event)
        $pca2011Revoked = ($Ca2011RevokedInDbx.Count -gt 0)
        
        # Check if SVN is already in DBX (Mitigation 4 complete without needing event)
        $svnInDbx = ($null -ne $SvnStatus -and $null -ne $SvnStatus.DbxSVN)
        
        # -----------------------------------------------
        # Mitigation 1: Add Windows UEFI CA 2023 to DB (0x40)
        # -----------------------------------------------
        if ($Has2023InDb) {
            Write-Log "INFO" "Mitigation 1: SKIP - 2023 cert already in db"
            $results.Mitigation1 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 1 (DB cert)'
        }
        else {
            Write-Log "INFO" "Mitigation 1: Applying - adding Windows UEFI CA 2023 to DB (0x40)"
            try {
                $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value 0x40
                $null = Trigger-SecureBootTask
                Write-Log "SUCCESS" "Mitigation 1: Triggered DB cert update (0x40)"
                $results.Mitigation1 = 'Applied'
                $results.ActionsApplied += 'Mitigation 1 (DB cert)'
                $results.RebootRequired = $true
                
                # Wait and verify
                Write-Log "INFO" "Mitigation 1: Waiting 30 seconds for update to process"
                Start-Sleep -Seconds 30
                
                # Re-read db to check if cert appeared
                $recheck = Get-UefiDatabaseCerts -Name db
                $recheckNames = @($recheck.Certs | Where-Object {
                    $_.Subject -match '2023'
                } | ForEach-Object {
                    if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                })
                if ($recheckNames -contains 'Windows UEFI CA 2023') {
                    Write-Log "SUCCESS" "Mitigation 1: Verified - Windows UEFI CA 2023 now in db$(if ($recheckNames.Count -gt 1) { " (also found: $(($recheckNames | Where-Object { $_ -ne 'Windows UEFI CA 2023' }) -join ', '))" })"
                    $Has2023InDb = $true
                }
                elseif ($recheckNames.Count -gt 0) {
                    Write-Log "WARNING" "Mitigation 1: Found $($recheckNames -join ', ') in db but Windows UEFI CA 2023 not yet visible - may require reboot"
                }
                else {
                    Write-Log "WARNING" "Mitigation 1: Cert not yet visible in db - may require reboot"
                }
            }
            catch {
                Write-Log "ERROR" "Mitigation 1 failed: $($_.Exception.Message)"
                $results.Mitigation1 = 'Failed'
                return $results
            }
        }
        
        # -----------------------------------------------
        # Supplementary: Best-effort application of optional db certs
        # Microsoft UEFI CA 2023 (0x1000) + Option ROM UEFI CA 2023 (0x0800)
        # These are not required for enforcement progression but are preferred
        # for full compliance. Attempt only after Mitigation 1 confirms the
        # required Windows UEFI CA 2023 is in db. Does NOT gate Mitigation 2.
        # -----------------------------------------------
        if ($Has2023InDb) {
            # Determine current db cert inventory (use recheck if Mitigation 1 just ran, else use caller data)
            $currentDbCerts = if ($recheckNames -and $recheckNames.Count -gt 0) {
                # Merge: recheck captures what's in db now; also keep caller's original findings
                @($DbCertsFound) + @($recheckNames) | Select-Object -Unique
            }
            else {
                @($DbCertsFound)
            }
            
            $optionalCerts = @(
                @{ Name = 'Microsoft UEFI CA 2023';            Bit = 0x1000 }
                @{ Name = 'Microsoft Option ROM UEFI CA 2023'; Bit = 0x0800 }
            )
            $missingOptional = @($optionalCerts | Where-Object { $currentDbCerts -notcontains $_.Name })
            
            if ($missingOptional.Count -gt 0) {
                $combinedBits = 0
                $missingOptional | ForEach-Object { $combinedBits = $combinedBits -bor $_.Bit }
                $missingNames = ($missingOptional | ForEach-Object { $_.Name }) -join ', '
                Write-Log "INFO" "Supplementary certs: Attempting best-effort install of $missingNames (0x$($combinedBits.ToString('X4')))"
                try {
                    $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $combinedBits
                    $null = Trigger-SecureBootTask
                    Write-Log "SUCCESS" "Supplementary certs: Triggered update (0x$($combinedBits.ToString('X4')))"
                    $results.SupplementaryCertsAttempted = $true
                    
                    # Short wait and verify, don't block enforcement for long
                    Write-Log "INFO" "Supplementary certs: Waiting 30 seconds for processing"
                    Start-Sleep -Seconds 30
                    
                    # Re-read db to see if any appeared
                    $suppRecheck = Get-UefiDatabaseCerts -Name db
                    $suppRecheckNames = @($suppRecheck.Certs | Where-Object {
                        $_.Subject -match '2023'
                    } | ForEach-Object {
                        if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                    })
                    $suppApplied = @($missingOptional | Where-Object { $suppRecheckNames -contains $_.Name })
                    $suppStillMissing = @($missingOptional | Where-Object { $suppRecheckNames -notcontains $_.Name })
                    
                    if ($suppApplied.Count -gt 0) {
                        Write-Log "SUCCESS" "Supplementary certs: Applied - $(($suppApplied | ForEach-Object { $_.Name }) -join ', ')"
                    }
                    if ($suppStillMissing.Count -gt 0) {
                        Write-Log "INFO" "Supplementary certs: Not yet visible - $(($suppStillMissing | ForEach-Object { $_.Name }) -join ', ') (may require reboot or firmware support)"
                    }
                }
                catch {
                    Write-Log "WARNING" "Supplementary certs: Best-effort install failed - $($_.Exception.Message) (non-blocking)"
                }
            }
            else {
                Write-Log "INFO" "Supplementary certs: All optional db certs already present"
            }
        }
        
        # -----------------------------------------------
        # Mitigation 2: Install 2023-signed boot manager (0x100)
        # -----------------------------------------------
        if ($has1799 -or $has1808) {
            Write-Log "INFO" "Mitigation 2: SKIP - 2023-signed boot manager already installed (Event $(if ($has1808) { '1808' } else { '1799' }))"
            $results.Mitigation2 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 2 (Boot manager)'
        }
        elseif (-not $Has2023InDb) {
            Write-Log "WARNING" "Mitigation 2: SKIP - Mitigation 1 must complete first (2023 cert not yet in db)"
            $results.Mitigation2 = 'Blocked'
            $results.Mitigation2BlockedReason = 'Awaiting DB cert (Mitigation 1)'
            $results.ActionsSkipped += 'Mitigation 2 (blocked by Mitigation 1)'
            return $results
        }
        else {
            Write-Log "INFO" "Mitigation 2: Applying - installing 2023-signed boot manager (0x100)"
            try {
                $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value 0x100
                $null = Trigger-SecureBootTask
                Write-Log "SUCCESS" "Mitigation 2: Triggered boot manager update (0x100)"
                $results.Mitigation2 = 'Applied'
                $results.ActionsApplied += 'Mitigation 2 (Boot manager)'
                $results.RebootRequired = $true
                
                Write-Log "INFO" "Mitigation 2: Waiting 30 seconds for update to process"
                Start-Sleep -Seconds 30
                
                # Check for 1799 event
                $postCheck = Check-PostTriggerEvents -Minutes 2
                if ($postCheck -eq 'Pending1808' -or $postCheck -eq 'Compliant') {
                    Write-Log "SUCCESS" "Mitigation 2: Boot manager installed (post-trigger: $postCheck)"
                    # Update event flags so the Mitigation 3+4 gate knows boot manager is confirmed
                    if ($postCheck -eq 'Compliant') { $has1808 = $true } else { $has1799 = $true }
                }
                else {
                    Write-Log "INFO" "Mitigation 2: Boot manager update processing - may need reboot"
                    # Boot manager was NOT confirmed installed (no 1799/1808).
                    # Re-query events: if 1800 fired during the wait, a reboot is required
                    # before Stage 3+4 can proceed. Mark Mitigation 2 as needing verification.
                    $mit2PostStatus = Get-CertUpdateEventStatus
                    if ($null -ne $mit2PostStatus -and $mit2PostStatus.EventId -eq 1800) {
                        Write-Log "WARNING" "Mitigation 2: Event 1800 detected - reboot required before boot manager can complete"
                        $mit2NeedsReboot = $true
                    }
                    else {
                        # No 1799/1808/1800 - boot manager update status unknown, don't assume success
                        Write-Log "WARNING" "Mitigation 2: No confirmation event (1799/1800/1808) - cannot verify boot manager install"
                        $mit2NeedsReboot = $true
                    }
                }
            }
            catch {
                Write-Log "ERROR" "Mitigation 2 failed: $($_.Exception.Message)"
                $results.Mitigation2 = 'Failed'
                return $results
            }
        }
        
        # -----------------------------------------------
        # Mitigation 3 + 4: Revoke PCA 2011 + Apply SVN (0x280)
        # Per CVE-2023-24932 enterprise guidance, these can be applied together in one step.
        # Uses Test-SvnStagePrerequisites for the Stage 1+2 gate check.
        # -----------------------------------------------
        $mit3Done = $pca2011Revoked -or $has1037
        $mit4Done = $svnInDbx -or $has1042
        $bothDone = $mit3Done -and $mit4Done
        
        # Run the shared prerequisite check (ground truth + manifest + events)
        $prereqs = Test-SvnStagePrerequisites -Has2023InDb $Has2023InDb -CertStatus $CertStatus -SvnEnforcementResult $results
        Write-Log "INFO" "Mitigation 3+4 gate: Stage1=$($prereqs.Stage1Done) ($($prereqs.Stage1Detail)), Stage2=$($prereqs.Stage2Done) ($($prereqs.Stage2Detail)), Reboot=$($prereqs.RebootPending), AllMet=$($prereqs.AllPrereqsMet)"
        
        if ($bothDone) {
            Write-Log "INFO" "Mitigation 3+4: SKIP - 2011 CA already revoked in DBX and SVN already applied"
            $results.Mitigation3 = 'AlreadyApplied'
            $results.Mitigation4 = 'AlreadyApplied'
            $results.ActionsSkipped += 'Mitigation 3 (2011 revocation)'
            $results.ActionsSkipped += 'Mitigation 4 (SVN update)'
        }
        elseif (-not $prereqs.AllPrereqsMet) {
            Write-Log "WARNING" "Mitigation 3+4: BLOCKED - $($prereqs.BlockReason)"
            if (-not $mit3Done) {
                $results.Mitigation3 = 'Blocked'
                $results.Mitigation3BlockedReason = $prereqs.BlockReason
                $results.ActionsSkipped += 'Mitigation 3 (blocked - prerequisites incomplete)'
            }
            else {
                $results.Mitigation3 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 3 (2011 revocation)'
            }
            if (-not $mit4Done) {
                $results.Mitigation4 = 'Blocked'
                $results.Mitigation4BlockedReason = $prereqs.BlockReason
                $results.ActionsSkipped += 'Mitigation 4 (blocked - prerequisites incomplete)'
            }
            else {
                $results.Mitigation4 = 'AlreadyApplied'
                $results.ActionsSkipped += 'Mitigation 4 (SVN update)'
            }
        }
        else {
            # Determine what to apply
            if (-not $mit3Done -and -not $mit4Done) {
                # Apply both together (0x280) per CVE-2023-24932 enterprise guidance
                $triggerValue = 0x280
                $desc = "Mitigation 3+4 combined (revoke 2011 CA + apply SVN) (0x280)"
            }
            elseif (-not $mit3Done) {
                $triggerValue = 0x80
                $desc = "Mitigation 3 only (revoke 2011 CA in DBX) (0x80)"
            }
            else {
                $triggerValue = 0x200
                $desc = "Mitigation 4 only (apply SVN to DBX) (0x200)"
            }
            
            Write-Log "INFO" "$desc"
            try {
                $null = RegistryShouldBe -KeyPath $regPath -Name "AvailableUpdates" -Value $triggerValue
                $null = Trigger-SecureBootTask
                Write-Log "SUCCESS" "Triggered $desc"
                if (-not $mit3Done) {
                    $results.Mitigation3 = 'Applied'
                    $results.ActionsApplied += 'Mitigation 3 (2011 revocation)'
                }
                else {
                    $results.Mitigation3 = 'AlreadyApplied'
                }
                if (-not $mit4Done) {
                    $results.Mitigation4 = 'Applied'
                    $results.ActionsApplied += 'Mitigation 4 (SVN update)'
                }
                else {
                    $results.Mitigation4 = 'AlreadyApplied'
                }
                $results.RebootRequired = $true
                
                Write-Log "INFO" "Waiting 30 seconds for update to process"
                Start-Sleep -Seconds 30
                
                # Verify via event log
                $postCheck1037 = @(Get-WinEvent -FilterHashtable @{
                    LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1037
                    StartTime = (Get-Date).AddMinutes(-2)
                } -ErrorAction SilentlyContinue)
                $postCheck1042 = @(Get-WinEvent -FilterHashtable @{
                    LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1042
                    StartTime = (Get-Date).AddMinutes(-2)
                } -ErrorAction SilentlyContinue)
                if ($postCheck1037.Count -gt 0) {
                    Write-Log "SUCCESS" "Event 1037 confirmed - 2011 CA revoked in DBX"
                }
                if ($postCheck1042.Count -gt 0) {
                    Write-Log "SUCCESS" "Event 1042 confirmed - SVN applied to DBX"
                }
                if ($postCheck1037.Count -eq 0 -and $postCheck1042.Count -eq 0) {
                    Write-Log "INFO" "Events 1037/1042 not yet observed - reboot required to complete"
                }
            }
            catch {
                Write-Log "ERROR" "Mitigation 3+4 failed: $($_.Exception.Message)"
                if (-not $mit3Done) { $results.Mitigation3 = 'Failed' }
                if (-not $mit4Done) { $results.Mitigation4 = 'Failed' }
            }
        }
        
        # Summary
        if ($results.ActionsApplied.Count -gt 0) {
            Write-Log "INFO" "SVN Enforcement applied: $($results.ActionsApplied -join ', ')"
        }
        if ($results.ActionsSkipped.Count -gt 0) {
            Write-Log "INFO" "SVN Enforcement skipped: $($results.ActionsSkipped -join ', ')"
        }
        if ($results.RebootRequired) {
            Write-Log "WARNING" "A reboot is required to complete the applied mitigations"
        }
        
        return $results
    }
}

# =========================================
# PROCESS Block: Data Gathering & Logic
#   Steps 1-2.6: Secure Boot status, cert parsing, dbx cross-check,
#   event log, servicing registry, SVN compliance, SVN enforcement,
#   opt-in check, trigger logic
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
    $allDbCertsPresent  = $false
    $has2023InDbDefault = $false
    $has2023InKek       = $false
    $dbCertsFound       = @()   # Which 2023 db certs are present
    $scheduledTaskPresent = $false
    $dbIsOsWritable     = $false
    
    if ($secureBoot -eq 'Enabled') {
        # --- Parse db (allowed signatures) ---
        Write-Log "INFO" "Parsing db certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $dbResult = Get-UefiDatabaseCerts -Name db
        $dbCerts  = $dbResult.Certs
        $dbBytes  = $dbResult.Bytes
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
        
        # --- Parse KEK (key exchange keys - authorizes writes to db) ---
        Write-Log "INFO" "Parsing KEK certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $kekResult = Get-UefiDatabaseCerts -Name KEK
        $kekCerts  = $kekResult.Certs
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
        
        # --- Parse dbx (revocation list) ---
        Write-Log "INFO" "Parsing dbx certificates$(if ($script:HasDecodedParam) { ' (using -Decoded)' })"
        $dbxResult = Get-UefiDatabaseCerts -Name dbx
        $dbxCerts  = $dbxResult.Certs
        $dbxBytes  = $dbxResult.Bytes
        if ($dbxCerts.Count -eq 0) {
            Write-Log "INFO" "No X509 certificates found in dbx"
        }
        else {
            foreach ($cert in $dbxCerts) {
                if ([string]::IsNullOrWhiteSpace($cert.Subject)) { continue }
                $shortSubject = (($cert.Subject -split ',') | Select-Object -First 2 | ForEach-Object { $_.Trim() }) -join ', '
                $validFrom = $cert.NotBefore.ToString('MM/dd/yyyy')
                $validTo = $cert.NotAfter.ToString('MM/dd/yyyy')
                Write-Log "INFO" "dbx Cert: $shortSubject, ValidFrom=$validFrom, ValidTo=$validTo"
            }
        }
        
        # --- Cross-check: are any 2011 CAs revoked in DBX? (Stage 3 indicator) ---
        $ca2011RevokedInDbx = @()   # Which 2011 CAs appear in the revocation list
        $oldCAs = @(
            'Microsoft Corporation UEFI CA 2011'
            'Microsoft Windows Production PCA 2011'
        )
        try {
            if ($dbxCerts.Count -gt 0) {
                # Check parsed cert objects by subject CN
                foreach ($oldCA in $oldCAs) {
                    foreach ($cert in $dbxCerts) {
                        if ($cert.Subject -match [regex]::Escape($oldCA)) {
                            $ca2011RevokedInDbx += $oldCA
                            break
                        }
                    }
                }
            }
            elseif ($null -ne $dbxBytes) {
                # Fallback: raw byte string match
                $dbxRawText = [System.Text.Encoding]::ASCII.GetString($dbxBytes)
                foreach ($oldCA in $oldCAs) {
                    if ($dbxRawText -match [regex]::Escape($oldCA)) {
                        $ca2011RevokedInDbx += $oldCA
                    }
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
            if ($dbCerts.Count -gt 0) {
                # Prefer cert object matching
                foreach ($certName in $updatedDbCertNames) {
                    foreach ($cert in $dbCerts) {
                        if ($cert.Subject -match [regex]::Escape($certName)) {
                            $dbCertsFound += $certName
                            break
                        }
                    }
                }
            }
            elseif ($null -ne $dbBytes) {
                # Fallback: raw byte string match
                $dbRawText = [System.Text.Encoding]::ASCII.GetString($dbBytes)
                foreach ($certName in $updatedDbCertNames) {
                    if ($dbRawText -match [regex]::Escape($certName)) {
                        $dbCertsFound += $certName
                    }
                }
            }
            $has2023InDb = $dbCertsFound -contains 'Windows UEFI CA 2023'
            $allDbCertsPresent = ($dbCertsFound.Count -eq $updatedDbCertNames.Count)
            if ($has2023InDb) {
                if ($allDbCertsPresent) {
                    Write-Log "INFO" "All 2023 certs found in db: $($dbCertsFound -join ', ')"
                }
                else {
                    $missingDb = $updatedDbCertNames | Where-Object { $dbCertsFound -notcontains $_ }
                    Write-Log "WARNING" "2023 certs found in db: $($dbCertsFound -join ', ') | Missing: $($missingDb -join ', ')"
                }
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
            $has2023InKek = $false
            if ($kekCerts.Count -gt 0) {
                foreach ($cert in $kekCerts) {
                    if ($cert.Subject -match [regex]::Escape($updatedKekCertName)) {
                        $has2023InKek = $true
                        break
                    }
                }
            }
            Write-Log "INFO" "2023 KEK authority cert ($updatedKekCertName): $(if ($has2023InKek) { 'Present' } else { 'Missing' })"
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 cert in KEK: $($_.Exception.Message)"
        }
        
        # --- If not in db, check dbDefault ---
        $dbDefaultCertsFound = @()   # Which 2023 certs are present in dbDefault
        if (-not $has2023InDb) {
            try {
                $dbDefaultResult = Get-UefiDatabaseCerts -Name dbDefault
                $dbDefaultCerts = $dbDefaultResult.Certs
                $dbDefaultBytes = $dbDefaultResult.Bytes
                if ($dbDefaultCerts.Count -gt 0) {
                    foreach ($certName in $updatedDbCertNames) {
                        foreach ($cert in $dbDefaultCerts) {
                            if ($cert.Subject -match [regex]::Escape($certName)) {
                                $dbDefaultCertsFound += $certName
                                break
                            }
                        }
                    }
                }
                elseif ($null -ne $dbDefaultBytes) {
                    $dbDefaultRawText = [System.Text.Encoding]::ASCII.GetString($dbDefaultBytes)
                    foreach ($certName in $updatedDbCertNames) {
                        if ($dbDefaultRawText -match [regex]::Escape($certName)) {
                            $dbDefaultCertsFound += $certName
                        }
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
    # Step 2.15: SVN Compliance check
    # SVN (Security Version Number) tracks boot component revocation levels in UEFI DBX.
    # Part of the Secure Boot hardening rollout (KB5046714 -> KB5077241):
    #   Stage 1 (May 2024)   : 2023 certs added to db via Windows Update
    #   Stage 2 (Feb 2025)   : 2023 boot manager deployed, Get-SecureBootSVN cmdlet added (KB5077241)
    #   Stage 3 (June 2026)  : PCA 2011 revoked in dbx, SVN enforcement begins
    #   Stage 4 (est. 2027)  : Full enforcement - 2011 certs removed from db
    # SVN progression: 0.0 (none) -> 2.0 (PCA 2011 revoked via DBXUpdate2024.bin) -> 7.0 (via DBXUpdateSVN.bin)
    # Uses Get-SecureBootSVN cmdlet (KB5077241+) when available; always parses raw DBX bytes
    # for pending update detection (compares live DBX against DBXUpdateSVN.bin staging file).
    # Source: https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates
    # Source: https://github.com/microsoft/secureboot_objects
    # -----------------------------------------------
    $svnStatus = $null
    if ($secureBoot -eq 'Enabled') {
        Write-Host " === Secure Boot SVN Compliance ==="
        # Always attempt SVN, raw DBX provides pending update detection, cmdlet adds richer info
        $svnStatus = Get-SecureBootSVNStatus -DbxBytes $dbxBytes
        if ($null -ne $svnStatus) {
            # Cross-reference: if not compliant but 2011 CA not yet revoked, it's expected (pre-Stage 3)
            $svnStatus.RevocationPending = (-not $svnStatus.IsCompliant -and $ca2011RevokedInDbx.Count -eq 0)
            # Cross-reference events 1037 (2011 CA revoked in DBX) and 1042 (SVN applied to DBX) for stage confirmation
            # Event 1037 = Stage 3 / Mitigation 3 complete
            # Event 1042 = Stage 4 / Mitigation 4 complete (SVN data written to DBX - bootmgfw.efi 7.0, cdboot.efi 3.0, wdsmgfw.efi 3.0)
            # AvailableUpdates 0x80 = Mitigation 3 triggered, 0x200 = Mitigation 4 triggered (persists across runs)
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            # Read AvailableUpdates directly - $optInStatus isn't populated yet (Step 2.3 runs later)
            $avBits  = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
            if ($null -eq $avBits) { $avBits = 0 }
            $mit3Triggered = ($avBits -band 0x0080) -ne 0
            $mit4Triggered = ($avBits -band 0x0200) -ne 0
            if ($has1042) {
                $svnStatus.Stage = 'Stage 4'
                $svnStatus.StageDetail = 'SVN applied to DBX (Event 1042)'
            }
            elseif ($has1037) {
                $svnStatus.Stage = 'Stage 3'
                $svnStatus.StageDetail = '2011 CA revoked in DBX (Event 1037)'
            }
            elseif ($mit4Triggered -and $mit3Triggered) {
                # 0x280 in AvailableUpdates, mitigations 3+4 were triggered, pending SVN reboot
                $svnStatus.Stage = 'Stage 3+4'
                $svnStatus.StageDetail = 'Mitigations applied, pending SVN reboot'
            }
            elseif ($mit3Triggered) {
                # 0x80 in AvailableUpdates, mitigation 3 was triggered, pending SVN reboot
                $svnStatus.Stage = 'Stage 3'
                $svnStatus.StageDetail = '2011 CA revocation triggered, pending SVN reboot'
            }
            elseif ($has2023InDb) {
                $svnStatus.Stage = 'Stage 2'
                $svnStatus.StageDetail = '2023 certs in db, boot manager deployed'
            }
            else {
                $svnStatus.Stage = 'Stage 1'
                $svnStatus.StageDetail = 'Pre-deployment'
            }
            # Reboot-pending detection: compare mitigation event timestamps against last boot time
            # UEFI writes (DBX updates, SVN data) happen at OS runtime and are visible immediately,
            # but firmware doesn't enforce them until the next boot. Boot time comparison is the
            # reliable cross-reference. If events 1037/1042 fired this boot session, reboot is needed.
            # Cmdlet path (FirmwareSVN < StagedSVN) is also reliable when available.
            $svnRebootPending = $false
            $lastBootTime = $null
            try { $lastBootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { }
            
            # Cmdlet path: FirmwareSVN < StagedSVN is a direct firmware-level indicator
            # Only meaningful at Stage 3+ (after mitigations triggered). At Stage 2 the mismatch
            # is expected: boot manager writes StagedSVN but firmware won't absorb until revocations happen.
            if ($svnStatus.Source -eq 'Get-SecureBootSVN' -and ($mit3Triggered -or $mit4Triggered -or $has1037 -or $has1042)) {
                try {
                    $fwVer = [version]$svnStatus.FirmwareSVN
                    $stagedVer = [version]$svnStatus.StagedSVN
                    if ($fwVer -lt $stagedVer) {
                        $svnRebootPending = $true
                    }
                }
                catch {
                  
                }
            }
            
            # Boot time cross-reference: if mitigation events fired since last boot, reboot is needed
            # This catches the raw DBX path where NVRAM data appears immediately but isn't enforced yet
            if (-not $svnRebootPending -and $null -ne $lastBootTime) {
                if ($has1042) {
                    $ev1042 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1042
                    if ($null -ne $ev1042 -and $ev1042.Time -gt $lastBootTime) {
                        $svnRebootPending = $true
                    }
                }
            }
            
            # Fallback: mitigation 4 triggered (0x200) but no event 1042 yet and no DBX SVN
            if (-not $svnRebootPending -and $mit4Triggered -and $null -eq $svnStatus.DbxSVN -and -not $has1042) {
                $svnRebootPending = $true
            }
            $svnStatus.RebootPending = $svnRebootPending
            
            # Revocation reboot detection: event 1037 fired this boot session, or mitigation 3
            # triggered but not yet processed, revocation is applied but needs reboot to enforce
            $svnStatus.RevocationAppliedPendingReboot = $false
            if ($has1037 -and $null -ne $lastBootTime) {
                $ev1037 = Get-LatestSecureBootEvent -CertStatus $certStatus -EventId 1037
                if ($null -ne $ev1037 -and $ev1037.Time -gt $lastBootTime) {
                    $svnStatus.RevocationAppliedPendingReboot = $true
                    $svnStatus.RevocationPending = $false
                }
            }
            elseif ($mit3Triggered -and -not $has1037) {
                $svnStatus.RevocationAppliedPendingReboot = $true
                $svnStatus.RevocationPending = $false
            }
            
            Write-Log "INFO" "SVN Compliance: $($svnStatus.ComplianceStatus) (source: $($svnStatus.Source)) | $($svnStatus.Stage): $($svnStatus.StageDetail)"
            if ($svnStatus.Source -eq 'Raw DBX') {
                Write-Log "INFO" "DBX SVN: $(if ($svnStatus.DbxSVN) { $svnStatus.DbxSVN } else { 'not present' }) | Windows Update SVN: $(if ($svnStatus.WindowsUpdateSVN) { $svnStatus.WindowsUpdateSVN } else { 'not staged' })"
            }
            else {
                Write-Log "INFO" "Firmware SVN: $($svnStatus.FirmwareSVN) | Boot Manager SVN: $($svnStatus.BootManagerSVN) | Staged SVN: $($svnStatus.StagedSVN)"
                if ($null -ne $svnStatus.WindowsUpdateSVN) {
                    Write-Log "INFO" "Windows Update staged SVN: $($svnStatus.WindowsUpdateSVN) | DBX SVN: $(if ($svnStatus.DbxSVN) { $svnStatus.DbxSVN } else { 'not present' })"
                }
            }
            if ($svnStatus.RevocationPending) {
                Write-Log "INFO" "SVN non-compliance expected - PCA 2011 not yet revoked in DBX (pre-Stage 3)"
            }
            if ($svnStatus.SvnUpdatePending) {
                Write-Log "INFO" "SVN update pending - DBXUpdateSVN.bin ($($svnStatus.WindowsUpdateSVN)) not yet applied to DBX"
            }
            if ($svnStatus.RebootPending) {
                Write-Log "WARNING" "SVN reboot pending - firmware SVN has not yet absorbed the staged update (reboot required)"
            }
            if ($svnStatus.RevocationAppliedPendingReboot) {
                Write-Log "WARNING" "2011 CA revocation applied (Event 1037) but not yet visible in DBX bytes (reboot required)"
            }
        }
    }
    
    # =======================================================================
    # Step 2.2: SVN Enforcement (when $EnforceSvnCompliance -eq 'Enforce SVN')
    # =======================================================================
    # Applies KB5025885 mitigations sequentially (CVE-2023-24932 enterprise guidance):
    #   Mitigation 1 (0x40)  : Add Windows UEFI CA 2023 to DB
    #   Mitigation 2 (0x100) : Install 2023-signed boot manager
    #   Mitigation 3 (0x80)  : Revoke PCA 2011 in DBX
    #   Mitigation 4 (0x200) : Apply SVN to DBX firmware
    # Combined 3+4 (0x280) per CVE-2023-24932 enterprise guidance when both needed - single reboot.
    # Each step checks current state first (idempotent).
    # Source: https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
    # Source: https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
    # =======================================================================
    $svnEnforcementResult = $null
    $enforceMissingOptIn  = $false
    if ($EnforceSvnCompliance -eq 'Enforce SVN' -and $secureBoot -eq 'Enabled') {
        # Check if opt-in is set (Step 2.3 hasn't run yet, read directly)
        # Only warn when certs are missing AND not pending install, if certs are in db or a reboot
        # will deliver them, enforcement handles stage pushing directly via AvailableUpdates.
        $earlyOptIn = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue)
        $certsPendingOrPresent = ($has2023InDb -or ($null -ne $certStatus -and $certStatus.EventId -in @(1800, 1799, 1808)))
        if (($null -eq $earlyOptIn -or $earlyOptIn -eq 0) -and -not $certsPendingOrPresent) {
            $enforceMissingOptIn = $true
            Write-Log "WARNING" "SVN Enforcement is enabled but WU Secure Boot management is NOT opted in and 2023 certs are not in db. Set securebootAction to 'Enable opt-in' for full deployment."
        }
        Write-Host "`n==================================================================="
        Write-Host " ===    SVN Enforcement Mode - Applying KB5025885 Mitigations    ==="
        Write-Host " ==================================================================="
        $svnEnforcementResult = Invoke-SvnEnforcement `
            -Has2023InDb      $has2023InDb `
            -Has2023InKek     $has2023InKek `
            -SvnStatus        $svnStatus `
            -CertStatus       $certStatus `
            -DbxBytes         $dbxBytes `
            -Ca2011RevokedInDbx $ca2011RevokedInDbx `
            -DbCertsFound     $dbCertsFound
        
        # Re-query event log after enforcement to capture new events (1037, 1042, etc.)
        # This ensures the event log summary and card show the full up-to-date picture
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.ActionsApplied.Count -gt 0) {
            $postEnforcementStatus = Get-CertUpdateEventStatus
            if ($null -ne $postEnforcementStatus -and $null -ne $postEnforcementStatus.AllEvents) {
                $certStatus = $postEnforcementStatus
                Write-Log "INFO" "Event log re-queried after enforcement: $($certStatus.AllEvents.Count) event(s)"
            }
        }

        # Re-read db certs after enforcement if supplementary certs were attempted
        # This ensures the cert inventory card reflects newly-applied optional certs
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.SupplementaryCertsAttempted) {
            Write-Log "INFO" "Re-reading db certs after supplementary cert application"
            try {
                $postEnfDb = Get-UefiDatabaseCerts -Name db
                $postEnfDbCerts = @($postEnfDb.Certs | Where-Object {
                    $_.Subject -match '2023'
                } | ForEach-Object {
                    if ($_.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() }
                })
                if ($postEnfDbCerts.Count -gt $dbCertsFound.Count) {
                    $newCerts = @($postEnfDbCerts | Where-Object { $dbCertsFound -notcontains $_ })
                    Write-Log "SUCCESS" "Post-enforcement db update: +$($newCerts -join ', ') (was: $($dbCertsFound -join ', '))"
                    $dbCertsFound = $postEnfDbCerts
                    $has2023InDb = $dbCertsFound -contains 'Windows UEFI CA 2023'
                    $allDbCertsPresent = ($dbCertsFound.Count -eq $updatedDbCertNames.Count)
                }
            }
            catch {
                Write-Log "WARNING" "Failed to re-read db certs after enforcement: $($_.Exception.Message)"
            }
        }
        
        # Update SVN stage and revocation status after enforcement
        if ($null -ne $svnEnforcementResult -and $svnEnforcementResult.ActionsApplied.Count -gt 0 -and $null -ne $svnStatus) {
            if ($svnEnforcementResult.Mitigation4 -in @('Applied','AlreadyApplied') -and
                $svnEnforcementResult.Mitigation3 -in @('Applied','AlreadyApplied')) {
                if ($svnEnforcementResult.RebootRequired) {
                    $svnStatus.Stage = 'Stage 3+4'
                    $svnStatus.StageDetail = 'Mitigations applied, pending SVN reboot'
                }
                else {
                    $svnStatus.Stage = 'Stage 4'
                    $svnStatus.StageDetail = 'SVN applied to DBX (enforcement complete)'
                }
            }
            elseif ($svnEnforcementResult.Mitigation3 -in @('Applied','AlreadyApplied')) {
                if ($svnEnforcementResult.RebootRequired) {
                    $svnStatus.Stage = 'Stage 3'
                    $svnStatus.StageDetail = '2011 CA revocation applied, pending SVN reboot'
                }
                else {
                    $svnStatus.Stage = 'Stage 3'
                    $svnStatus.StageDetail = '2011 CA revoked in DBX (enforcement complete)'
                }
            }
            # Update revocation flag - if mitigation 3 was just applied, the revocation
            # is no longer "pending" (waiting for MS to do it), it's been applied but may need reboot
            if ($svnEnforcementResult.Mitigation3 -eq 'Applied') {
                $svnStatus.RevocationPending = $false
                $svnStatus.RevocationAppliedPendingReboot = $true
            }
            elseif ($svnEnforcementResult.Mitigation3 -eq 'AlreadyApplied') {
                $svnStatus.RevocationPending = $false
            }
            # Re-read DBX SVN if mitigation 4 was just applied
            if ($svnEnforcementResult.Mitigation4 -eq 'Applied') {
                $newDbxBytes = (Get-UefiDatabaseCerts -Name dbx).Bytes
                $newDbxSvn = Get-DbxBootMgrSVN -DbxBytes $newDbxBytes
                if ($null -ne $newDbxSvn) {
                    $svnStatus.DbxSVN = $newDbxSvn
                    Write-Log "INFO" "Post-enforcement DBX SVN: $newDbxSvn"
                }
            }
        }
        # Post-enforcement safety check: if Mitigation 3+4 were blocked but their bits
        # exist in the manifest (from this run or a previous run), attempt to clear them
        # before the next reboot processes them prematurely.
        if ($null -ne $svnEnforcementResult -and
            ($svnEnforcementResult.Mitigation3 -eq 'Blocked' -or $svnEnforcementResult.Mitigation4 -eq 'Blocked')) {
            $repairCheck = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
            if (-not $repairCheck.AllPrereqsMet -and ($repairCheck.Stage3BitPending -or $repairCheck.Stage4BitPending)) {
                Write-Log "WARNING" "SVN Repair: Stage 3+4 bits in manifest but prerequisites not met - clearing to prevent premature application"
                $svnRepairResult = Repair-SvnEnforcement -Has2023InDb $has2023InDb -CertStatus $certStatus
            }
        }
        Write-Host ""
    }
    elseif ($EnforceSvnCompliance -eq 'Passive' -and $secureBoot -eq 'Enabled') {
        Write-Log "INFO" "SVN Enforcement: Passive mode - audit only (Microsoft enforcement: June 2026 - 2027)"
        # Safety check: even in passive mode, if Stage 3+4 bits are in the manifest
        # but Stage 1+2 aren't complete, clear them to prevent premature application on reboot
        $passivePrereqs = Test-SvnStagePrerequisites -Has2023InDb $has2023InDb -CertStatus $certStatus
        if (-not $passivePrereqs.AllPrereqsMet -and ($passivePrereqs.Stage3BitPending -or $passivePrereqs.Stage4BitPending)) {
            Write-Log "WARNING" "SVN Repair (Passive): Stage 3+4 bits in manifest but prerequisites not met - clearing"
            $svnRepairResult = Repair-SvnEnforcement -Has2023InDb $has2023InDb -CertStatus $certStatus
        }
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
                    
                    # 2. Set opt-in gate key (MicrosoftUpdateManagedOptIn only - no stage pushing)
                    Set-SecureBootOptInKeys
                    
                    # 3. Trigger Secure-Boot-Update scheduled task to nudge Windows Update
                    Trigger-SecureBootTask
                    
                    Write-Log "SUCCESS" "Secure Boot opt-in and telemetry enablement complete"
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
    # IMPORTANT: This step only runs when SecureBootAction is 'Enable opt-in for SecureBoot management'.
    # In Audit mode, this step is skipped entirely. No registry writes, no task triggers.
    # Windows will NOT update the CA2023 certificates without opt-in (MicrosoftUpdateManagedOptIn = 0x5944).
    # Microsoft's automatic enforcement begins June 2026 and ramps through 2027.
    $triggeredOsUpdate = $false
    $postTriggerState  = $null
    if ($SecureBootAction -eq 'Enable opt-in for SecureBoot management') {
        # Trigger conditions (when servicing hasn't already confirmed Updated):
        #   A) 2023 cert is in db but OS hasn't confirmed via 1808 (stale 1801 or no events)
        #   B) Cert in dbDefault, KEK missing, no Event 1803 blocker - opt-in can push KEK + certs
        # Skip trigger if 1800 (reboot required) or 1799 (boot manager installed) - these are in-progress states
        # that re-triggering cannot advance; they need time, sometimes up to 9+ days
        $servicingAlreadyUpdated = ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated')
        $has1803InLog = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
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
            $setReg     = Set-SecureBootOptInKeys
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
    }
    elseif ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
        # Audit mode: warn that Windows will not update CA2023 without opt-in
        $servicingAlreadyUpdated = ($null -ne $servicingStatus -and $servicingStatus.UEFICA2023Status -eq 'Updated')
        if (-not $servicingAlreadyUpdated -and $certStatus.EventId -notin @(1808, 1799)) {
            Write-Log "WARNING" "SecureBootAction is 'Audit' (read-only). Windows may not update CA2023 certificates without opt-in. Set action to 'Enable opt-in for SecureBoot management' to allow automatic deployment."
        }
    }
    
    # -----------------------------------------------
    # Step 2.6: 1799 without 1808 - informational note
    #           Servicing confirms Updated but 1808 hasn't appeared in the event log.
    #           The Secure-Boot-Update task runs at startup + every 12 hours and is
    #           expected to produce 1808 on its next cycle(s). No action needed, only annotate.
    # -----------------------------------------------
    $pending1808Note = $false
    if ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1799 -and $servicingAlreadyUpdated) {
        $pending1808Note = $true
        Write-Log "INFO" "Event 1799 is latest, servicing confirms Updated - 1808 expected on next scheduled task cycle(s)"
    }
    
}

# =========================================
# END Block: State Mapping, Card Building & Output
#   Steps 3-6: Final state resolution, HTML/local card,
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
                $detailRowHtml = "2023 Secure Boot update confirmed by servicing registry.<br />Reboot to apply remaining certs:<br />    $missingShort"
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Servicing: Updated <span style="color:#F0AD4E;">| Latest event: 1800 (reboot required)</span>'
                $plainText     = "✅ Secure Boot Enabled. Compliant (UEFICA2023Status=Updated). Reboot pending for $($missingDbCerts.Count) cert(s)."
            }
            elseif ($certStatus.Status -eq 'Compliant') {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.'
                $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event 1808 detected at ' + $eventTime
                $plainText     = '✅ Secure Boot Enabled. Certificates up to date in BIOS (Event 1808). Compliant.'
            }
            else {
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.'
                # Compliant via servicing registry (UEFICA2023Status=Updated) without Event 1808 in log
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Servicing status: Updated'
                $plainText     = '✅ Secure Boot Enabled. Certificates up to date (UEFICA2023Status=Updated). Compliant.'
            }
            $statusEmoji = '✅'
            break
        }
        
        # State 4: Pending (Secure Boot enabled + Event 1801 found)
        # 1801 indicates certs available but not yet applied - usually resolves on its own via WU
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'ActionRequired') {
            $statusKey     = 'Pending'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
            
            $oemKeyGuide = Get-OemKeyResetGuide
            $bitlockerNote = '<br /><br />Suspend BitLocker or have recovery keys handy for <br />each enabled volume before resetting keys.'
            
            if ($oemKeyGuide) {
                $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
            }
            else {
                $guideHtml = ''
            }
            
            if ($has2023InDb) {
                $detailRowHtml = '2023 Secure Boot certificates are present in the active<br />database (db), but the OS-side validation is stuck on 1801.<br />Windows Update should* resolve this automatically<br />before the June 2026 enforcement deadline.'
                $plainText     = '⚠️ Secure Boot Enabled. 2023 certs in db but OS stuck on 1801. Pending Windows Update validation.'
                $statusEmoji = '⚠️'
            }
            elseif ($has2023InDbDefault) {
                # Check for Event 1803 (PK-signed KEK not available) - the definitive OEM blocker
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable - Windows Update will handle it
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />but not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. Pending. Windows Update will apply certs automatically.'
                    $statusEmoji = '⚠️'
                }
                elseif ($has1803) {
                    # Event 1803 confirms OEM has NOT provided a PK-signed KEK
                    # This is a genuine blocker - key reset or OEM firmware update required
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#D9534F;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "KEK 2K CA 2023 not available - OEM has not provided a<br />PK-signed KEK update (Event 1803).<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Wait for OEM firmware update that includes KEK 2023<br />• Reset Secure Boot keys in BIOS to apply from defaults" + $bitlockerNote + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required.'
                    $statusEmoji = '❌'
                }
                else {
                    # KEK missing but no 1803 - Windows Update may be able to push the KEK
                    # via the 0x4004 bit in AvailableUpdates. Opt-in is the first step.
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in (0x4004 bit)."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to trigger KEK + cert deployment.'
                        $plainText     = '⚠️ Secure Boot Enabled. Not opted in. Pending Opt-In.'
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = '⚠️ Secure Boot Enabled. Opted in. Pending Windows Update.'
                    }
                    $statusEmoji = '⚠️'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault - firmware update or OS-driven update needed
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                $oemBiosGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosGuide) {
                    $biosGuideHtml = '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $biosGuideHtml = ''
                }
                if ($dbIsOsWritable) {
                    # KEK present + UEFI writable - Windows Update will handle everything
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update will eventually push the cert automatically,<br />or a manual BIOS update can be applied.' + $biosGuideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing; Windows will eventually update the BIOS db directly, or push a BIOS update if available.'
                    $statusEmoji = '⚠️'
                }
                elseif ($has1803) {
                    # Event 1803 confirms OEM blocker - KEK not available, cert not in defaults
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#D9534F;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />OEM has not provided a PK-signed KEK update (Event 1803).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support. Update before June 2026.' + $biosGuideHtml
                    $plainText     = '❌ Secure Boot Enabled. 2023 cert missing, OEM KEK not available (1803). BIOS update required.'
                    $statusEmoji = '❌'
                }
                else {
                    # No cert in db/dbDefault but no 1803 either - opt-in may resolve via Windows Update
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to allow WU deployment.' + $biosGuideHtml
                        $plainText     = '⚠️ Secure Boot Enabled. Not opted in. Pending Opt-In.'
                    }
                    else {
                        $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />KEK 2023 is also missing, but no Event 1803 (OEM blocker).<br />Opt-in is enabled - Windows Update may deliver KEK + certs.<br />If no progress, a BIOS update may be needed.' + $biosGuideHtml
                        $plainText     = '⚠️ Secure Boot Enabled. Opted in. Pending Windows Update.'
                    }
                    $statusEmoji = '⚠️'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            break
        }
        
        # State 5a: Pending Cert Reboot (Event 1800 - reboot required to continue)
        ($secureBoot -eq 'Enabled' -and $certStatus.EventId -eq 1800 -and -not $postTriggerState) {
            $statusKey     = 'Pending'
            $cardIconColor = '#F0AD4E'
            $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Cert Reboot'
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
            if ($enforceMissingOptIn) {
                $detailRowHtml += '<br /><br /><span style="color:#F59E0B;"><i class="fas fa-exclamation-triangle" style="color:#F59E0B;"></i> SVN Enforcement is active but WU opt-in is not enabled.<br />Set securebootAction to &quot;Enable opt-in&quot; for full deployment.</span>'
                $plainText     += ' ⚠️ SVN Enforcement active but WU opt-in not enabled.'
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
                if ($oemKeyGuide) {
                    $guideHtml = '<br /><a href="' + $oemKeyGuide + '" target="_blank">OEM Key Reset Guide</a>'
                }
                else {
                    $guideHtml = ''
                }
                $cardIconColor = '#F0AD4E'
                # Check for Event 1803 (PK-signed KEK not available)
                $has1803 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1803)
                
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately." + $bitlockerNote + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. Pending. Windows Update will apply certs automatically.'
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events - Windows capable of updating BIOS db'
                }
                elseif ($has1803) {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = "KEK 2K CA 2023 not available - OEM has not provided a<br />PK-signed KEK update (Event 1803).<br />In firmware defaults (dbDefault): $dbDefaultCertLabel<br />Options:<br />• Wait for OEM firmware update that includes KEK 2023<br />• Reset Secure Boot keys in BIOS to apply from defaults" + $bitlockerNote + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. OEM KEK 2023 not available (Event 1803). BIOS update or key reset required.'
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> Event 1803 - OEM KEK blocker'
                    $statusEmoji = '❌'
                }
                else {
                    # KEK missing but no 1803 - opt-in can push KEK
                    $statusKey     = 'Pending'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                    $detailRowHtml = "In firmware defaults (dbDefault): $dbDefaultCertLabel<br />KEK 2K CA 2023 is not yet installed.<br />Windows Update can deliver the PK-signed KEK via opt-in."
                    if ($null -ne $optInStatus -and -not $optInStatus.IsOptedIn) {
                        $detailRowHtml += '<br /><br /><b>Not opted in.</b> Windows will not update CA2023 without opt-in.<br />Set SecureBootAction to &quot;Enable opt-in&quot; to trigger KEK + cert deployment.'
                        $plainText     = '⚠️ Secure Boot Enabled. Not opted in. Pending Opt-In.'
                    }
                    else {
                        $detailRowHtml += '<br /><br />Opt-in is enabled. Windows Update will push the KEK<br />and then apply certs. This may take time.'
                        $plainText     = '⚠️ Secure Boot Enabled. Opted in. Pending Windows Update.'
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
                $detailRowHtml = 'Triggered OS-side update.<br />2023 certificates successfully applied to BIOS firmware.'
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
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Cert Reboot'
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
    
    # Append SVN context to detail text when SVN data is available
    # This gives a quick rundown of SVN status alongside the cert-focused detail
    if ($null -ne $svnStatus) {
        $svnRebootNeeded = ($svnStatus.RebootPending -or $svnStatus.RevocationAppliedPendingReboot)
        # Append "Pending SVN Reboot" to card title when reboot is needed
        if ($svnRebootNeeded) {
            $statusRowHtml += ' <span style="color:#F59E0B; font-size:0.85em;">(Pending SVN Reboot)</span>'
            if ($plainText -notmatch 'SVN') {
                $plainText += ' Pending SVN reboot.'
            }
        }
        # Append SVN summary, so the SVN line is the single source of action status for both certs and SVN
        $svnSummary = if ($svnRebootNeeded) {
            'Reboot required to complete SVN updates.'
        }
        elseif ($svnStatus.IsCompliant) {
            'No action required.'
        }
        elseif ($statusKey -eq 'Compliant' -and ($svnStatus.RevocationPending -or $svnStatus.SvnUpdatePending)) {
            # Cert rotation complete - SVN stages 3+4 are future enforcement and not a pending action
            $null
        }
        elseif ($svnStatus.RevocationPending -or $svnStatus.SvnUpdatePending) {
            'SVN updates pending. Awaiting Microsoft rollout (June 2026 - 2027).'
        }
        else {
            'SVN update in progress.'
        }
        if ($svnSummary) { $detailRowHtml += "<br />$svnSummary" }
        # Keep $statusEmoji unchanged. Cert compliance is still valid, SVN info is supplemental
    }
    
    # Update "Last Event" if a newer event exists beyond the cert-state event (e.g. 1037, 1042)
    # The state machine picks the latest STATE event (1799/1800/1801/1808) for cert compliance,
    # but 1037/1042 may be more recent and should be reflected as the actual last event.
    if ($null -ne $certStatus -and $null -ne $certStatus.AllEvents -and $certStatus.AllEvents.Count -gt 0) {
        $newestEvent = $certStatus.AllEvents | Sort-Object Time -Descending | Select-Object -First 1
        if ($null -ne $newestEvent -and $null -ne $certStatus.EventTime -and $newestEvent.Time -gt $certStatus.EventTime) {
            $newestTimeStr = $newestEvent.Time.ToString('yyyy-MM-dd HH:mm')
            $newestDesc = $newestEvent.Description
            $newestColor = switch ($newestEvent.Id) {
                1037  { '#26A644' }
                1042  { '#26A644' }
                1808  { '#26A644' }
                1799  { '#26A644' }
                1800  { '#F0AD4E' }
                1801  { '#F0AD4E' }
                { $_ -in @(1032, 1033, 1795, 1796, 1797, 1798, 1802, 1803) } { '#D9534F' }
                default { '#5BC0DE' }
            }
            $newestIcon = if ($newestColor -eq '#D9534F') { 'fa-exclamation-triangle' }
                          elseif ($newestColor -eq '#F0AD4E') { 'fa-clock' }
                          else { 'fa-calendar-check' }
            $eventRowHtml = "<i class='fas $newestIcon' style='color:$newestColor;'></i> Event $($newestEvent.Id) at $newestTimeStr"
        }
    }
    
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
        $cardProperties['Event Log'] = Build-EventLogSection -Format 'Html'
    }
    # Pre-compute which certs are "unconfirmed", OS hasn't confirmed via 1799/1808.
    # A cert is unconfirmed when: its manifest bit is set AND neither 1799 nor 1808 is the current state event.
    # 1799 = boot manager installed (certs applied, progressing), 1808 = fully confirmed.
    $certsUnconfirmed = @()
    $osConfirmed = ($null -ne $certStatus -and $certStatus.EventId -in @(1799, 1808))
    if ($secureBoot -eq 'Enabled' -and -not $osConfirmed -and $null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0) {
        $preAvVal = $optInStatus.EffectiveAvailable
        if ($preAvVal -band 0x0040)  { $certsUnconfirmed += 'Windows UEFI CA 2023' }
        if ($preAvVal -band 0x0800)  { $certsUnconfirmed += 'Option ROM UEFI CA 2023' }
        if ($preAvVal -band 0x1000)  { $certsUnconfirmed += 'UEFI CA 2023' }
        # KEK: test bit 0x0004 specifically - 0x4000 is the conditional qualifier (not the KEK bit)
        if ($preAvVal -band 0x0004)  { $certsUnconfirmed += 'KEK 2K CA 2023' }
    }
    
    # Certificate inventory (all four 2023 certs - only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        $cardProperties['Certificates'] = Build-CertInventorySection -Format 'Html'
    }
    # Servicing status (only when Secure Boot is Enabled and servicing data exists)
    if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
        $servContent = Build-ServicingSection -Format 'Html'
        if ($null -ne $servContent) { $cardProperties['Servicing'] = $servContent }
    }
    # AvailableUpdates bitmask decoded. Shown when registry has a value OR event-confirmed mitigations exist
    # Cross-reference manifest bits against actual cert inventory to determine what's truly applied
    $has1037ForManifest = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
    $has1042ForManifest = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
    $hasEventMitigations = $has1037ForManifest -or $has1042ForManifest
    $hasRegistryManifest = ($null -ne $optInStatus -and $optInStatus.EffectiveAvailable -ne 0)
    if ($secureBoot -eq 'Enabled' -and ($hasRegistryManifest -or $hasEventMitigations)) {
        # Re-read AvailableUpdates fresh. Windows may have updated the registry with mitigation bits
        # (0x0080 = Mitigation 3, 0x0200 = Mitigation 4) since Check-OptInStatus ran in Step 2.3
        $freshAvailable = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty 'AvailableUpdates' -ErrorAction SilentlyContinue)
        if ($null -eq $freshAvailable) { $freshAvailable = 0 }
        $avVal = if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) { $optInStatus.AvailableUpdatesPolicy } else { $freshAvailable }
        
        # Enrich with event-confirmed mitigations whose bits may not be in the registry
        if ($has1037ForManifest -and -not ($avVal -band 0x0080)) { $avVal = $avVal -bor 0x0080 }
        if ($has1042ForManifest -and -not ($avVal -band 0x0200)) { $avVal = $avVal -bor 0x0200 }
        
        $avHex  = '0x{0:X}' -f $avVal
        $source = if ($null -ne $optInStatus -and $optInStatus.AvailableUpdatesPolicySet) { 'Policy' }
                  elseif ($freshAvailable -ne 0) { 'Registry' }
                  else { 'Events' }
        # Re-decode with enriched value so bullet points include mitigations
        $enrichedMeaning = Get-AvailableUpdatesMeaning -Value $avVal
        
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
            if ($dbCertsFound -notcontains 'Microsoft UEFI CA 2023') { $manifestPending += 'Microsoft UEFI CA 2023' }
        }
        # Boot manager bit (0x0100) - if 1799 has occurred, boot manager is installed
        if ($avVal -band 0x0100) {
            $has1799 = ($null -ne $certStatus -and $certStatus.EventId -eq 1799) -or
                       (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1799)
            if (-not $has1799) { $manifestPending += 'Boot manager (2023-signed)' }
        }
        # Mitigation 3 (0x80) - Revoke PCA 2011 in DBX; complete when 2011 CA appears in dbx or Event 1037 fires
        if ($avVal -band 0x0080) {
            $has1037 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1037)
            if ($ca2011RevokedInDbx.Count -eq 0 -and -not $has1037) { $manifestPending += 'PCA 2011 revocation (Mitigation 3)' }
        }
        # Mitigation 4 (0x200) - Apply SVN to DBX firmware; complete when SVN appears in DBX or Event 1042 fires
        if ($avVal -band 0x0200) {
            $has1042 = (Test-HasSecureBootEvent -CertStatus $certStatus -EventId 1042)
            $dbxSvnPresent = ($null -ne $svnStatus -and $null -ne $svnStatus.DbxSVN)
            if (-not $dbxSvnPresent -and -not $has1042) { $manifestPending += 'SVN update (Mitigation 4)' }
        }
        
        $allApplied = ($manifestPending.Count -eq 0)
        $pendingReboot = ($null -ne $certStatus -and $certStatus.EventId -eq 1800)
        
        $svnRebootForManifest = (Test-SvnRebootPending -SvnStatus $svnStatus)
        # Log the registry data to console (not shown on card)
        Write-Log "INFO" "Update Manifest: $avHex ($source) | Enriched meaning: $($enrichedMeaning -join '; ')"
        $cardProperties['Updates'] = Build-UpdatesSection -Format 'Html'
    }
    # SVN Compliance (Get-SecureBootSVN cmdlet or raw DBX byte fallback)
    $svnWhatIsThis = '<a href="https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d" target="_blank" rel="nofollow noopener noreferrer" style="font-size:0.75em;">What is this <i class="fas fa-question-circle" style="color:#6B7280;"></i></a>'
    $svnSectionTitle = "SVN Compliance $svnWhatIsThis"
    if ($secureBoot -eq 'Enabled' -and $null -ne $svnStatus) {
        $cardProperties[$svnSectionTitle] = Build-SvnComplianceSection -Format 'Html'
    }
    # Bucket / confidence (from event message metadata)
    if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
        $cardProperties['Rollout Tier'] = Build-RolloutTierSection -Format 'Html'
    }
    # Scheduled task status (only when Secure Boot is Enabled)
    if ($secureBoot -eq 'Enabled') {
        $cardProperties['Update Task'] = Build-UpdateTaskSection -Format 'Html'
    }
    # Opt-in status (only when Secure Boot is Enabled and check ran)
    if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
        $cardProperties['Opt-In Status'] = Build-OptInSection -Format 'Html'
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
        # Local HTML card: reuse the exact same Html-format output as Ninja (1:1 parity),
        # then swap FontAwesome <i> icons → emoji via Convert-FaIconsToEmoji.
        $localCardProperties = [ordered]@{
            'Secure Boot' = Convert-FaIconsToEmoji $statusRowHtml
            'Detail'      = Convert-FaIconsToEmoji $detailRowHtml
        }
        if ($null -ne $eventRowHtml) {
            $localCardProperties['Last Event'] = Convert-FaIconsToEmoji $eventRowHtml
        }
        # Build-* functions called with 'Html' format (same as Ninja card) for guaranteed parity
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $certStatus.EventSummary.Count -gt 0) {
            $localCardProperties['Event Log'] = Convert-FaIconsToEmoji (Build-EventLogSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled') {
            $localCardProperties['Certificates'] = Convert-FaIconsToEmoji (Build-CertInventorySection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $servicingStatus) {
            $servContent = Build-ServicingSection -Format 'Html'
            if ($null -ne $servContent) { $localCardProperties['Servicing'] = Convert-FaIconsToEmoji $servContent }
        }
        if ($secureBoot -eq 'Enabled' -and ($hasRegistryManifest -or $hasEventMitigations)) {
            $localCardProperties['Updates'] = Convert-FaIconsToEmoji (Build-UpdatesSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $svnStatus) {
            $localCardProperties[(Convert-FaIconsToEmoji $svnSectionTitle)] = Convert-FaIconsToEmoji (Build-SvnComplianceSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $certStatus -and $null -ne $certStatus.Confidence) {
            $localCardProperties['Rollout Tier'] = Convert-FaIconsToEmoji (Build-RolloutTierSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled') {
            $localCardProperties['Update Task'] = Convert-FaIconsToEmoji (Build-UpdateTaskSection -Format 'Html')
        }
        if ($secureBoot -eq 'Enabled' -and $null -ne $optInStatus) {
            $localCardProperties['Opt-In Status'] = Convert-FaIconsToEmoji (Build-OptInSection -Format 'Html')
        }
        
        $localCardInfo = [PSCustomObject]$localCardProperties
        
        $localCardTitle = "Secure Boot Status"
        
        $localCardHtml = Get-LocalHtmlDocument `
            -Title $localCardTitle `
            -Data $localCardInfo `
            -AccentColor $cardIconColor
        
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
                Write-Host "Reboot Link : 1800 -> reboot ($($rc.BootTimes[-1].ToString('yyyy-MM-dd HH:mm'))) -> 1799 (confirmed)"
            }
            else {
                Write-Host "Reboot Link : 1800 -> 1799 (no reboot found between them)"
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
        if ($null -ne $svnStatus) {
            if ($svnStatus.IsCompliant) {
                Write-Host "SVN Status  : Compliant"
            }
            elseif ($svnStatus.RebootPending) {
                Write-Host "SVN Status  : Pending SVN reboot - firmware SVN update not yet applied"
            }
            elseif ($svnStatus.RevocationAppliedPendingReboot) {
                Write-Host "SVN Status  : 2011 CA revocation pending reboot"
            }
            elseif ($svnStatus.RevocationPending) {
                Write-Host "SVN Status  : Pending - 2011 CA not yet revoked"
            }
            else {
                Write-Host "SVN Status  : $($svnStatus.ComplianceStatus)"
            }
            if ($svnStatus.Source -eq 'Raw DBX') {
                Write-Host "DBX SVN     : $(if ($svnStatus.DbxSVN) { $svnStatus.DbxSVN } else { 'Not present' })"
                if ($null -ne $svnStatus.WindowsUpdateSVN) {
                    Write-Host "WU SVN      : $($svnStatus.WindowsUpdateSVN)"
                }
            }
            else {
                Write-Host "Firmware SVN: $($svnStatus.FirmwareSVN)"
                Write-Host "BootMgr SVN : $($svnStatus.BootManagerSVN)"
                Write-Host "Staged SVN  : $($svnStatus.StagedSVN)"
            }
            if ($svnStatus.SvnUpdatePending) {
                Write-Host "SVN Pending : DBXUpdateSVN.bin $($svnStatus.WindowsUpdateSVN) not yet in DBX"
            }
            if ($null -ne $svnStatus.Stage) {
                Write-Host "SVN Stage   : $($svnStatus.Stage) - $($svnStatus.StageDetail)"
            }
        }
        if ($null -ne $svnEnforcementResult) {
            Write-Host "SVN Enforce : $($svnEnforcementResult.ActionsApplied.Count) applied, $($svnEnforcementResult.ActionsSkipped.Count) skipped$(if ($svnEnforcementResult.RebootRequired) { ' (reboot required)' })"
        }
        elseif ($EnforceSvnCompliance -eq 'Passive') {
            Write-Host "SVN Enforce : Passive (MS enforcement: June 2026 - 2027)"
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
