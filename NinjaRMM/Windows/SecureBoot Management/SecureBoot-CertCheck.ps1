#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 03-05-2026
    
    Note:
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
    Reports Secure Boot status and 2023 certificate update state for NinjaRMM.

.DESCRIPTION
    Checks whether the machine supports UEFI Secure Boot, whether it is enabled,
    and (if enabled) queries the System event log for Microsoft-Windows-TPM-WMI
    events 1808 (BIOS updated - compliant) and 1801 (Windows updated but BIOS
    not yet updated - action required). Outputs an HTML status card and a
    searchable plain-text summary to NinjaRMM custom fields.
    
    The five possible output states are:
      1. Not Applicable  - Non-UEFI or unsupported hardware (Confirm-SecureBootUEFI throws)
      2. Disabled        - UEFI capable but Secure Boot is off
      3. Compliant       - Secure Boot on, Event 1808 found (BIOS certs updated)
      4. Action Required - Secure Boot on, Event 1801 found (BIOS firmware update needed)
                         - OR Secure Boot on, no events, and 2023 cert missing from both db and dbDefault
      5. Pending         - Secure Boot on, no events, 2023 cert in db or dbDefault (awaiting update)

.PARAMETER StatusCardFieldName
    NinjaRMM WYSIWYG custom field name for the HTML status card.
    Defaults to "SecureBootCertStatusCard" or env:secureBootStatusCardField.

.PARAMETER PlainTextFieldName
    NinjaRMM text custom field name for the plain-text summary.
    Defaults to "SecureBootCertStatus" or env:secureBootPlainTextField.

.PARAMETER SaveStatusLocal
    If specified, saves the plain-text status to a local text file and the HTML card to a local HTML file,
    in addition to any NinjaRMM field updates. Useful for non-NinjaRMM environments.

.PARAMETER TestUEFIEnvironmentVariableAccess
    If specified, performs an active test of UEFI variable writability using a custom test variable.
    This is optional and only runs if Secure Boot is Enabled.
#>

[CmdletBinding()]
param(
    # Ninja custom field names          Ninja Variable Resolution                                             Fallback
    [string]$StatusCardFieldName = $(if ($env:secureBootStatusCardField)  { $env:secureBootStatusCardField }  else { "SecureBootCertStatusCard" }), # Optional Ninja Script Variable; String
    [string]$PlainTextFieldName  = $(if ($env:secureBootPlainTextField)   { $env:secureBootPlainTextField }   else { "SecureBootCertStatus" }),     # Optional Ninja Script Variable; String
    
    # Other options                 Ninja Variable Resolution                                             Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true }), # Ninja Script Variable; Checkbox
    [switch]$SaveStatusLocal = $(if ($env:saveStatusLocal) { [Convert]::ToBoolean($env:saveStatusLocal) } else { $false }), # Ninja Script Variable; Checkbox
    
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
        
        $buffer = New-Object byte[] 65536  # 64 KB — Dell/OEM db can exceed 4 KB
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
    
    # Helper function: Query the System event log for Secure Boot certificate update events
    # Event 1808 = Certificates updated successfully in BIOS (compliant)
    # Event 1801 = Certificates updated in Windows but NOT yet in BIOS (action required)
    # Event 1799 = Boot manager installed, awaiting BIOS update confirmation
    # Neither    = Machine has not received the certificate update via Windows Update yet
    #
    # Returns a hashtable: @{ Status; EventId; EventTime; EventMessage }
    function Get-CertUpdateEventStatus {
        $events = $null
        
        # Primary method: Get-WinEvent (modern, preferred for Windows 10+)
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = 1799, 1801, 1808
            } -MaxEvents 5 -ErrorAction Stop
            Write-Log "INFO" "Get-WinEvent succeeded: $(@($events).Count) event(s) found"
        }
        catch {
            # Get-WinEvent throws (rather than returning empty) when no events match or provider is missing.
            # Distinguish "no results" from a real error to decide whether to fall back.
            if ($_.Exception.Message -match 'No events were found') {
                Write-Log "INFO" "Get-WinEvent: No matching events found in System log"
                $events = @()
            }
            else {
                Write-Log "WARNING" "Get-WinEvent failed: $($_.Exception.Message). Attempting Get-EventLog fallback."
                # Legacy fallback: Get-EventLog (deprecated in PS7 but available on PS5.1)
                try {
                    $events = Get-EventLog `
                        -LogName System `
                        -Source 'Microsoft-Windows-TPM-WMI' `
                        -Newest 5 `
                        -InstanceId 1799, 1801, 1808 `
                        -ErrorAction Stop
                    Write-Log "INFO" "Get-EventLog fallback succeeded: $(@($events).Count) event(s) found"
                }
                catch {
                    Write-Log "WARNING" "Get-EventLog fallback also failed: $($_.Exception.Message). Treating as no events found."
                    $events = @()
                }
            }
        }
        
        $events = @($events)
        
        if ($events.Count -eq 0) {
            return @{
                Status       = 'Pending'
                EventId      = $null
                EventTime    = $null
                EventMessage = 'No TPM-WMI certificate update events (1799/1801/1808) found in System log'
            }
        }
        
        # The most recent event reflects the current state of the machine.
        # If both 1808 and 1801 are present, 1808 (BIOS updated) should be more recent after remediation.
        $latestEvent = $events | Sort-Object -Property { if ($_.TimeCreated) { $_.TimeCreated } else { $_.TimeGenerated } } -Descending | Select-Object -First 1
        
        # Normalize property names between Get-WinEvent (Id, TimeCreated) and Get-EventLog (InstanceId, TimeGenerated)
        $eventId   = if ($null -ne $latestEvent.Id)          { $latestEvent.Id }          else { $latestEvent.InstanceId }
        $eventTime = if ($null -ne $latestEvent.TimeCreated) { $latestEvent.TimeCreated } else { $latestEvent.TimeGenerated }
        
        Write-Log "INFO" "Most recent certificate event: ID $eventId at $eventTime"
        
        switch ($eventId) {
            1808 {
                return @{
                    Status       = 'Compliant'
                    EventId      = 1808
                    EventTime    = $eventTime
                    EventMessage = 'Certificates updated successfully in BIOS (Event 1808)'
                }
            }
            1801 {
                return @{
                    Status       = 'ActionRequired'
                    EventId      = 1801
                    EventTime    = $eventTime
                    EventMessage = 'Certificates updated in Windows but NOT yet in BIOS (Event 1801)'
                }
            }
            1799 {
                return @{
                    Status       = 'Pending'
                    EventId      = 1799
                    EventTime    = $eventTime
                    EventMessage = 'Boot manager installed, awaiting BIOS update (Event 1799)'
                }
            }
            default {
                Write-Log "WARNING" "Unexpected event ID $eventId encountered; treating as Pending"
                return @{
                    Status       = 'Pending'
                    EventId      = $eventId
                    EventTime    = $eventTime
                    EventMessage = "Unexpected event ID $eventId found; treating as Pending"
                }
            }
        }
    }
    
    # Helper function: Check for recent post-trigger events (1808, 1799) in last N minutes
    # Returns: 'Compliant' (1808 found), 'Pending1808' (1799 found, awaiting 1808),
    #          or 'Pending1799' (neither found, awaiting 1799)
    function Check-PostTriggerEvents {
        param (
            [int]$Minutes = 5
        )
        $startTime = (Get-Date).AddMinutes(-$Minutes)
        
        # Check for 1808 first (best case — already fully compliant)
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
        
        return 'Pending1799'
    }
    
    # Helper function: Set the AvailableUpdates registry key to trigger OS-side update
    function Set-SecureBootUpdateRegKey {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        $regName = "AvailableUpdates"
        $regValue = 0x5944  # Bitmask to trigger all updates
        
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord -Force
            Write-Log "SUCCESS" "Set $regPath\$regName to 0x5944 to trigger Secure Boot updates"
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
# PROCESS Block: (Status Reporting Only)
# =========================================
process {
    
}

# =========================================
# END Block: Core Logic & Output
# =========================================
end {
    Write-Host "`n=== Secure Boot Certificate Status Check ==="
    
    # -----------------------------------------------
    # Step 1: Determine Secure Boot state
    # -----------------------------------------------
    Write-Log "INFO" "Checking Secure Boot UEFI status"
    $secureBoot = Get-SecureBootStatus
    Write-Log "INFO" "Secure Boot status: $secureBoot"
    
    # -----------------------------------------------
    # Step 1.5: If Enabled, parse db and dbx certificates
    # -----------------------------------------------
    $has2023InDb = $false
    $has2023InDbDefault = $false
    if ($secureBoot -eq 'Enabled') {
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
            Write-Log "WARNING" "Failed to parse db/dbx: $($_.Exception.Message)"
        }
        
        # Check for 2023 cert in db
        try {
            $has2023InDb = [System.Text.Encoding]::ASCII.GetString($dbBytes) -match 'Windows UEFI CA 2023'
            Write-Log "INFO" "2023 Cert in db: $has2023InDb"
        }
        catch {
            Write-Log "WARNING" "Failed to check 2023 cert in db: $($_.Exception.Message)"
        }
        
        # If not in db, check dbDefault
        if (-not $has2023InDb) {
            try {
                $dbDefaultBytes = (Get-SecureBootUEFI -Name dbDefault -ErrorAction Stop).Bytes
                $has2023InDbDefault = [System.Text.Encoding]::ASCII.GetString($dbDefaultBytes) -match 'Windows UEFI CA 2023'
                Write-Log "INFO" "2023 Cert in dbDefault: $has2023InDbDefault"
            }
            catch {
                Write-Log "WARNING" "Failed to check 2023 cert in dbDefault: $($_.Exception.Message)"
            }
        }
        
        # Always perform passive attributes check for 'db'
        Write-Host "`n === Windows UEFI DB Access Check ==="
        Write-Log "INFO" "Performing passive UEFI variable attributes check for 'db'"
        $dbAttributes = Get-UefiVariableAttributes -VarName "db"
        $dbIsOsWritable = $null -ne $dbAttributes -and (($dbAttributes -band 0x00000004) -ne 0) -and (($dbAttributes -band 0x00000020) -ne 0)
        Write-Log "INFO" "OS capable of writing to UEFI db: $dbIsOsWritable"
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
    # Step 2.5: Automate registry trigger if needed
    # -----------------------------------------------
    $triggeredOsUpdate = $false
    $postTriggerState  = $null
    # Trigger if 2023 cert is in db but OS hasn't confirmed via 1808 (stale 1801 or no events at all)
    if ($secureBoot -eq 'Enabled' -and $has2023InDb -and $certStatus.EventId -ne 1808) {
        if ($certStatus.EventId -eq 1799) {
            $ageMinutes = ((Get-Date) - $certStatus.EventTime).TotalMinutes
            Write-Log "INFO" "1799 event age: $ageMinutes minutes"
            if ($ageMinutes -gt 20) {
                $postTriggerState = 'PendingRestart'
            }
            else {
                $postTriggerState = 'Pending1808'
            }
        }
        else {
            if ($certStatus.Status -eq 'ActionRequired') {
                Write-Log "INFO" "2023 cert in db but stale 1801; attempting to trigger OS update"
            }
            else {
                Write-Log "INFO" "2023 cert in db but no events logged; attempting to trigger OS update"
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
                    Write-Log "INFO" "Post-trigger state: $postTriggerState"
                }
            }
        }
    }
    
    # -----------------------------------------------
    # Step 3: Map to one of the 5 final states
    # -----------------------------------------------
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
        
        # State 3: Compliant (Secure Boot enabled + Event 1808 found)
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Compliant') {
            $statusKey     = 'Compliant'
            $cardIconColor = '#26A644'
            $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
            $detailRowHtml = '2023 Secure Boot certificates have been successfully<br />applied to the BIOS firmware.<br />No action required.'
            $eventTime     = if ($certStatus.EventTime) { $certStatus.EventTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> Event 1808 detected at ' + $eventTime
            $plainText     = '✅ Secure Boot Enabled. Certificates up to date in BIOS (Event 1808). Compliant.'
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
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is in firmware defaults (dbDefault)<br />but not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately.' + $bitlockerNote + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert in dbDefault; Windows will push to db directly, or reset keys to apply now.'
                    $statusEmoji = '⚠️'
                }
                else {
                    $detailRowHtml = 'Windows has applied 2023 Secure Boot certificates<br />but the BIOS active database has NOT been updated.<br />BIOS supports via default db; reset Secure Boot keys<br />in BIOS to apply before the June 2026 deadline.<br /> Re-Run script after secure boot keys are cleared!' + $bitlockerNote + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. BIOS supports 2023 cert (in dbDefault); reset keys to apply (Event 1801).'+ $guidePlain + ' BIOS Key Reset Required.'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault — firmware update or OS-driven update needed
                $oemBiosGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosGuide) {
                    $biosGuideHtml = '<br /><a href="' + $oemBiosGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $biosGuideHtml = ''
                }
                if ($dbIsOsWritable) {
                    $statusKey     = 'ActionOptional'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Action Optional'
                    $eventRowHtml  = '<i class="fas fa-calendar-times" style="color:#F0AD4E;"></i> Event 1801 detected at ' + $eventTime
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update will eventually push the cert automatically,<br />or a manual BIOS update can be applied.' + $biosGuideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing; Windows will eventually update the BIOS db directly, or push a BIOS update if available.'
                    $statusEmoji = '⚠️'
                }
                else {
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support before Windows Update<br />can complete the rotation. Update before June 2026.' + $biosGuideHtml
                    $plainText     = '❌ Secure Boot Enabled. 2023 cert missing from db and dbDefault. OEM BIOS/firmware update required.'
                    $statusEmoji = '❌'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            break
        }
        
        # State 5: Pending (Secure Boot enabled, no certificate update events found)
        # Sub-branches based on whether 2023 cert exists in db or dbDefault
        ($secureBoot -eq 'Enabled' -and $certStatus.Status -eq 'Pending' -and -not $postTriggerState) {
            $eventRowHtml  = '<i class="fas fa-search" style="color:#F0AD4E;"></i> No certificate update events (1808/1801) found'
            
            if ($has2023InDb) {
                # 2023 cert already in active db but no events logged — possibly pre-installed by firmware or manually added
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = '2023 Secure Boot certificate is present in the active db<br />but no completion events (1808/1801) were logged.<br />Cert may have been pre-installed by firmware.<br />Awaiting Windows Update to finalize validation.'
                $plainText     = '⚠️ Secure Boot Enabled. 2023 cert in db but no events logged. Waiting for Windows Update to finalize. Pending probable reboot.'
            }
            elseif ($has2023InDbDefault) {
                # 2023 cert in firmware defaults but not deployed — Windows Update or key reset can resolve
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
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Action Optional'
                if ($dbIsOsWritable) {
                    $detailRowHtml = '2023 Secure Boot certificate is in firmware defaults (dbDefault)<br />but not yet in the active database (db).<br />Windows is capable of updating the BIOS cert db directly<br />and will eventually push the cert automatically.<br />Optionally, reset Secure Boot keys in BIOS to apply immediately.' + $bitlockerNote + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert in dbDefault; Windows will push to db directly, or reset keys to apply now.'
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events — Windows capable of updating BIOS db'
                }
                else {
                    $detailRowHtml = '2023 Secure Boot certificate is in firmware defaults (dbDefault)<br />but not yet in the active database (db).<br /> Reset Secure Boot keys in BIOS to apply from defaults.<br /> Re-Run after for an updated status.' + $bitlockerNote + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert in dbDefault but not db; Reset keys in BIOS (see card details) before Windows can complete the rotation. Pending BIOS key reset.'
                }
                if ($plainText.Length -gt 200) {
                    $plainText = $plainText.Substring(0, 197) + '...'
                }
            }
            else {
                # 2023 cert not in db OR dbDefault — firmware update or OS-driven update needed
                $oemBiosUpdateGuide = Get-OemBIOSUpdateGuide
                if ($oemBiosUpdateGuide) {
                    $guideHtml = '<br /><a href="' + $oemBiosUpdateGuide + '" target="_blank">OEM BIOS/Firmware Update Guide</a>'
                }
                else {
                    $guideHtml = ''
                }
                if ($dbIsOsWritable) {
                    $statusKey     = 'Pending'
                    $cardIconColor = '#F0AD4E'
                    $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Action Optional'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />However, Windows is capable of updating the BIOS cert db directly.<br />Windows Update may push the cert automatically,<br />or a manual BIOS update can be applied.' + $guideHtml
                    $plainText     = '⚠️ Secure Boot Enabled. 2023 cert missing; Windows can update BIOS db directly, or push BIOS update.'
                    $eventRowHtml  = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> No events — Windows capable of updating BIOS db'
                    $statusEmoji = '⚠️'
                }
                else {
                    $statusKey     = 'ActionRequired'
                    $cardIconColor = '#D9534F'
                    $statusRowHtml = '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Action Required'
                    $detailRowHtml = '2023 Secure Boot certificate is NOT present in the active<br />database (db) or firmware defaults (dbDefault).<br />A BIOS/firmware update from the OEM is required<br />to add 2023 certificate support before Windows Update<br />can complete the rotation. Update before June 2026.' + $guideHtml
                    $plainText     = '❌ Secure Boot Enabled. 2023 cert missing from db and dbDefault. OEM BIOS/firmware update required.'
                    $eventRowHtml  = '<i class="fas fa-exclamation-circle" style="color:#D9534F;"></i> No events — BIOS lacks 2023 certificate support'
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
    
    # Override for triggered OS update based on post-trigger event state
    if ($postTriggerState) {
        switch ($postTriggerState) {
            'Compliant' {
                # 1808 already appeared — fully done
                $statusKey     = 'Compliant'
                $cardIconColor = '#26A644'
                $statusRowHtml = '<i class="fas fa-check-circle" style="color:#26A644;"></i> Compliant'
                $detailRowHtml = 'Triggered OS-side update.<br />Event 1808 detected — 2023 certificates successfully<br />applied to BIOS firmware. No action required.'
                $plainText     = '✅ Secure Boot Enabled. Triggered OS update; 1808 detected. Certificates up to date. Compliant.'
                $eventRowHtml  = '<i class="fas fa-calendar-check" style="color:#26A644;"></i> 1808 detected after trigger — Compliant'
                $statusEmoji = '✅'
            }
            'Pending1808' {
                # 1799 found, awaiting 1808
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = 'Event 1799 detected (boot manager installed).<br />Pending UEFI final validation (1808) ~15 min.'
                $plainText     = '⚠️ Secure Boot Enabled. 1799 detected, awaiting 1808 (~15 min). Pending final event confirmation.'
                $eventRowHtml  = '<i class="fas fa-search" style="color:#F0AD4E;"></i> 1799 detected; awaiting 1808 (~15 min)'
                $statusEmoji = '⚠️'
            }
            'PendingRestart' {
                # 1799 old, likely stuck pending restart
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending'
                $detailRowHtml = 'Event 1799 detected (boot manager installed).<br />But over 20 minutes ago without 1808.<br />Likely pending a system restart to complete.'
                $plainText     = '⚠️ Secure Boot Enabled. 1799 old (>20 min), no 1808. Likely pending restart.'
                $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> 1799 old; likely pending restart'
                $statusEmoji = '⚠️'
                $rebootStatus = Get-PendingRebootStatus
                if ($rebootStatus.Pending) {
                    $sourceList = $rebootStatus.Sources -join ', '
                    Write-Log "INFO" "Reboot pending from: $sourceList"
                    $detailRowHtml += '<br />Reboot pending from: ' + $sourceList
                    $plainText     += ' Reboot pending (' + $sourceList + ').'
                    if ($plainText.Length -gt 200) {
                        $plainText = $plainText.Substring(0, 197) + '...'
                    }
                }
            }
            default {
                # Neither 1808 nor 1799 yet — check if a reboot is pending
                $rebootStatus = Get-PendingRebootStatus
                $statusKey     = 'Pending'
                $cardIconColor = '#F0AD4E'
                $statusRowHtml = '<i class="fas fa-clock" style="color:#F0AD4E;"></i> Pending Restart'
                if ($rebootStatus.Pending) {
                    $sourceList = $rebootStatus.Sources -join ', '
                    Write-Log "INFO" "Reboot pending from: $sourceList"
                    $detailRowHtml = 'Triggered OS-side update.<br />No 1799 yet (boot manager install).<br />A system reboot is pending (' + $sourceList + ').<br />Reboot may be required before update can proceed.'
                    $plainText     = '⚠️ Secure Boot Enabled. Triggered OS update; no 1799 yet. Reboot pending (' + $sourceList + ').'
                    if ($plainText.Length -gt 200) {
                        $plainText = $plainText.Substring(0, 197) + '...'
                    }
                    $eventRowHtml  = '<i class="fas fa-exclamation-triangle" style="color:#F0AD4E;"></i> Awaiting 1799 - reboot pending (' + $sourceList + ')'
                }
                else {
                    Write-Log "INFO" "No pending reboot detected"
                    $detailRowHtml = 'Triggered OS-side update.<br />No 1799 yet (boot manager install).<br />Pending signed boot manager confirmation (1799) ~5 min.'
                    $plainText     = '⚠️ Secure Boot Enabled. Triggered OS update; awaiting 1799 (~5 min). Pending event validation.'
                    $eventRowHtml  = '<i class="fas fa-search" style="color:#F0AD4E;"></i> Awaiting 1799 (~5 min)'
                }
                $statusEmoji = '⚠️'
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
    Write-Host "--------------------------------------`n"
    
    Write-Host "=== Complete ==="
    Write-Log "SUCCESS" "Secure Boot certificate status check completed"
}
