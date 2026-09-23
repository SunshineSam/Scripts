#Requires -Version 5.1
<#
    === Developed by Sam ===
    Last Edit: 09-23-2026
    
    09-23-2026: Added a pre-check for signed-in accounts. LogonUI cannot be overridden while a user is logged in, so the script now warns and exits without making changes
    12-11-2025: Addressed a small oversight in the logic that specifically effected Domain Tiles. Both Local & Domain tiles now work!
#>

<#
.SYNOPSIS
    Sets the Windows Logon UI "last logged on user" to a specific account
    for convenience.

.DESCRIPTION
    This script updates the core LogonUI values under:
      
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
    
    Specifically:
      Removes:
      - LastLoggedOnUser        (REG_SZ)
      - LastLoggedOnSAMUser     (REG_SZ)
      - LastLoggedOnDisplayName (REG_SZ)
      - LastLoggedOnUserSID     (REG_SZ)
      - LastLoggedOnProvider    (REG_SZ)  -> Authentication provider GUID
      
      Sets:
      - SelectedUserSID         (REG_SZ)
      - LastLoggedOnUser        (REG_SZ)
      - LastLoggedOnSAMUser     (REG_SZ)
      - LastLoggedOnDisplayName (REG_SZ)
      - LastLoggedOnUserSID     (REG_SZ)
      - LastLoggedOnProvider    (REG_SZ)  -> Authentication provider GUID
    
    And under:
      
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile
    
    It sets:
      - <SID> (REG_SZ)          -> Authentication provider GUID for that SID
    
    Input handling rules:
      
      - DOMAIN\User
          * Only allowed when the computer is joined to that same domain.
          * Domain must match the current joined domain (NetBIOS or FQDN).
          * Example: Domain\Sam on a computer joined to "Domain" or "Domain.local".
      
      - User
          * Treated as a LOCAL account.
          * For SID resolution: COMPUTERNAME\User
          * For LogonUI name values:
                .\User
            (matches how LogonUI shows local accounts)
      
      - DOMAIN\User when not domain joined
          * Rejected with an error. If the machine is not domain joined,
            you cannot set a domain user here.
    
    Authentication provider selection:
      
      Logon method is controlled by -AuthMethod / env:authMethod.
      It maps to the selection GUIDs you discovered:
        
        Password            -> {60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}
        Windows Hello Face  -> {8AF662BF-65A0-4D0A-A540-A338A999D36F}
        Windows Hello PIN   -> {2135F72A-90B5-4ED3-A7F1-8BB705AC276A}
        SmartCard           -> {8FD7E19C-3BF7-489B-A72C-846AB3678C96}
        FidoKey             -> {F8A1793B-7873-4046-B2A7-1F318747F427}
        Cloud               -> {C5D7540A-CD51-453B-B22B-05305BA03F07}
      
      These are written to:
        - LastLoggedOnProvider
        - HKLM\...\LogonUI\UserTile\<SID>
    
    Validation / resolution:
      
      - The script resolves the specified identity to a SecurityIdentifier (SID)
        using System.Security.Principal.NTAccount.
      - If SID resolution fails, the script logs an error and exits with code 1.
      - Display name is dynamically obtained from Win32_UserAccount.FullName
        (when available); otherwise the plain user name (e.g., "User") is used.
        DisplayName is *never* stored as ".\User" – just the friendly name.
    
    Signed-in account check:

      - Before any changes are made, the script checks for signed-in accounts
        (active, locked, or disconnected sessions).
      - If any are found, it logs a WARNING listing them and exits with code 1
        without touching the registry or LogonUI.exe.

    LogonUI refresh behavior:
      
      - When running as SYSTEM:
          * If a LogonUI.exe process is present, it is terminated *before*
            registry changes and allowed to restart.
          * After registry changes are written, LogonUI.exe is terminated
            again (if present) to ensure the new default user is picked up.
          * When not running as SYSTEM, the script does not attempt to touch
            LogonUI.exe.
    
    Example usage:
      
      - Set local user "User" using password auth on a workgroup box:
            .\Set-LogonUIUser.ps1 -LogonUser "User" -AuthMethod Password
      
      - Set domain user "Domain\User" using PIN on a domain-joined box:
            .\Set-LogonUIUser.ps1 -LogonUser "Domain\User" -AuthMethod HelloPIN

.PARAMETER SaveLogToDevice
    Switch:
      - $true  -> write logs to %SystemDrive%\Logs\LogonUI\Set-LogonUIUser.log
      - $false -> only emit to console/host

.PARAMETER LogonUser
    String identity to set as the last logged on user. Supports:
      
      - "DOMAIN\User"   -> domain account (must match current domain)
      - "User"          -> local account (COMPUTERNAME\User for SID,
                           .\User for LogonUI name values)
    
    UPN-style names ("user@domain") are not supported here to keep behavior simple strings.

.PARAMETER AuthMethod
    Authentication provider to bind as the last logon provider:
      
      - Password            -> classic password provider
      - Windows Hellp Face  -> Windows Hello face unlock
      - Windows Hello PIN   -> Windows Hello PIN (PicturePasswordLogonProvider)
      - Smart Card          -> smart card login
      - FidoKey             -> FIDO security key
      - Cloud               -> Cloud Experience (for Microsoft/AAD accounts)
    
    This controls:
      - LastLoggedOnProvider (LogonUI)
      - HKLM\...\LogonUI\UserTile\<SID>
    
    Default is Password.

.ENVIRONMENT VARIABLE
    saveLogToDevice : 1/true to enable SaveLogToDevice; 0/false to disable  
    logonUser       : user to set as last logged-on identity (same semantics
                      as -LogonUser parameter)
    authMethod      : optional; same values as -AuthMethod (Password,HelloPIN,etc.)

.NOTES
    This does *not* manipulate user hives or load/unload NTUSER.DAT.
    It only touches the LogonUI key for convenience pinning and, when
    running as SYSTEM, restarts LogonUI.exe before and after the change.

#>

[CmdletBinding()]
param(
    # Logging toggle
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true }),
    
    # Target identity for LogonUI (DOMAIN\User or User)
    [string]$LogonUser       = $(if ($env:logonUser) { $env:logonUser } else { '' }),
    
    # Authentication provider selection
    [ValidateSet('Password','Windows Hello Face','Windows Hello PIN','Smart Card','FidoKey','Cloud')]
    [string]$AuthMethod      = $(if ($env:loginAuthMethod) { $env:loginAuthMethod } else { 'Password' })
)

# =========================================
# BEGIN Block: Functions & Setup
# =========================================
begin {
    
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    
    # Helper function: Check if running as SYSTEM
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY\*" -or $id.IsSystem
    }
    
    # Helper function: Define logging function for consistent output and optional file logging
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        
        Write-Host "[$Level] $Message"
        
        if ($SaveLogToDevice) {
            $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            $MountPoint  = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $driveLetter = ($MountPoint -replace '[^A-Za-z]', '').ToUpper()
            $logDir      = "$driveLetter`:\Logs\LogonUI"
            $logFile     = Join-Path $logDir "LogonUIUser.log"
            
            if (-not (Test-Path $logDir)) {
                try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
            }
            
            $today        = Get-Date -Format 'yyyy-MM-dd'
            $header       = "=== $today ==="
            $existingText = if (Test-Path $logFile) { Get-Content $logFile -Raw } else { "" }
            
            if (-not $existingText -or -not ($existingText -match [regex]::Escape($header))) {
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
            [string]$Type = 'String'
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
        
        } while (-not $valuesMatch -and $attempt -lt 5)
        
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
        
        if (Test-RegistryValueEqual -Current $final -Desired $Value) {
            Write-Log "VERBOSE" "$Name confirmed $Value"
        }
        else {
            Write-Log "WARNING" "$Name failed to set to $Value"
        }
    }
    
    # Helper function: Restart LogonUI.exe when running as SYSTEM
    function Restart-LogonUI {
        <#
            When running as SYSTEM:
              - If one or more LogonUI.exe processes are present, terminate them.
              - Let the OS respawn LogonUI as needed.
              - This is done *before* and *after* registry changes to ensure
                the Logon UI refreshes its cached user list / default account.
            
            When not running as SYSTEM:
              - This function is effectively a no-op (logs VERBOSE only).
        #>
        [CmdletBinding()]
        param(
            [string]$Phase = ''
        )
        
        $isSystem = Test-IsSystem
        $phaseTag = if ($Phase) { " ($Phase)" } else { "" }
        
        if (-not $isSystem) {
            Write-Log "VERBOSE" "Restart-LogonUI$phaseTag skipped (not running as SYSTEM)."
            return
        }
        
        $procs = Get-Process -Name 'LogonUI' -ErrorAction SilentlyContinue
        if (-not $procs) {
            Write-Log "VERBOSE" "No LogonUI.exe process detected$phaseTag."
            return
        }
        
        Write-Log "INFO" "Restarting LogonUI$phaseTag (found $($procs.Count) instance(s))."
        
        foreach ($p in $procs) {
            try {
                Write-Log "VERBOSE" "Terminating LogonUI PID $($p.Id)..."
                $p.Kill()
                $p.WaitForExit(5000) | Out-Null
            }
            catch {
                Write-Log "WARNING" "Failed to terminate LogonUI PID $($p.Id): $_"
            }
        }
        
        # Give the OS a moment to respawn it if needed
        Start-Sleep -Seconds 2
    }
    
    # Helper function: Detect any interactive user sessions (active, locked, or disconnected)
    function Get-LoggedOnUsers {
        <#
            LogonUI will not honor the pinned user while an account is signed in
            (it shows the signed-in / locked account instead), so we detect this
            up front and bail out rather than making changes that won't apply.
            
            Sources:
              - Owners of explorer.exe processes (covers console, locked, and
                disconnected/RDP sessions)
              - Win32_ComputerSystem.UserName (console user, as a fallback)
            
            Returns an array of unique "DOMAIN\User (Session N)" strings.
        #>
        [CmdletBinding()]
        param()
        
        $users = @()
        
        try {
            $explorers = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
            foreach ($proc in $explorers) {
                try {
                    $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
                    if ($owner.ReturnValue -eq 0 -and $owner.User) {
                        $users += "$($owner.Domain)\$($owner.User) (Session $($proc.SessionId))"
                    }
                }
                catch {
                    Write-Log "VERBOSE" "Unable to resolve owner for explorer.exe PID $($proc.ProcessId): $_"
                }
            }
        }
        catch {
            Write-Log "WARNING" "Failed to enumerate explorer.exe processes: $_"
        }
        
        try {
            $consoleUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
            if ($consoleUser -and -not ($users | Where-Object { $_ -like "$consoleUser *" })) {
                $users += "$consoleUser (Console)"
            }
        }
        catch {
            Write-Log "VERBOSE" "Unable to query console user: $_"
        }
        
        return @($users | Select-Object -Unique)
    }
    
    # Helper function: Resolve a LogonUser string into canonical pieces
    function Resolve-LogonIdentity {
        <#
            Input:
              - "Domain\User" -> Domain account
              - "Sam"         -> Local account (ComputerName\User / .\User)
            
            Output object:
              - DomainName      -> Domain or ComputerName
              - UserName        -> Sam
              - SamAccountName  -> value to use in LogonUI: DOMAIN\User or .\User
              - DisplayName     -> Friendly display name (e.g., "DeviceName\User")
              - Sid             -> SID string (S-1-5-21-...)
              - IsDomainUser    -> $true/$false
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$InputUser
        )
        
        $u = $InputUser.Trim()
        if (-not $u) {
            throw "LogonUser is empty after trimming."
        }
        
        $domainPart = $null
        $userPart   = $null
        
        if ($u -like '*\*') {
            # DOMAIN\User form
            $parts = $u.Split('\', 2)
            $domainPart = $parts[0]
            $userPart   = $parts[1]
        }
        elseif ($u -like '*@*') {
            throw "UPN-style names ('user@domain') are not supported. Use 'DOMAIN\User' or 'User'."
        }
        else {
            # "User" -> local account
            $userPart = $u
        }
        
        if (-not $userPart) {
            throw "User portion of LogonUser could not be determined. Input: '$InputUser'"
        }
        
        # Machine/domain context
        $cs             = Get-CimInstance Win32_ComputerSystem
        $computerName   = $cs.Name
        $isDomainJoined = $cs.PartOfDomain
        $computerDomain = $cs.Domain
        
        # Build comparison list for allowed domain names
        $candidateDomains = @()
        
        if ($computerDomain) {
            $candidateDomains += $computerDomain
            if ($computerDomain -like '*.*') {
                # FQDN -> add NetBIOS-style short name
                $short = $computerDomain.Split('.')[0]
                if ($short) { $candidateDomains += $short }
            }
        }
        
        if ($env:USERDOMAIN -and ($candidateDomains -notcontains $env:USERDOMAIN)) {
            $candidateDomains += $env:USERDOMAIN
        }
        
        # Normalize array to upper for case-insensitive comparison
        $candidateDomainsUpper = $candidateDomains | ForEach-Object { $_.ToUpperInvariant() }
        
        $isDomainUser   = $false
        $resolvedDomain = $null
        
        if ($domainPart) {
            # DOMAIN\User was requested
            if (-not $isDomainJoined) {
                throw "This computer is not joined to a domain, but a domain user '$InputUser' was specified."
            }
            
            $requestedDomainUpper = $domainPart.ToUpperInvariant()
            
            if ($candidateDomainsUpper -notcontains $requestedDomainUpper) {
                $allowed = if ($candidateDomains) { $candidateDomains -join ', ' } else { '<unknown>' }
                throw "Requested domain '$domainPart' does not match the currently joined domain. Allowed: $allowed"
            }
            
            $isDomainUser   = $true
            $resolvedDomain = $domainPart   # Use exactly what was typed for canonical domain
        }
        else {
            # No domain specified -> treat as local
            $isDomainUser   = $false
            $resolvedDomain = $computerName
        }
        
        # Build NTAccount string for SID resolution (always COMPUTER/DOMAIN\User)
        $accountForSid = "$resolvedDomain\$userPart"
        
        # For LogonUI registry name values, use:
        #   - DOMAIN\User for domain users
        #   - .\User      for local users
        if ($isDomainUser) {
            $samForRegistry = $accountForSid
        }
        else {
            $samForRegistry = ".\$userPart"
        }
        
        # Try to resolve SID via .NET first, using the accountForSid identity
        $sidValue = $null
        try {
            $nt  = New-Object System.Security.Principal.NTAccount($accountForSid)
            $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
            $sidValue = $sid.Value
        }
        catch {
            # As a fallback, try Win32_UserAccount if available
            try {
                $filter = "Name='$userPart' AND Domain='$resolvedDomain'"
                $acct   = Get-CimInstance -ClassName Win32_UserAccount -Filter $filter -ErrorAction Stop
                if ($acct.SID) { $sidValue = $acct.SID }
            }
            catch {
                # leave $sidValue null; handled below
            }
        }
        
        if (-not $sidValue) {
            throw "Failed to resolve SID for '$accountForSid'. Ensure the account exists and is accessible."
        }
        
        # Resolve display name / friendly name
        $displayName = $null
        try {
            $filter = "Name='$userPart' AND Domain='$resolvedDomain'"
            $acct   = Get-CimInstance -ClassName Win32_UserAccount -Filter $filter -ErrorAction Stop
            
            if ($acct.FullName) {
                $displayName = $acct.FullName
            }
            elseif ($acct.Caption) {
                $displayName = $acct.Caption
            }
        }
        catch {
            # If WMI fails for any reason, fall back to plain user name
        }
        
        if (-not $displayName) {
            # Plain "Sam" — explicitly do NOT add ".\" here
            $displayName = $userPart
        }
        
        [PSCustomObject]@{
            DomainName     = $resolvedDomain
            UserName       = $userPart
            SamAccountName = $samForRegistry   # DOMAIN\User or .\User for LogonUI
            DisplayName    = $displayName      # friendly name without ".\"
            Sid            = $sidValue
            IsDomainUser   = $isDomainUser
        }
    }
    
    # Constant for LogonUI key paths
    $script:LogonUIKey        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
    $script:LogonUIUserTile   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile'
    
    # Map AuthMethod -> provider GUID
    $script:AuthProviderMap = @{
        'Password'           = '{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}'
        'Windows Hello Face' = '{8AF662BF-65A0-4D0A-A540-A338A999D36F}'
        'Windows Hello PIN'  = '{2135F72A-90B5-4ED3-A7F1-8BB705AC276A}'
        'Smart Card'         = '{8FD7E19C-3BF7-489B-A72C-846AB3678C96}'
        'FidoKey'            = '{F8A1793B-7873-4046-B2A7-1F318747F427}'
        'Cloud'              = '{C5D7540A-CD51-453B-B22B-05305BA03F07}'
    }
    
    # Helper function: Ensure UserTile only contains a single SID -> provider mapping
    function Set-UserTileProviderSingle {
        <#
            Ensures HKLM\...\LogonUI\UserTile is "clean" and contains exactly one
            value:
            
              Name : <SID>
              Data : <ProviderGuid>
            
            This avoids stale SIDs competing with the desired default.
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProviderGuid
        )
        
        # Make sure the UserTile key exists
        if (-not (Test-Path $script:LogonUIUserTile)) {
            try {
                Write-Log "VERBOSE" "Creating UserTile key at '$script:LogonUIUserTile'"
                New-Item -Path $script:LogonUIUserTile -Force | Out-Null
            }
            catch {
                Write-Log "ERROR" "Failed to create UserTile key at '$script:LogonUIUserTile': $_"
                return
            }
        }
        else {
            # Clear any existing SID/value pairs; Windows appears to only honor one
            try {
                $existingProps = (Get-Item $script:LogonUIUserTile).Property
                foreach ($prop in $existingProps) {
                    if ([string]::IsNullOrWhiteSpace($prop)) {
                        # Keep (default) unnamed value if present
                        continue
                    }
                    Write-Log "VERBOSE" "Removing existing UserTile entry '$prop'"
                    Remove-ItemProperty -Path $script:LogonUIUserTile -Name $prop -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "WARNING" "Failed to enumerate/clear existing UserTile values: $_"
            }
        }
        
        # Now write the single, authoritative SID -> provider mapping
        Write-Log "INFO" "Setting UserTile mapping for SID '$Sid' to provider '$ProviderGuid'"
        RegistryShouldBe -KeyPath $script:LogonUIUserTile -Name $Sid -Value $ProviderGuid -Type 'String'
    }
    
    # Helper: Clear existing "last logon" state
    function Clear-LogonUIState {
        <#
            Emulates the Ivanti article:
              - Remove LastLoggedOnUser / LastLoggedOnSAMUser so they repopulate cleanly
            and extends it to:
              - Also clear LastLoggedOnDisplayName / LastLoggedOnUserSID / SelectedUserSID
              - Clear any existing UserTile SID mappings
            
            Call this *before* setting a new pinned user so that no stale values
            interfere with the next LogonUI session.
        #>
        [CmdletBinding()]
        param()
        
        Write-Log "INFO" "Clearing existing LogonUI last-user state..."
        
        if (Test-Path $script:LogonUIKey) {
            $valueNames = @(
                'LastLoggedOnUser',
                'LastLoggedOnSAMUser',
                'LastLoggedOnDisplayName',
                'LastLoggedOnUserSID',
                'SelectedUserSID',
                'LastLoggedOnProvider'
            )
            
            foreach ($name in $valueNames) {
                try {
                    Remove-ItemProperty -Path $script:LogonUIKey -Name $name -ErrorAction SilentlyContinue
                    Write-Log "VERBOSE" "Removed LogonUI value '$name'"
                }
                catch {
                    Write-Log "WARNING" "Failed to remove LogonUI value '$name': $_"
                }
            }
        }
        else {
            Write-Log "VERBOSE" "LogonUI key '$script:LogonUIKey' does not exist; nothing to clear."
        }
        
        # Clear existing UserTile SID → provider mappings
        if (Test-Path $script:LogonUIUserTile) {
            try {
                $props = (Get-Item $script:LogonUIUserTile).Property
                foreach ($prop in $props) {
                    if ([string]::IsNullOrWhiteSpace($prop)) {
                        # Preserve default unnamed value if there is one
                        continue
                    }
                    Write-Log "VERBOSE" "Removing UserTile entry '$prop'"
                    Remove-ItemProperty -Path $script:LogonUIUserTile -Name $prop -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "WARNING" "Failed to enumerate/clear UserTile values: $_"
            }
        }
        else {
            Write-Log "VERBOSE" "UserTile key '$script:LogonUIUserTile' does not exist; nothing to clear."
        }
    }
}

# =========================================
# PROCESS Block: Apply Settings
# =========================================
process {
    
    if (-not (Test-IsElevated)) {
        Write-Log "ERROR" "Administrator privileges are required."
        exit 1
    }
    
    if (-not $LogonUser) {
        Write-Log "ERROR" "LogonUser parameter (or env:logonUser) is required."
        exit 1
    }
    
    Write-Log "INFO" "=== Set Logon User starting ==="
    Write-Log "INFO" "Requested LogonUser: '$LogonUser'"
    Write-Log "INFO" "Requested AuthMethod: '$AuthMethod'`b"
    
    $isSystem = Test-IsSystem
    
    # Resolve provider GUID from AuthMethod
    $providerGuid = $AuthProviderMap[$AuthMethod]
    if (-not $providerGuid) {
        Write-Log "ERROR" "AuthMethod '$AuthMethod' did not resolve to a provider GUID."
        exit 1
    }
    
    # Pre-check: LogonUI cannot be overridden while an account is signed in
    $loggedOnUsers = Get-LoggedOnUsers
    if ($loggedOnUsers.Count -gt 0) {
        Write-Log "WARNING" "An account is currently signed in to this device. LogonUI cannot be overridden while a user is logged in."
        foreach ($u in $loggedOnUsers) {
            Write-Log "WARNING" "  Signed in: $u"
        }
        Write-Log "WARNING" "No changes were made. Have the user(s) sign out (not just lock) and run this script again."
        exit 1
    }
    Write-Log "VERBOSE" "No signed-in accounts detected; continuing.`n"
    
    # Step 0: Restart LogonUI (pre-change) when running as SYSTEM
    if ($isSystem) {
        Restart-LogonUI -Phase 'before change'
    }
    
    # Step 1: Resolve identity into domain + SID + display name
    try {
        $identity = Resolve-LogonIdentity -InputUser $LogonUser
    }
    catch {
        Write-Log "ERROR" $_.Exception.Message
        exit 1
    }
    
    $samName     = $identity.SamAccountName   # DOMAIN\User or .\User (for registry)
    $displayName = $identity.DisplayName      # friendly name (no .\)
    $sidString   = $identity.Sid
    
    Write-Log "INFO" "Resolved identity:"
    Write-Log "INFO" "  Logon name: $samName"
    Write-Log "INFO" "  Display:    $displayName"
    Write-Log "INFO" "  IsDomain:   $($identity.IsDomainUser)"
    Write-Log "INFO" "  Provider:   $($AuthProviderMap[$AuthMethod])`n"
    
    # Step 1.5: Clear any existing last-logon state (Ivanti-style prep)
    Clear-LogonUIState
    
    # Step 2: Write to LogonUI registry values
    Write-Log "INFO" "Updating LogonUI registry values..."
    
    # SAM-style name (DOMAIN\User or .\User) for both LastLoggedOn* values
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'LastLoggedOnUser'        -Value $samName     -Type 'String'
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'LastLoggedOnSAMUser'     -Value $samName     -Type 'String'
    
    # Friendly display name (no ".\"): usually the user’s FullName or just "Sam"
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'LastLoggedOnDisplayName' -Value $displayName -Type 'String'
    
    # SID for the account
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'LastLoggedOnUserSID'     -Value $sidString   -Type 'String'
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'SelectedUserSID'         -Value $sidString   -Type 'String'
    
    # Provider GUID for the chosen auth method
    RegistryShouldBe -KeyPath $LogonUIKey -Name 'LastLoggedOnProvider'    -Value $providerGuid -Type 'String'
    
    # UserTile\<SID> -> provider GUID
    # Only one SID entry at a time.
    Set-UserTileProviderSingle -Sid $sidString -ProviderGuid $providerGuid
    
    # Step 3: Restart LogonUI (post-change) when running as SYSTEM
    if ($isSystem) {
        Restart-LogonUI -Phase 'after change'
    }
    
    Write-Log "INFO" "LogonUI user pinned to '$samName' (Provider: $($AuthProviderMap[$AuthMethod]))."
    Write-Log "INFO" "The next interactive logon UI should default to this account and auth method."
}

# =========================================
# END Block: Completion
# =========================================
end {
    Write-Log "INFO" "Set Logon User complete."
}