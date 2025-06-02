#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-31-2025
#>

<#
.SYNOPSIS
    Configures various Windows Explorer advanced options via ValidateSet Actions.

.DESCRIPTION
    This script uses three Action parameters (each with "Enable"/"Disable") to control:
      - HideFileExtension    -> Show or hide file extensions (Enable = hide, Disable = show)  
      - UseCompactMode       -> Enable or disable compact mode in Explorer  
      - StartShowOnUpgrade   -> Show or hide Start layout after an upgrade  

    Additionally, it can restart Explorer if requested and apply to the Default user hive.
    Settings are applied machine-wide (HKLM) and per-user (loaded hives or HKCU).

.PARAMETER HideFileExtension
    ValidateSet Enable|Disable.  
      Enable  = hide file extensions (HideFileExt = 1)  
      Disable = show file extensions (HideFileExt = 0)

.PARAMETER UseCompactMode
    ValidateSet Enable|Disable.  
      Enable  = compact mode on (UseCompactMode = 1)  
      Disable = compact mode off (UseCompactMode = 0)

.PARAMETER StartShowOnUpgrade
    ValidateSet Enable|Disable.  
      Enable  = show Start on upgrade (StartShowOnUpgrade = 1)  
      Disable = hide Start on upgrade (StartShowOnUpgrade = 0)

.PARAMETER RestartExplorer
    Switch:
      - $true  = restart Explorer at end  
      - $false = do not restart

.PARAMETER IncludeDefaultHive
    Switch:
      - $true  = apply to Default user hive  
      - $false = skip Default user hive

.PARAMETER SaveLogToDevice
    Switch:
      - $true  = save log to device  
      - $false = do not save log
#>

[CmdletBinding()]
param(
    # Dropdown options                                           Ninja Variable Resolution                                    Fallback
    [ValidateSet('Enable','Disable')][string]$HideFileExtension  = $(if ($env:hideFileExtension) { $env:hideFileExtension }   else { 'Enable' }), # Ninja Script Variable; Dropdown
    [ValidateSet('Enable','Disable')][string]$UseCompactMode     = $(if ($env:useCompactMode) { $env:useCompactMode }         else { 'Disable' }), # Ninja Script Variable; Dropdown
    [ValidateSet('Enable','Disable')][string]$StartShowOnUpgrade = $(if ($env:startShowOnUpgrade) { $env:startShowOnUpgrade } else { 'Enable' }), # Ninja Script Variable; Dropdown
    
    # Individual switches       Ninja Variable Resolution                                                          Fallback
    [switch]$RestartExplorer    = $(if ($env:restartExplorer) { [Convert]::ToBoolean($env:restartExplorer) }       else { $true }),  # Ninja Script Variable; Checkbox
    [switch]$IncludeDefaultHive = $(if ($env:includeDefaultHive) { [Convert]::ToBoolean($env:includeDefaultHive) } else { $false }), # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice    = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }       else { $false })  # Ninja Script Variable; Checkbox
)

# ===========================================
# BEGIN Block: Helper Functions & Validation
# ===========================================
begin {
    # Helper function: Ensure script runs elevated
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
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
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            $MountPoint = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $driveLetter = ($MountPoint -replace '[^A-Za-z]', '').ToUpper()
            $logDir = "$driveLetter`:\Logs\Explorer"
            $logFile = Join-Path $logDir "ExplorerSettings.log"
            if (-not (Test-Path $logDir)) {
                try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
            }
            $today = Get-Date -Format 'yyyy-MM-dd'
            $header = "=== $today ==="
            $existingContent = if (Test-Path $logFile) { Get-Content $logFile -Raw } else { "" }
            if (-not $existingContent -or -not ($existingContent -match [regex]::Escape($header))) {
                Add-Content -Path $logFile -Value "`r`n$header"
            }
            Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
        }
    }
    
    # Helper function: Retrieve all user SIDs and their NTUSER hive paths
    function Get-UserHives {
        [CmdletBinding()]
        param(
            [ValidateSet('AzureAD','DomainAndLocal','All')][string]$Type = 'All'
        )
        $patterns = switch ($Type) {
            'AzureAD'        { 'S-1-12-1-(\d+-?){4}$' }
            'DomainAndLocal' { 'S-1-5-21-(\d+-?){4}$' }
            'All'            { 'S-1-12-1-(\d+-?){4}$','S-1-5-21-(\d+-?){4}$' }
        }
        $hives = foreach ($pat in $patterns) {
            Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
            Where-Object { $_.PSChildName -match $pat } |
            ForEach-Object {
                [PSCustomObject]@{
                    SID      = $_.PSChildName
                    HivePath = Join-Path $_.ProfileImagePath 'NTUSER.DAT'
                }
            }
        }
        if ($IncludeDefaultHive) {
            $defaultPath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
            if (Test-Path $defaultPath) {
                $hives += [PSCustomObject]@{
                    SID      = 'DefaultUser'
                    HivePath = $defaultPath
                }
            }
            else {
                Write-Log "WARNING" "Default hive not found at $defaultPath"
            }
        }
        return $hives
    }
    
    # Helper function: Set or create a registry value, retrying until correct
    function RegistryShouldBe {
        param(
            [Parameter(Mandatory)][string]$KeyPath,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$Value,
            [ValidateSet('DWord','String','ExpandString','MultiString','Binary','QWord')][string]$Type = 'DWord'
        )
        if (-not (Test-Path $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
        $attempt = 0
        do {
            $attempt++
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            if ($current -ne $Value) {
                if ($null -eq $current) {
                    Write-Log "VERBOSE" "Creating $KeyPath\$Name = $Value"
                    New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                }
                else {
                    Write-Log "VERBOSE" "Updating $KeyPath\$Name from $current to $Value"
                    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
                }
            }
            Start-Sleep -Milliseconds 200
        }
        while (((Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue).$Name -ne $Value) -and ($attempt -lt 5))
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($final -eq $Value) {
            Write-Log "VERBOSE" "$KeyPath\$Name confirmed $Value"
        }
        else {
            Write-Log "WARNING" "$KeyPath\$Name failed to set to $Value"
        }
    }
    
    # Helper function: Apply Explorer settings to a registry root
    function Apply-ExplorerSettings {
        param(
            [Parameter(Mandatory)][string]$RegRoot
        )
        $pathMap = @{
            'ExplorerAdvanced' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        }
        $ExplorerSettings = @{
            'HideFileExtension' = @{
                'HideFileExt' = @{ Path='ExplorerAdvanced'; Label='Hide file extensions'; ValueLogic='EnableTo1' }
            }
            'UseCompactMode' = @{
                'UseCompactMode' = @{ Path='ExplorerAdvanced'; Label='Use compact mode'; ValueLogic='EnableTo1' }
            }
            'StartShowOnUpgrade' = @{
                'StartShowOnUpgrade' = @{ Path='ExplorerAdvanced'; Label='Show Start on upgrade'; ValueLogic='EnableTo1' }
            }
        }
        foreach ($setting in $ExplorerSettings.Keys) {
            $paramValue = Get-Variable -Name $setting -ValueOnly
            $value = if ($paramValue -eq 'Enable') { '1' } else { '0' }
            $keyName = $ExplorerSettings[$setting].Keys[0]
            $info = $ExplorerSettings[$setting][$keyName]
            $fullPath = "Registry::$RegRoot\$($pathMap[$info.Path])"
            RegistryShouldBe -KeyPath $fullPath -Name $keyName -Value $value
        }
    }
    
    # Helper function: Get current user SID
    function Get-CurrentUserSID {
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            return $currentUser.User.Value
        }
        catch {
            return $null
        }
    }
}

# ===========================================
# PROCESS Block: Apply Settings
# ===========================================
process {
    if (-not (Test-IsElevated)) {
        Write-Log "ERROR" "Administrator privileges are required."
        exit 1
    }
    
    # Apply machine-wide settings
    Write-Log "INFO" "Applying machine-wide Explorer settings"
    Apply-ExplorerSettings -RegRoot 'HKEY_LOCAL_MACHINE'
    
    if (Test-IsSystem) {
        # Apply to all user hives
        $hives = Get-UserHives
        $loaded = @()
        $currentUserSID = Get-CurrentUserSID
        foreach ($hive in $hives) {
            $sid = $hive.SID
            $isCurrentUser = ($sid -eq $currentUserSID)
            if ($isCurrentUser) {
                try {
                    Write-Log "INFO" "Stopping Explorer for current user to safely apply settings..."
                    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
                }
                catch {
                    Write-Log "WARNING" "Could not stop Explorer: $_"
                }
            }
            $regRoot = "HKEY_USERS\$sid"
            if (-not (Test-Path "Registry::$regRoot")) {
                Write-Log "VERBOSE" "Loading hive from $($hive.HivePath)"
                reg.exe LOAD "HKEY_USERS\$sid" $hive.HivePath | Out-Null
                $loaded += $sid
            }
            Apply-ExplorerSettings -RegRoot $regRoot
            if ($isCurrentUser -and $RestartExplorer) {
                Write-Log "INFO" "Restarting Explorer for current user after safe update..."
                Start-Process explorer.exe | Out-Null
            }
        }
        # Unload loaded hives
        foreach ($sid in $loaded) {
            Start-Sleep -Milliseconds 200
            reg.exe UNLOAD "HKEY_USERS\$sid" | Out-Null
            Write-Log "VERBOSE" "Unloaded hive for $sid"
        }
    }
    else {
        # Apply only to current user
        Write-Log "INFO" "Applying settings for current user only"
        $regRoot = "HKEY_CURRENT_USER"
        try {
            Write-Log "INFO" "Stopping Explorer for current user to safely apply settings..."
            Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        }
        catch {
            Write-Log "WARNING" "Could not stop Explorer: $_"
        }
        Apply-ExplorerSettings -RegRoot $regRoot
        if ($RestartExplorer) {
            Write-Log "INFO" "Restarting Explorer after safe update..."
            Start-Process explorer.exe | Out-Null
        }
    }
}

# ===========================================
# END Block: Completion
# ===========================================
end {
    Write-Log "INFO" "Explorer settings have been applied."
}