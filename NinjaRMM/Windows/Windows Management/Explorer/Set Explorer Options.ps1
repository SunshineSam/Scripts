#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 04-16-2025
#>

<#
.SYNOPSIS
    Configures various Windows Explorer advanced options via ValidateSet Actions.

.DESCRIPTION
    This script uses four Action parameters (each with "Enable"/"Disable") to control:
      - HideFileExtension    -> Show or hide file extensions (Enable = hide, Disable = show)  
      - UseCompactMode       -> Enable or disable compact mode in Explorer  
      - StartShowOnUpgrade   -> Show or hide Start layout after an upgrade  
      - RestartExplorer      -> Restart or leave Explorer running  

    Each setting is applied machine-wide (HKLM) and per-user (HKCU or loaded hives).
    Registry writes have full try/catch error handling and verbose comments.

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
    ValidateSet Enable|Disable.  
      Enable  = restart Explorer at end  
      Disable = do not restart
#>

# Relying on Auto Parameter Resolution with Ninja
[CmdletBinding()]
param(
    [ValidateSet("Enable","Disable")][string]$HideFileExtension = $(if ($env:hideFileExtension) { $env:hideFileExtension } else { "Enable" }),
    [ValidateSet("Enable","Disable")][string]$UseCompactMode = $(if ($env:useCompactMode) { $env:useCompactMode } else { "Disable" }),
    # Relavent
    [ValidateSet("Enable","Disable")][string]$StartShowOnUpgrade = $(if ($env:startShowOnUpgrade) { $env:startShowOnUpgrade } else { "Enable" }),
    [Switch]$RestartExplorer = $(if ($env:restartExplorer) { [Convert]::ToBoolean($env:restartExplorer) } else { $true })
)

# ===========================================
# BEGIN Block: Helper Functions & Validation
# ===========================================
begin {
    
    # Convert variable strings to integer values
    # HideFileExtension: Enable -> 1 (hide), Disable -> 0 (show)
    [int]$hideExtValue      = if ($HideFileExtension -eq 'Enable') { 1 } else { 0 }
    # UseCompactMode: Enable -> 1, Disable -> 0
    [int]$compactModeValue  = if ($UseCompactMode   -eq 'Enable') { 1 } else { 0 }
    # StartShowOnUpgrade: Enable -> 1, Disable -> 0
    [int]$startUpgradeValue = if ($StartShowOnUpgrade-eq 'Enable') { 1 } else { 0 }
    
    # Ensure script runs as Admin 
    function Test-IsElevated {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id))
               .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    if (-not (Test-IsElevated)) {
        Write-Error "[Error] Must run as Administrator."
        exit 1
    }

    # Detect SYSTEM account
    function Test-IsSystem {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY\*" -or $id.IsSystem
    }

    # Helper function
    function Get-UserHives {
        <#
            Get-UserHives:
            - Enumerates user SIDs and hive paths
            - Filters by SID pattern (local/domain/AzureAD)
            - Optionally includes Default user hive
        #>
        param(
            [ValidateSet('All','DomainAndLocal','AzureAD')]
            [string]$Type = 'All',
            [switch]$IncludeDefault
        )
        # Determine SID patterns
        $patterns = switch ($Type) {
            'AzureAD'        { 'S-1-12-1-(\d+-?){4}$' }
            'DomainAndLocal' { 'S-1-5-21-(\d+-?){4}$' }
            'All'            { 'S-1-12-1-(\d+-?){4}$'; 'S-1-5-21-(\d+-?){4}$' }
        }
        # Collect profiles
        $list = foreach ($pat in $patterns) {
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
            Where-Object PSChildName -match $pat |
            Select-Object @{n='SID';e={$_.PSChildName}},
                          @{n='Hive';e={"$($_.ProfileImagePath)\NTUSER.DAT"}},
                          @{n='User';e={ Split-Path $_.ProfileImagePath -Leaf }}
        }
        # Include Default profile if requested
        if ($IncludeDefault) {
            $list += [pscustomobject]@{
                SID  = 'Default'
                Hive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                User = 'Default'
            }
        }
        return $list
    }
    
    # Helper function
    function Get-CurrentUserSID {
        <#
            Get-CurrentUserSID:
            - Gets the current SID for exploerer handling
        #>
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            return $currentUser.User.Value
        }
        catch {
            return $null
        }
    }

    function Set-RegKey {
        <#
            Set-RegKey:
            - Creates registry path if missing
            - Sets or updates a DWORD value
            - Outputs what changed
        #>
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][int]$Value
        )
        try {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
                Write-Host "[Info] Created registry key path: $Path"
            }
            $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            if ($current -ne $Value) {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
                Write-Host "[Info] $Path\$Name changed from '$current' to '$Value'"
            }
            else {
                Write-Host "[Info] $Path\$Name already set to '$Value'"
            }
        }
        catch {
            #Write-Warning "[Warning] Failed setting $Path\$Name: $_"
            Write-Warning ("[Warning] Failed setting {0}\{1}: {2}" -f $Path, $Name, $_)
        }
    }

    # Machine-wide registry base
    $machinePath = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    
    # Current User SID
    $currentUserSID = Get-CurrentUserSID
}

# ===========================================
# PROCESS Block: Apply Settings
# ===========================================
process {
    # Machine Wide Settings
    Write-Host "`n=== Machine-Wide Explorer Settings ==="
    # Hide or show file extensions
    Set-RegKey -Path $machinePath -Name 'HideFileExt'        -Value $hideExtValue
    # Enable/disable compact mode
    Set-RegKey -Path $machinePath -Name 'UseCompactMode'    -Value $compactModeValue
    # Show/hide Start on upgrade
    Set-RegKey -Path $machinePath -Name 'StartShowOnUpgrade' -Value $startUpgradeValue

    # Per-User settings
    Write-Host "`n=== Per-User Explorer Settings ==="
    if (Test-IsSystem) {
        # SYSTEM context: apply to all user hives
        $loaded = @()
        $profiles = Get-UserHives -Type All -IncludeDefault
        foreach ($p in $profiles) {
            $sid  = $p.SID
            $hive = $p.Hive
            
            # Load hive if not already loaded
            if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
                reg.exe LOAD "HKU\$sid" "`"$hive`"" | Out-Null
                $loaded += $sid
            }
            # Inside the foreach loop over $profiles
            $userPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Write-Host "[Info] Applying for user '$($p.User)' (SID $sid)"
            
            # Current user check
            $isCurrentUser = $sid -eq $currentUserSID
            if ($isCurrentUser) {
                try {
                    Write-Host "[Info] Stopping Explorer for current user to safely apply settings..."
                    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
                }
                catch {
                    Write-Warning "[Warning] Could not stop Explorer: $_"
                }
            }
            # Set Reg Keys
            Set-RegKey -Path $userPath -Name 'HideFileExt'        -Value $hideExtValue
            Set-RegKey -Path $userPath -Name 'UseCompactMode'     -Value $compactModeValue
            Set-RegKey -Path $userPath -Name 'StartShowOnUpgrade' -Value $startUpgradeValue
            
            # Restart explorer only if current user
            if ($isCurrentUser -and $RestartExplorer) {
                Write-Host "[Info] Restarting Explorer for current user after safe update..."
                Start-Process explorer.exe | Out-Null
            }
            elseif (-not $isCurrentUser -and $RestartExplorer) {
                Write-Host "[Info] Restart skipped for SID $sid — not the current user."
            }
        }
        # Unload any hives we loaded
        foreach ($sid in $loaded) {
            reg.exe UNLOAD "HKU\$sid" | Out-Null
        }
    }
    
    # Not in System Auth
    else {
        # Get current user SID for comparison and future use
        $currentUserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Write-Host "[Info] Current user SID: $currentUserSID"

        # Construct path
        $userPath = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Write-Host "[Info] Applying for current user"

        # End Explorer prior to setting Reg Keys
        try {
            Write-Host "[Info] Stopping Explorer for current user to safely apply settings..."
            Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        }
        catch {
            Write-Warning "[Warning] Could not stop Explorer: $_"
        }

        # Set Reg Keys
        Set-RegKey -Path $userPath -Name 'HideFileExt'         -Value $hideExtValue
        Set-RegKey -Path $userPath -Name 'UseCompactMode'      -Value $compactModeValue
        Set-RegKey -Path $userPath -Name 'StartShowOnUpgrade'  -Value $startUpgradeValue

        # Start Explorer after setting Reg Keys (if Restart requested)
        if ($RestartExplorer) {
            Write-Host "[Info] Restarting Explorer after safe update..."
            Start-Process explorer.exe | Out-Null
        }
        else {
            Write-Host "[Info] Restart skipped — changes will take effect after next login or manual relaunch."
        }
    }
}

# ===========================================
# END Block: Completion
# ===========================================
end {
    Write-Host "`nAll requested Explorer settings have been applied."
}