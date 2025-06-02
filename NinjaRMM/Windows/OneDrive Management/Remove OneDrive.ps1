#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 04-17-2025
    
    Notes:
    04-17-2025: Improved per-version detection for Program Files uninstall
#>

<#
.SYNOPSIS
    Removes and disables OneDrive integration based on provided switches.

.DESCRIPTION
    This script can:
      - Terminate OneDrive.
      - Uninstall from:
          - System32/SysWOW64            (-SystemUninstall)
          - Program Files MSI install    (-PreInstalledUninstall)
          - Per-user AppData             (-UserProfileUninstall)
      - Remove leftover folders (if any uninstall ran).
      - Optionally apply GPO to disable OneDrive.
      - Optionally remove from Explorer sidebar.
      - Optionally delete scheduled OneDrive tasks.
      - Optionally remove new-user run-hook.
      - Optionally restart Explorer at end.

.PARAMETER SystemUninstall
    Switch. If set, runs the "built-in" uninstaller from System32 & SysWOW64.

.PARAMETER PreInstalledUninstall
    Switch. If set, runs the MSI-style uninstaller under Program Files directories.

.PARAMETER UserProfileUninstall
    Switch. If set, uninstalls the per-user AppData copy of OneDrive.

.PARAMETER ApplyGPO
    Switch. If set, applies Group Policy to disable OneDrive file sync.

.PARAMETER RemoveFromExplorerSidebar
    Switch. If set, removes OneDrive from the Explorer sidebar.

.PARAMETER RemoveScheduledRun
    Switch. If set, unregisters any scheduled OneDrive tasks.

.PARAMETER RemoveRunHook
    Switch. If set, deletes the "run" entry for OneDrive in the Default user hive.

.PARAMETER RestartExplorer
    Switch. If set, restarts the Explorer process at the end.
#>

[CmdletBinding()]
param(
    # Independent switches
    [Switch]$SystemUninstall           = $(if ($env:systemUninstall)           { [Convert]::ToBoolean($env:systemUninstall) }           else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$PreInstalledUninstall     = $(if ($env:preinstalledRemoval)       { [Convert]::ToBoolean($env:preinstalledRemoval) }       else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$UserProfileUninstall      = $(if ($env:userProfileUninstall)      { [Convert]::ToBoolean($env:userProfileUninstall) }      else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$ApplyGPO                  = $(if ($env:applyGPO)                  { [Convert]::ToBoolean($env:applyGPO) }                  else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$RemoveFromExplorerSidebar = $(if ($env:removeFromExplorerSidebar) { [Convert]::ToBoolean($env:removeFromExplorerSidebar) } else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$RemoveScheduledRun        = $(if ($env:removeScheduledRun)        { [Convert]::ToBoolean($env:removeScheduledRun) }        else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$RemoveRunHook             = $(if ($env:removeRunHook)             { [Convert]::ToBoolean($env:removeRunHook) }             else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$RestartExplorer           = $(if ($env:restartExplorer)           { [Convert]::ToBoolean($env:restartExplorer) }           else { $false })  # Ninja Script Variable; Checkbox
)

# ===========================================
# BEGIN Block: Initialization & Helper Functions
# ===========================================
begin {
    Write-Output "`n=== Starting OneDrive Removal ==="
    Write-Output ("SystemUninstall:             {0}" -f $SystemUninstall)
    Write-Output ("PreInstalledUninstall:       {0}" -f $PreInstalledUninstall)
    Write-Output ("UserProfileUninstall:        {0}" -f $UserProfileUninstall)
    Write-Output ("ApplyGPO:                    {0}" -f $ApplyGPO)
    Write-Output ("RemoveFromExplorerSidebar:   {0}" -f $RemoveFromExplorerSidebar)
    Write-Output ("RemoveScheduledRun:          {0}" -f $RemoveScheduledRun)
    Write-Output ("RemoveRunHook:               {0}" -f $RemoveRunHook)
    Write-Output ("RestartExplorer:             {0}`n" -f $RestartExplorer)
    
    function New-FolderForced {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param([string]$Path)
        process {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
                Write-Output "[INFO] Created folder: $Path"
            }
        }
    }
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like 'NT AUTHORITY\*' -or $id.IsSystem
    }
    function Get-OneDriveSetupInFolder {
        param([string]$BasePath)
        if (-not (Test-Path $BasePath)) {
            return $null
        }
        return Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
            $candidate = Join-Path $_.FullName 'OneDriveSetup.exe'
            if (Test-Path $candidate) {
                  return $candidate
            }
        }
    }
}

# ===========================================
# PROCESS Block: OneDrive Uninstall & Cleanup
# ===========================================
process {
    try {
        ### 1) End One Drive for Uninstall
        try {
            taskkill.exe /F /IM OneDrive.exe 2>$null
            Write-Output "[INFO] Terminated OneDrive.exe"
        }
        catch {
            Write-Output ("[WARNING] Could not terminate OneDrive.exe: {0}" -f $_)
        }
        
        ### 2) System32/SysWOW64 Uninstall ###
        if ($SystemUninstall) {
            Write-Output "`n=== System ninstall: running built-in uninstallers ==="
            $paths = @(
                Join-Path -Path $env:SystemRoot -ChildPath 'System32\OneDriveSetup.exe'
                Join-Path -Path $env:SystemRoot -ChildPath 'SysWOW64\OneDriveSetup.exe'
            )
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    try {
                        & $p /uninstall
                        Write-Output ("[SUCCESS] Uninstalled via {0}" -f $p)
                    }
                    catch {
                        Write-Output ("[WARNING] Failed uninstall with {0}: {1}" -f $p, $_)
                    }
                }
                else {
                    Write-Output ("[ERROR] Not found: {0}" -f $p)
                }
            }
        }
        else {
            Write-Output "[WARNING] SystemUninstall not set; skipping.`n"
        }
        
        ### 3) Program Files MSI Uninstall ###
        if ($PreInstalledUninstall) {
            Write-Output "`n=== PreInstalled Removal: MSI uninstall under Program Files ==="
            # Build the two candidate base directories explicitly:
            $pf64 = "${env:ProgramFiles}\Microsoft OneDrive"
            $pf86 = "${env:ProgramFiles(x86)}\Microsoft OneDrive"
            
            foreach ($root in @($pf64, $pf86)) {
                $exe = Get-OneDriveSetupInFolder -BasePath $root
                if ($exe) {
                    try {
                        & $exe /uninstall
                        Write-Output ("[SUCCESS] Uninstalled via MSI installer: {0}" -f $exe)
                    }
                    catch {
                        Write-Output ("[WARNING] Failed to uninstall via {0}: {1}" -f $exe, $_)
                    }
                }
                else {
                    Write-Output ("[WARNING] No OneDriveSetup.exe found under {0}" -f $root)
                }
            }
        }
        else {
            Write-Output "[INFO] PreInstalled Removal not set; skipping."
        }
        
        ### 4) Per-User AppData Uninstall ###
        if ($UserProfileUninstall) {
            Write-Output "`n=== User Profile Uninstall: per-user AppData uninstall ==="
            if (Test-IsSystem) {
                $cs = Get-CimInstance Win32_ComputerSystem
                $user = $cs.UserName.Split('\')[-1]
                $localApp = "C:\Users\$user\AppData\Local"
                Write-Output ("[INFO] Detected interactive user: {0}" -f $user)
            }
            else {
                $localApp = $env:LocalAppData
                Write-Output ("[INFO] Running as user: {0}" -f $env:USERNAME)
            }
            $userExe = Join-Path $localApp 'Microsoft\OneDrive\OneDriveSetup.exe'
            if (Test-Path $userExe) {
                try {
                    & $userExe /uninstall
                    Write-Output ("[SUCCESS] Uninstalled via {0}" -f $userExe)
                }
                catch {
                    Write-Output ("[ERROR] Failed uninstall with {0}: {1}" -f $userExe, $_)
                }
            }
            else {
                Write-Output ("[ERROR] Not found: {0}" -f $userExe)
            }
        }
        else {
            Write-Output "[INFO] User Profile Uninstall not set; skipping."
        }
        
        ### 5) Leftover Cleanup (three phase granular per-switch) ###
        
        ### 5b) PreInstalled-specific cleanup (stop explorer, wait for uninstall, delete folder) ###
        if ($PreInstalledUninstall) {
            Write-Output "`n=== PreInstalled cleanup: delete Program Files OneDrive folder ==="
            
            # 1) Stop UserOOBEBroker and Explorer to release any file locks (e.g. FileSyncShell64.dll)
            try {
                Get-Process UserOOBEBroker -ErrorAction SilentlyContinue |
                  Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Output "[INFO] Stopping UserOOBEBroker to release file locks… "
            }
            catch {
                Write-Output "[INFO] No UserOOBEBroker processes(s) to terminate"
            }
            
            Write-Output "[INFO] Stopping Explorer to release file locks…"
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            
            # 2) Wait for OneDriveSetup.exe to exit (up to 3 tries, 5s apart)
            $maxTries = 3
            for ($i = 1; $i -le $maxTries; $i++) {
                if (-not (Get-Process -Name OneDriveSetup -ErrorAction SilentlyContinue)) {
                    Write-Output ("[SUCCESS] OneDriveSetup uninstall process finished on (attempt {0}/{1})…" -f $i, $maxTries)
                    break
                }
                Write-Output ("[INFO] OneDriveSetup uninstall process is finishing up. Waiting 5 seconds (attempt {0}/{1})…" -f $i, $maxTries)
                Start-Sleep -Seconds 5
            }
            if (Get-Process -Name OneDriveSetup -ErrorAction SilentlyContinue) {
                Write-Output "[WARNING] OneDriveSetup.exe is still running after waiting. Proceeding with folder deletion."
            }
            
            # 3) Now delete the entire 'Microsoft OneDrive' folder under both ProgramFiles paths
            foreach ($root in @(
                "${env:ProgramFiles}\Microsoft OneDrive",
                "${env:ProgramFiles(x86)}\Microsoft OneDrive"
            )) {
                if (Test-Path $root) {
                    try {
                        Remove-Item -Path $root -Recurse -Force -ErrorAction Stop
                        Write-Output ("[SUCCESS] Deleted Program Files folder: {0}" -f $root)
                    }
                    catch {
                        Write-Output ("[ERROR] Failed deleting {0}: {1}" -f $root, $_)
                    }
                }
                else {
                    Write-Output ("[WARNING] Not found: {0}" -f $root)
                }
            }
            Start-Process explorer -ErrorAction SilentlyContinue
        }
        
        ### 5c) Per-user AppData/profile cleanup for ALL users ###
        if ($UserProfileUninstall) {
            Write-Output "`n=== Per-user AppData/profile cleanup for every user ==="
            $skip = 'All Users','Default','Default User','Public','desktop.ini'
            Get-ChildItem -Path "$($env:SystemDrive)\Users" -Directory |
              Where-Object { $skip -notcontains $_.Name } |
              ForEach-Object {
                $u              = $_.Name
                $localAppDrive  = Join-Path $_.FullName 'AppData\Local\Microsoft\OneDrive'
                $topLevelDrive  = Join-Path $_.FullName 'OneDrive'
                
                # AppData\Local\Microsoft\OneDrive
                if (Test-Path $localAppDrive) {
                    try {
                        Remove-Item -Path $localAppDrive -Recurse -Force -ErrorAction Stop
                        Write-Output ("[SUCCESS] Removed AppData leftover for {0}" -f $u)
                    }
                    catch {
                        Write-Output ("[ERROR] Failed removing AppData for {0}: {1}" -f $u, $_)
                    }
                }
                
                # Top-level "OneDrive" if empty
                if (Test-Path $topLevelDrive) {
                    $count = (Get-ChildItem -Path $topLevelDrive -Recurse -Force | Measure-Object).Count
                    if ($count -eq 0) {
                        try {
                            Remove-Item -Path $topLevelDrive -Recurse -Force -ErrorAction Stop
                            Write-Output ("[SUCCESS] Removed empty profile folder for {0}" -f $u)
                        }
                        catch {
                            Write-Output ("[ERROR] Failed removing profile folder for {0}: {1}" -f $u, $_)
                        }
                    }
                }
              }
        }
        
        ### 6) Apply GPO ###
        if ($ApplyGPO) {
            Write-Output "`n=== Applying Group Policy to disable OneDrive ==="
            try {
                New-FolderForced -Path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive'
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive' `
                                 -Name DisableFileSyncNGSC -Value 1
                Write-Output "[SUCCESS] GPO applied"
            }
            catch {
                Write-Output "[ERROR] Failed to apply GPO: $_"
            }
        }
        else {
            Write-Output "[INFO] ApplyGPO not set; skipping."
        }
        
        ### 7) Remove from Explorer Sidebar ###
        if ($RemoveFromExplorerSidebar) {
            Write-Output "`n=== Removing from Explorer sidebar ==="
            
            # Directly use the Registry: provider to avoid PSDrive issues
            $clsid = 'Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
            if (Test-Path $clsid) {
                try {
                    Set-ItemProperty -Path $clsid `
                                     -Name 'System.IsPinnedToNameSpaceTree' `
                                     -Value 0 `
                                     -ErrorAction Stop
                    Write-Output "[SUCCESS] Un-pinned sidebar HKEY_CLASSES_ROOT entry"
                    
                    # also handle the Wow6432Node hive if present
                    $clsid32 = $clsid -replace 'HKEY_CLASSES_ROOT','HKEY_CLASSES_ROOT\Wow6432Node'
                    if (Test-Path $clsid32) {
                        Set-ItemProperty -Path $clsid32 `
                                         -Name 'System.IsPinnedToNameSpaceTree' `
                                         -Value 0 `
                                         -ErrorAction Stop
                        Write-Output "[SUCCESS] Un-pinned sidebar WoW6432Node entry"
                    }
                }
                catch {
                    Write-Output ("[ERROR] Sidebar removal failed: {0}" -f $_)
                }
            }
            else {
                Write-Output "[INFO] Sidebar entry not found; skipping."
            }
        }
        else {
            Write-Output "[INFO] RemoveFromExplorerSidebar not set; skipping."
        }
        
        ### 8) Remove Run Hook ###
        if ($RemoveRunHook) {
            Write-Output "`n=== Removing new-user run hook ==="
            try {
                reg load HKU\Default 'C:\Users\Default\NTUSER.DAT' 2>$null
                reg delete 'HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                           /v OneDriveSetup /f 2>$null
                reg unload HKU\Default 2>$null
                Write-Output "[SUCCESS] Run hook removed"
            }
            catch {
                Write-Warning "[ERROR] Failed to remove run hook: $_"
            }
        }
        else {
            Write-Output "[INFO] RemoveRunHook not set; skipping."
        }
        
        ### 9) Remove Scheduled Task ###
        if ($RemoveScheduledRun) {
            Write-Output "`n=== Removing scheduled OneDrive tasks ==="
            try {
                Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' `
                  -ErrorAction SilentlyContinue |
                  Unregister-ScheduledTask -Confirm:$false
                Write-Output "[SUCCESS] Scheduled tasks removed"
            }
            catch {
                Write-Warning "[ERROR] Failed to remove scheduled tasks: $_"
            }
        }
        else {
            Write-Output "[INFO] RemoveScheduledRun not set; skipping."
        }
        
        ### 10) Restart Explorer ###
        if ($RestartExplorer) {
            Write-Output "`n=== Restarting Explorer ==="
            try {
                Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
                Start-Process explorer -ErrorAction SilentlyContinue
                Write-Output "[SUCCESS] Explorer restarted"
            }
            catch {
                Write-Warning "[ERROR] Failed to restart Explorer: $_"
            }
        }
        else {
            Write-Output "[INFO] RestartExplorer not set; skipping."
        }
    }
    catch {
        Write-Error ("[ERROR] Unhandled error during OneDrive removal: {0}" -f $_)
    }
}

# ===========================================
# END Block: Finalization
# ===========================================
end {
    Write-Output "[FINISHED] OneDrive removal script completed."
}