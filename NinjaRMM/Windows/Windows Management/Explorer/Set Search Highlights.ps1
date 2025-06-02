#Requires -Version 5.1
<#
    === Developed by Sam ===
    Last Edit: 05-16-2025

#>

<#
.SYNOPSIS
    Configures Windows Search Highlights (AllowSearchHighlights) policy and optionally restarts services.

.DESCRIPTION
    Targets the registry value EnableDynamicContentInWSB under:
      HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search

    - When $false: sets EnableDynamicContentInWSB = 0 (disables Search Highlights).  
    - When $true: removes EnableDynamicContentInWSB (enables default behavior).

    You can override the switches via environment variables:
      - $env:enableDynamicContent     (1 = $true, 0 = $false)
      - $env:forceRestartExplorer     (1 = $true, 0 = $false)

.PARAMETER EnableDynamicContent
    $true  -> enable Search Highlights (remove policy override).  
    $false -> disable Search Highlights (set override to 0).

.PARAMETER ForceRestartExplorer
    $true  -> restart Explorer and the Windows Search (WSearch) service.  
    $false -> leave services running.
#>

[CmdletBinding()]
param(
    # Independent switches        Ninja Variable Resolution                                                              Fallback
    [switch]$EnableDynamicContent = $(if ($env:enableDynamicContent) { [Convert]::ToBoolean($env:enableDynamicContent) } else { $false }), # Ninja Script Variable; Checkbox
    [switch]$ForceRestartExplorer = $(if ($env:forceRestartExplorer) { [Convert]::ToBoolean($env:forceRestartExplorer) } else { $false })  # Ninja Script Variable; Checkbox
)

# =========================================
# BEGIN Block: Log effective parameter values
# =========================================
begin {
    Write-Host "[INFO] EnableDynamicContent = $EnableDynamicContent"
    Write-Host "[INFO] ForceRestartExplorer = $ForceRestartExplorer"
}

# =========================================
# PROCESS Block: Apply Search Highlights policy
# =========================================
process {
    # Registry path for Windows Search policy
    $PolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    $ValueName  = 'EnableDynamicContentInWSB'
    
    # Ensure the policy path exists
    if (-not (Test-Path $PolicyPath)) {
        Write-Host "[INFO] Creating registry path: $PolicyPath"
        New-Item -Path $PolicyPath -Force | Out-Null
    }
    
    if (-not $EnableDynamicContent) {
        # DISABLE: set DWORD = 0
        $Desired = 0
        $Current = (Get-ItemProperty -Path $PolicyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
        if ($Current -ne $Desired) {
            Write-Host "[INFO] Disabling Search Highlights: setting $ValueName = 0"
            Set-ItemProperty -Path $PolicyPath -Name $ValueName -Value $Desired -Type DWord
        }
        else {
            Write-Host "[WARNING] No change: $ValueName is already 0"
        }
    }
    else {
        # ENABLE: remove the override
        if (Get-ItemProperty -Path $PolicyPath -Name $ValueName -ErrorAction SilentlyContinue) {
            Write-Host "[INFO] Enabling Search Highlights: removing $ValueName"
            Remove-ItemProperty -Path $PolicyPath -Name $ValueName -ErrorAction Stop
        }
        else {
            Write-Host "[WARNING] No change: $ValueName not present"
        }
    }
    
    # Trigger a Group Policy update
    Write-Host "[INFO] Running gpupdate /force"
    gpupdate /force | Out-Null
    
    # Optionally restart Explorer & Windows Search service
    if ($ForceRestartExplorer) {
        Write-Host "[INFO] Restarting Explorer and WSearch service..."
        # Restart Explorer
        Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        Start-Process explorer.exe
        # Restart WSearch service
        if (Get-Service -Name WSearch -ErrorAction SilentlyContinue) {
            Restart-Service WSearch -Force
        }
        Write-Host "[INFO] Explorer and Windows Search restarted"
    }
}

# =========================================
# END Block: Completion
# =========================================
end {
    Write-Host "[SUCCESS] Windows Search Highlights configuration complete."
}