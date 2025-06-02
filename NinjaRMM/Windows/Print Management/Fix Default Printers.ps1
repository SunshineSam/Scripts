#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 04-19-2025
#>

#Requires -Version 5.1

<#
.SYNOPSIS
    Purge and reprovision the built-in Fax or Microsoft Print to PDF queue.

.DESCRIPTION
    - Select via Ninja Script Variable dropdown - env:printerType ("Fax" or "Microsoft Print to PDF")  
    - Stops the Print Spooler  
    - Deletes any existing printer (and Fax port)  
    - Enables or installs the correct driver/feature  
    - Restarts the Spooler  
    - (Re)creates the port if Fax  
    - Adds the queue via PrintUIEntry  
    - Verifies the queue exists

.PARAMETER PrinterType
    "Fax" or "Microsoft Print to PDF" (set via env:printerType).

.NOTES
    - Must run elevated (Administrator or SYSTEM)
    - Uses built-in INF files (`msfax.inf`, `prnms009.inf`)
#>

[CmdletBinding()]
param(
    # Dropdown option                                                 Ninja Variable Resolution                      Fallbaack
    [ValidateSet('Fax','Microsoft Print to PDF')][string]$PrinterType = $(if ($env:printerType) { $env:printerType } else { "Not Set!" }) # Ninja Script Variable; Dropdown - Fallback will cause failure

    # Individual Switch        Ninja Variable Resolution                                                  Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }), # Ninja Script Variable; Checkbox
)

# ===========================================
# BEGIN Block: Elevation check & set variables
# ===========================================
begin {
    # Elevation check
    $me = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] Must run elevated (Admin or SYSTEM)."
        exit 1
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
            
            $MountPoint = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $driveLetter = ($MountPoint -replace '[^A-Za-z]', '').ToUpper()
            $logDir = "$driveLetter`:\Logs\Print Management"
            $logFile = Join-Path $logDir "DefaultPrinterFix.log"
            
            # Sublogic: Create the log directory if it doesn’t exist
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
    
    # Switch to handle dropdown selection
    switch ($PrinterType) {
        'Fax' {
            $PrinterName = 'Fax'
            $PortName    = 'FAX:'
            $DriverName  = 'Microsoft Shared Fax Driver'
            $InfPath     = "$env:windir\INF\msfax.inf"
            $NeedsPort   = $true
        }
        'Microsoft Print to PDF' {
            $PrinterName = 'Microsoft Print to PDF'
            $PortName    = 'PORTPROMPT:'
            $DriverName  = 'Microsoft Print To PDF'
            $InfPath     = "$env:windir\INF\prnms009.inf"        # PDF driver INF - https://techpress.net/fix-microsoft-print-to-pdf-missing-in-windows-10-11
            $NeedsPort   = $false
            
            Write-Log "INFO" "Enabling Print to PDF feature..."
            Enable-WindowsOptionalFeature -Online `
              -FeatureName Printing-PrintToPDFServices-Features -All -NoRestart | Out-Null          # enable via DISM/PowerShell - https://smbtothecloud.com/fixing-the-microsoft-print-to-pdf-printer-with-intune)
        }
    }
    
    Write-Host "=== Reprovisioning '$PrinterName' ===`n"
}

# ===========================================
# PROCESS Block: stop spooler, remove, install, add, verify
# ===========================================
process {
    # 1) Stop Spooler
    Write-Log "INFO" "Stopping Print Spooler"
    Stop-Service Spooler -Force -ErrorAction Stop
    
    # 2) Delete existing printer
    Write-Log "INFO" "Removing existing printer '$PrinterName'"
    rundll32 printui.dll,PrintUIEntry /dl /n "`"$PrinterName`"" /q
    
    # 3) Delete Fax port for recreation
    if ($NeedsPort) {
        Write-Log "INFO" "Removing existing port '$PortName'"
        Remove-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
    }
    
    # 4) Install driver if missing
    if (-not (Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue)) {
        Write-Log "INFO" "Installing driver '$DriverName' from $InfPath"
        try {
            Add-PrinterDriver -Name $DriverName -InfPath $InfPath -ErrorAction Stop
        }
        catch {
            Write-Log "WARNING" "Add-PrinterDriver failed; falling back to PrintUIEntry"
            rundll32 printui.dll,PrintUIEntry /ia /m "`"$DriverName`"" /f "`"$InfPath`""  2>$null
        }
    }
    else {
        Write-Log "WARNING" "Driver '$DriverName' already installed."
    }
    
    # 5) Restart Spooler for port/printer creation
    Write-Log "INFO" "Starting Print Spooler"
    Start-Service Spooler -ErrorAction Stop
    
    # 6) Create Fax port if needed
    if ($NeedsPort) {
        Write-Log "INFO" "Creating port '$PortName'"
        Add-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
    }
    
    # 7) Add the printer via PrintUIEntry
    Write-Log "INFO" "Adding printer '$PrinterName' on port '$PortName'"
    rundll32 printui.dll,PrintUIEntry `
        /if `
        /b "`"$PrinterName`"" `
        /f "`"$InfPath`"" `
        /r "`"$PortName`"" `
        /m "`"$DriverName`"" 2>$null
        
    # 8) Verify it exists
    Write-Host "`nVerifying '$PrinterName' exists"
    if (Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue) {
        Write-Log "SUCCESS" " '$PrinterName' reprovisioned."
        exit 0
    }
    else {
        Write-Log "ERROR" "'$PrinterName' not found after reprovision."
        exit 1
    }
}

# ===========================================
# END Block: Finalization
# ===========================================
end {
    
}