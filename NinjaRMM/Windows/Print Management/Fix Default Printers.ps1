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
    - Select via env:printerType ("Fax" or "Microsoft Print to PDF")  
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
    [ValidateSet('Fax','Microsoft Print to PDF')]
    [string]$PrinterType = $(if ($env:printerType) { $env:printerType } else { "Not Set!" })
)

# ===========================================
# BEGIN Block: Elevation check & set variables
# ===========================================
begin {
    # Elevation
    $me = [Security.Principal.WindowsPrincipal]::new(
             [Security.Principal.WindowsIdentity]::GetCurrent()
          )
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "[Error] Must run elevated (Admin or SYSTEM)."
        exit 1
    }
    
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
            
            Write-Host "Enabling Print to PDF feature..."
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
    Write-Host "Stopping Print Spooler"
    Stop-Service Spooler -Force -ErrorAction Stop
    
    # 2) Delete existing printer
    Write-Host "Removing existing printer '$PrinterName'"
    rundll32 printui.dll,PrintUIEntry /dl /n "`"$PrinterName`"" /q
    
    # 3) Delete Fax port for recreation
    if ($NeedsPort) {
        Write-Host "Removing existing port '$PortName'"
        Remove-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
    }
    
    # 4) Install driver if missing
    if (-not (Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue)) {
        Write-Host "Installing driver '$DriverName' from $InfPath"
        try {
            Add-PrinterDriver -Name $DriverName -InfPath $InfPath -ErrorAction Stop
        }
        catch {
            Write-Warning "  Add-PrinterDriver failed; falling back to PrintUIEntry"
            rundll32 printui.dll,PrintUIEntry /ia /m "`"$DriverName`"" /f "`"$InfPath`""  2>$null
        }
    }
    else {
        Write-Host "Driver '$DriverName' already installed."
    }
    
    # 5) Restart Spooler for port/printer creation
    Write-Host "Starting Print Spooler"
    Start-Service Spooler -ErrorAction Stop
    
    # 6) Create Fax port if needed
    if ($NeedsPort) {
        Write-Host "Creating port '$PortName'"
        Add-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
    }
    
    # 7) Add the printer via PrintUIEntry
    Write-Host "Adding printer '$PrinterName' on port '$PortName'"
    rundll32 printui.dll,PrintUIEntry `
        /if `
        /b "`"$PrinterName`"" `
        /f "`"$InfPath`"" `
        /r "`"$PortName`"" `
        /m "`"$DriverName`"" 2>$null
        
    # 8) Verify it exists
    Write-Host "`nVerifying '$PrinterName' exists"
    if (Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue) {
        Write-Host "[Success] '$PrinterName' reprovisioned."
        exit 0
    }
    else {
        Write-Error "[Error] '$PrinterName' not found after reprovision."
        exit 1
    }
}

# ===========================================
# END Block: Finalization
# ===========================================
end {
  
}