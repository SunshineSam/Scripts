<#
.SYNOPSIS
    Activate Windows using the BIOS key if necessary.

.DESCRIPTION
    This script checks the current Windows activation status and product key.
    If the current product key is generic or Windows is not activated,
    it attempts to activate Windows using the BIOS key embedded in the system.
    An optional parameter allows forcing the use of the BIOS key regardless
    of the current activation state or key type.

.PARAMETER ForceBIOSKey
    If specified, forces the script to use the BIOS key to activate Windows,
    even if Windows is already activated or the current key is not generic.
#>

param(
    # Individual switches    Ninja Variable Resolution                                                    Fallback
    [switch]$ForceBIOSKey    = $(if ($env:forceBiosKey) { [Convert]::ToBoolean($env:forceBiosKey) }       else { $false }), # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true })   # # Ninja Script Variable; String
)

# ========================
# BEGIN Block: Initialization and Validation
# ========================
begin {
    # Check for administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Administrator privileges required"
        exit 1
    }
    Write-Host "Running as Administrator"
    
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
            $logDir = "$driveLetter`:\Logs\Windows Activation"
            $logFile = Join-Path $logDir "Activation.log"
            
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
    
    # Retrieve the BIOS key from SoftwareLicensingService
    $biosKey = (Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService').OA3xOriginalProductKey
    if (-not $biosKey) {
        Write-Log "ERROR" "No BIOS key found in system firmware. Cannot proceed."
        exit 1
    }
    Write-Log "INFO" "BIOS key retrieved successfully"
    
    # Retrieve current Windows activation status and partial product key
    $licensingProduct = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.Name -match 'windows' -and $_.PartialProductKey }
    if ($licensingProduct) {
        $partialKey = $licensingProduct.PartialProductKey
        $licenseStatus = $licensingProduct.LicenseStatus
        $statusDescription = switch ($licenseStatus) {
            0 { "Unlicensed" }
            1 { "Licensed" }
            2 { "OOBGrace (Out-of-Box Grace period)" }
            3 { "OOTGrace (Out-of-Tolerance Grace period)" }
            4 { "NonGenuineGrace (Non-Genuine Grace period)" }
            5 { "Notification" }
            6 { "ExtendedGrace" }
            default { "Unknown" }
        }
        Write-Log "INFO" "Current Partial Product Key: $partialKey"
        Write-Log "INFO" "Current License Status: $statusDescription"
    }
    else {
        $partialKey = $null
        $licenseStatus = $null
        $statusDescription = "Not Found"
        Write-Log "WARNING" "No product key or activation status found"
    }
    
    # Define list of known generic partial product keys (last 5 characters)
    $genericPartialKeys = @(
        "3V66T", # Windows 10/11 Pro
        "8HVX7", # Windows 10/11 Home
        "2YT43", # Windows 10/11 Enterprise
        "NW6C2"  # Windows 10/11 Education
    )
    Write-Host "Generic partial keys defined for comparison"
}

# ========================
# PROCESS Block: Activation Logic
# ========================
process {
    # Determine if activation with BIOS key is necessary
    if ($ForceBIOSKey -or ($partialKey -and $partialKey -in $genericPartialKeys) -or ($licenseStatus -ne 1)) {
        Write-Log "INFO" "Conditions met for activation:"
        if ($ForceBIOSKey) { Write-Host " - ForceBIOSKey switch specified" }
        if ($partialKey -and $partialKey -in $genericPartialKeys) { Write-Host " - Current key is generic: $partialKey" }
        if ($licenseStatus -ne 1) {
            if ($null -eq $licenseStatus) {
                Write-Log "WARNING" " - No activation status found"
            }
            else {
                Write-Log "WARNING" " - Windows is not activated (Status: $statusDescription)"
            }
        }
        
        # Attempt to install the BIOS key
        Write-Log "INFO" "Installing BIOS product key..."
        & cscript //nologo "$env:windir\system32\slmgr.vbs" /ipk $biosKey | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to install BIOS product key. Exit code: $LASTEXITCODE"
            exit 1
        }
        Write-Log "INFO" "BIOS product key installed successfully"
        
        # Attempt to activate Windows
        Write-Log "INFO" "Activating Windows..."
        & cscript //nologo "$env:windir\system32\slmgr.vbs" /ato
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR" "Failed to activate Windows. Exit code: $LASTEXITCODE"
            exit 1
        }
        Write-Log "SUCCESS" "Windows activated successfully using BIOS key"
    }
    else {
        Write-Host "INFO" "No action required: Windows is activated with a non-generic key"
    }
}

# ========================
# END Block: Finalization
# ========================
end {
    Write-Log "SUCCESS" "Completed activation or already valid."
}