#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-19-2025
    
    Notes:
    05-19-2025: General cleanup improvements
    04-25-2025: Creation and validation testing
#>

<#
.SYNOPSIS
    Add, update, or remove ACL for a specific group on a local printer.

.DESCRIPTION
    - Reads the existing Win32_Printer security descriptor
    - Preserves all ACEs except those for the target principal
    - Can completely remove that principal's ACEs if requested
    - Computes three decimal access masks (Print, ManagePrinter, ManageDocuments)
    - Applies Windows logic: 
      - Deny Print -> Deny everything
      - Deny ManagePrinter under Print=Allow -> skip explicit Deny to avoid cascade
      - Seed Deny then Allow for ManageDocuments so Allow shows in UI
    - Writes the updated descriptor back to the printer
    - Explains when impossible combinations are normalized

.PARAMETER PrinterName
    Exact name of the local printer.

.PARAMETER PrinterPrincipal
    Canonical principal (e.g. BUILTIN\Everyone, JoinedDomain\<group, user, object, etc>).

.PARAMETER PrintPermission
    "Allow" or "Deny" the Print right.

.PARAMETER ManagePrinterPermission
    "Allow" or "Deny" the Manage this Printer right.

.PARAMETER ManageDocumentsPermission
    "Allow" or "Deny" the Manage Documents right.

.PARAMETER RemovePrincipal
    If set, removes all ACEs for the principal and exits.

.NOTES
    Must run elevated
#>

[CmdletBinding()]
param(
    # Individual strings      Ninja Variable Resolution                                Fallback
    [string]$PrinterName      = $(if ($env:printerName) { $env:printerName }           else { "Not Set!" }), # Ninja Script Variable; String - Fallback will cause failure
    [string]$PrinterPrincipal = $(if ($env:printerPrincipal) { $env:printerPrincipal } else { "Not Set!" }), # Ninja Script Variable; String - Fallback will cause failure

    # Dropdown Dropdowns                                            Ninja Variable Resolution                                                  Fallback
    [ValidateSet("Allow","Deny")][string]$PrintPermission           = $(if ($env:managePrintPermission) { $env:managePrintPermission }         else { "Not Set!" }), # Ninja Script Variable; Dropdown - Fallback will cause failure
    [ValidateSet("Allow","Deny")][string]$ManagePrinterPermission   = $(if ($env:managePrinterPermission) { $env:managePrinterPermission }     else { "Not Set!" }), # Ninja Script Variable; Dropdown - Fallback will cause failure
    [ValidateSet("Allow","Deny")][string]$ManageDocumentsPermission = $(if ($env:manageDocumentsPermission) { $env:manageDocumentsPermission } else { "Not Set!" }), # Ninja Script Variable; Dropdown - Fallback will cause failure
    
    # Independent switches   Ninja Variable Resolution                                                    Fallback
    [Switch]$RemovePrincipal = $(if ($env:removePrincipal) { [Convert]::ToBoolean($env:removePrincipal) } else { $false }), # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true })   # Ninja Script Variable; Checkbox
)

# ===========================================
# BEGIN Block: Pull from env:, validate & define masks
# ===========================================
begin {
    # Make sure all needed inputs are included
    foreach ($v in 'PrinterName','PrinterPrincipal','PrintPermission','ManagePrinterPermission','ManageDocumentsPermission') {
        if (-not (Get-Variable $v -ValueOnly)) {
            Write-Log "ERROR" "Missing parameter/env var: $v"
            exit 1
        }
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
            $logFile = Join-Path $logDir "Permissions.log"
            
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

    # Helper function: parse short principal to DOMAIN\Name
    function Parse-Principal {
        param($p)
        if ($p -notmatch '\\') {
            "$($env:COMPUTERNAME)\$p"
        }
        else {
            $p
        }
    }
    
    # Helper function: append Win32_ACE to $sdNew.DACL
    function Add-Ace {
        param($type,$flags,$mask)
        $ace = ([WmiClass]"Win32_ACE").CreateInstance()
        $ace.AceType    = $type
        $ace.AceFlags   = $flags
        $ace.Trustee    = $trustee
        $ace.AccessMask = $mask
        $sdNew.DACL   += $ace
    }
    
    # Helper function: apply descriptor with custom ManageDocumentsPermission
    function Apply-Descriptor {
        param($mdPerm)
        # start new descriptor
        $sdNew = ([WmiClass]"Win32_SecurityDescriptor").CreateInstance()
        $sdNew.ControlFlags = $SE_DACL_PRESENT
        $sdNew.DACL = @()
        # preserve all ACEs except our principal
        foreach ($old in $sdOld.DACL) {
            if (-not ($old.Trustee.Domain -eq $domain -and $old.Trustee.Name -eq $acctName)) {
                $sdNew.DACL += $old
            }
        }
        # Add or Deny Print right
        if ($PrintPermission -eq 'Allow') {
            Add-Ace 0 0 $maskPrint
        }
        else {
            Add-Ace 1 0 $maskPrint
        }
        # Add or Deny ManagePrinter right (skip Deny if Print=Allow)
        if ($ManagePrinterPermission -eq 'Allow') {
            Add-Ace 0 0 $maskManagePrinter
        }
        <#
          Important for proper handling. Removes the ace for ManagingPrinter specifically when the following is set:
          Print           = Allow
          ManagePrinter   = Deny
          This allows the Print and ManagePrinter security to be set without error
        #>
        elseif ($ManagePrinterPermission -eq 'Deny' -and $PrintPermission -ne 'Allow') {
            Add-Ace 1 0 $maskManagePrinter
            Write-Log "WARNING" "Manage Printer permissions no longer have explicit permissions set.`n This is correct handling for your selection."
        }
        # Add or Deny ManageDocuments right (flags=9 for UI visibility)
        if ($mdPerm -eq 'Allow') {
            Add-Ace 0 9 $maskManageDocuments
        }
        else {
            Add-Ace 1 9 $maskManageDocuments
        }
        # commit descriptor
        $printer.psbase.Scope.Options.EnablePrivileges = $true
        $r = $printer.SetSecurityDescriptor($sdNew)
        if ($r.ReturnValue -ne 0) {
            Write-Log "ERROR" "Commit failed ($($r.ReturnValue))"
            exit 1
        }
    }
    
    # Require elevation
    $me = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "ERROR" "Must run as Administrator."
        exit 1
    }
    
    # well-known SIDs map
    $wellKnownSids = @{
        'NT AUTHORITY\SYSTEM'              = 'S-1-5-18'
        'BUILTIN\Administrators'           = 'S-1-5-32-544'
        'BUILTIN\Users'                    = 'S-1-5-32-545'
        'BUILTIN\Print Operators'          = 'S-1-5-32-551'
        'BUILTIN\Power Users'              = 'S-1-5-32-547'
        'NT AUTHORITY\Authenticated Users' = 'S-1-5-11'
        'CREATOR OWNER'                    = 'S-1-3-0'
        'OWNER RIGHTS'                     = 'S-1-3-4'
        'BUILTIN\Everyone'                 = 'S-1-1-0'
    }
    
    # ControlFlags to indicate DACL present
    $SE_DACL_PRESENT = 0x4
    
    # decimal masks (PrintSystemAccessRights):
    $maskPrint           = 131072 -bor 8          # READ_CONTROL + PRINTER_ACCESS_USE
    $maskManagePrinter   = 983040 -bor 4 -bor 8   # STANDARD_RIGHTS_REQUIRED + PRINTER_ACCESS_ADMINISTER + PRINTER_ACCESS_USE
    $maskManageDocuments = 983040 -bor 16 -bor 32 # STANDARD_RIGHTS_REQUIRED + JOB_ACCESS_ADMINISTER + JOB_ACCESS_READ
    
    Write-Host "`n=== Permission Masks ==="
    Write-Host " Print           = $PrintPermission"
    Write-Host " ManagePrinter   = $ManagePrinterPermission"
    Write-Host " ManageDocuments = $ManageDocumentsPermission"
    Write-Host " RemovePrincipal = $RemovePrincipal"

}

# ===========================================
# PROCESS Block: fetch printer, build trustee & old DACL
# ===========================================
process {
    # Resolve principal & split domain/name
    $fullPrincipal = Parse-Principal $PrinterPrincipal
    $domain,$acctName = $fullPrincipal -split '\\',2
    
    # Fetch WMI printer object
    $printer = Get-WmiObject -EnableAllPrivileges Win32_Printer | Where Name -eq $PrinterName
    if (-not $printer) {
        Write-Log "ERROR" "Printer '$PrinterName' not found."
        exit 1
    }
    
    # Load existing descriptor
    $sdOld = ($printer.GetSecurityDescriptor()).Descriptor
    
    # build trustee object
    $trustee = ([WmiClass]"Win32_Trustee").CreateInstance()
    if ($wellKnownSids.ContainsKey($fullPrincipal)) {
        $sid = New-Object Security.Principal.SecurityIdentifier($wellKnownSids[$fullPrincipal])
    }
    else {
        try {
            $sid = (New-Object Security.Principal.NTAccount($fullPrincipal)).Translate(
                       [Security.Principal.SecurityIdentifier]
                   )
        }
        catch {
            Write-Log "ERROR" "Cannot resolve SID for '$fullPrincipal'"
            exit 1
        }
    }
    # Hold parsed input data for further handling
    $trustee.Domain    = $domain
    $trustee.Name      = $acctName
    $trustee.SIDString = $sid.Value
    
    # Remove principal entirely if requested
    if ($RemovePrincipal) {
        $sdNew = ([WmiClass]"Win32_SecurityDescriptor").CreateInstance()
        $sdNew.ControlFlags = $SE_DACL_PRESENT
        $sdNew.DACL = @()
        foreach ($ace in $sdOld.DACL) {
            if (-not ($ace.Trustee.Domain -eq $domain -and $ace.Trustee.Name -eq $acctName)) {
                $sdNew.DACL += $ace
            }
        }
        $printer.psbase.Scope.Options.EnablePrivileges = $true
        $res = $printer.SetSecurityDescriptor($sdNew)
        Write-Log "INFO" "Removed all ACEs for '$fullPrincipal'."
        if ($res.ReturnValue -eq 0) {
            Write-Log "INFO" "Removed all ACEs for '$fullPrincipal'."
            exit 0
        }
        else {
            Write-Log "INFO" "'$fullPrincipal' is not a security member.`n Exiting now."
            exit 1
        }
    }
    
    # normalize impossible combo: Print=Deny & ManagePrinter=Allow
    if ($PrintPermission -eq 'Deny' -and $ManagePrinterPermission -eq 'Allow') {
        Write-Warning "Cannot Allow Manage Printer when Print Permission is Denied; overriding both to Deny."
        $ManagePrinterPermission = 'Deny'
    }
    
    # apply Windows logic
    if ($PrintPermission -eq 'Deny') {
        Write-Log "INFO" "Print -> Denied all rights"
        Apply-Descriptor 'Deny'
    }
    # Seed Descriptor for proper UI updating. Required to work correctly.
    elseif ($ManageDocumentsPermission -eq 'Allow') {
        Apply-Descriptor 'Deny'
        Apply-Descriptor 'Allow'
        Write-Log "INFO" "Manage Documents -> Allowed Manage Documents"
    }
    else {
        Apply-Descriptor $ManageDocumentsPermission
    }
}

# ===========================================
# END Block: success
# ===========================================
end {
    Write-Log "SUCCESS" "Updated ACL for '$PrinterPrincipal' on '$PrinterName'."
}