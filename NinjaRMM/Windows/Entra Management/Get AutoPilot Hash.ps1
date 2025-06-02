#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-15-2025
    
    Notes:
    05-15-2025: Update category tagging
    05-10-2025: Creation and validation testing
#>

<#
.SYNOPSIS
    Data Gathering - Windows - Autopilot Hardware Identifier (Hardware Hash)
.DESCRIPTION
    Retrieves the Windows Autopilot hardware hash via CIM and reports it back to Ninja
.NOTES
    'dsregcmd /join'
    This attempts to join the device to Entra ID using the logged-in user's credentials.
    This method still respects the MDM user scope settings, so it won't enroll the device into Intune if the scope is set to None.
#>

[CmdletBinding()]
param(
    # Independent switch     Ninja Variable Resolution                                                    Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true });, # Ninja Script Variable; Checkbox

    # Ninja custom field name           Ninja Variable Resolution                                                    Fallback
    [string]$AutoPilotSecureCustomField = $(if ($env:autopilotSecureCustomField) { $env:autopilotSecureCustomField } else { 'AutopilotHWID'  }) # Optional Ninja Script Variable - String
)

# ===========================================
# BEGIN Block: RMM Parameter Safety & Property Usage
# ===========================================
begin {
    # Override from environment if provided
    if ($env:AutopilotHWIDPropertyName) {
        $AutoPilotSecureCustomField = $env:AutopilotHWIDPropertyName
    }
    
    # Validate that we have a property name
    if ([string]::IsNullOrWhiteSpace($AutoPilotSecureCustomField)) {
        Write-Error '[ERROR] $AutoPilotSecureCustomField is required. Pass via -PropertyName or set env:AutopilotHWIDPropertyName.'
        exit 1
    }
    
    # NinjaOne property-set command
    $NinjaCmd = 'Ninja-Property-Set'
}

# ===========================================
# PROCESS Block: Retrieve Autopilot Hardware Hash
# ===========================================
process {
    # Define CIM query parameters for the MDM_DevDetail_Ext01 class
    $cimParams = @{
        Namespace = 'root/cimv2/mdm/dmmap'
        Class     = 'MDM_DevDetail_Ext01'
        Filter    = "InstanceID='Ext' AND ParentID='./DevDetail'"
    }

    # Query CIM for device details
    try {
        $detail = Get-CimInstance @cimParams -ErrorAction Stop
    }
    catch {
        Write-Error "[ERROR] Failed to query CIM: $_"
        exit 1
    }
    
    # Ensure we got a result
    if (-not $detail) {
        Write-Error '[ERROR] No device details returned. Cannot retrieve hardware hash.'
        exit 1
    }
    
    # Extract the hardware hash
    $hash = $detail.DeviceHardwareData
    if (-not $hash) {
        Write-Error '[ERROR] DeviceHardwareData property is empty.'
        exit 1
    }
    
    # Report the hash back to NinjaOne
    if (Get-Command $NinjaCmd -ErrorAction SilentlyContinue) {
        Write-Host "Updating NinjaOne property '$AutoPilotSecureCustomField' with hardware hash."
        & $NinjaCmd -Name $AutoPilotSecureCustomField -Value $hash
    }
    else {
        Write-Warning "[WARNING] Command '$NinjaCmd' not found. Skipping property update."
    }
}

# ============================
# END Block: Exit on Success
# ============================
end {
    Write-Host "[SUCCESS] Completed AutoPilot hash update to secure field."
}