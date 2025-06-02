#Requires -Version 5.1
<#
    === Developed by Sam ===
    Last Edit: 02-26-2025
#>

<#
.SYNOPSIS
    Change the system time zone based on an RMM dropdown selection.

.DESCRIPTION
    Reads the 'timeZone' environment variable set by your RMM platform,
    validates it against a predefined list of shorthands,
    maps it to a full Windows Time Zone ID,
    and applies that setting via tzutil.

.PARAMETER TimeZone
    One of: Eastern, Central, Mountain, Pacific.
    Defaults to Central if not specified or invalid.
#>

[CmdletBinding()]
param(
    # Dropdown option                                                        Ninja Variable Resolution                Fallback
    [ValidateSet("Eastern","Central","Mountain","Pacific")][string]$TimeZone = $(if ($env:timeZone) { $env:timeZone } else { "Central" }) # Ninja Script Variable; Dropdown
)

# =========================================
# BEGIN Block: Elevation & Input Validation
# =========================================
begin {
    # Function: Check for Administrator rights
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    
    # Ensure script is running elevated
    if (-not (Test-IsElevated)) {
        Write-Error "Administrator privileges are required to change the system time zone."
        exit 1
    }
    
    Write-Host "Timezone Input: '$TimeZone'"
}

# =========================================
# PROCESS Block: Map Shorthand -> Time Zone ID
# =========================================
process {
    # Define mapping table
    $tzMap = @{
        "Eastern"  = "Eastern Standard Time"
        "Central"  = "Central Standard Time"
        "Mountain" = "Mountain Standard Time"
        "Pacific"  = "Pacific Standard Time"
    }
    
    # Retrieve full Windows TZ ID
    if ($tzMap.ContainsKey($TimeZone)) {
        $fullTz = $tzMap[$TimeZone]
        Write-Host "Selected time zone shorthand '$TimeZone' -> '$fullTz'"
    }
    else {
        # This should never happen due to ValidateSet, but guard anyway
        Write-Error "Invalid time zone '$TimeZone'. Allowed values: $($tzMap.Keys -join ', ')."
        exit 1
    }
    
    # Apply the time zone
    try {
        tzutil /s "$fullTz"
        Write-Host "Time zone successfully set to '$fullTz'."
    }
    catch {
        Write-Error "Failed to apply time zone '$fullTz'. Error: $_"
        exit 1
    }
}

# =========================================
# END Block: Finalization
# =========================================
end {
    Write-Host "Time zone configuration script completed."
}