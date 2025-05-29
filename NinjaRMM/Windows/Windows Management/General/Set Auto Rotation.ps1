#Requires -Version 5.1
<#
    === Developed by Sam ===
    Last Edit: 05-16-2025
#>

<#
.SYNOPSIS
    Enables or disables Windows Auto-Rotation based on an RMM checkbox.

.DESCRIPTION
    This script imports the undocumented SetAutoRotation function (ordinal 2507) from user32.dll
    and invokes it to turn Auto-Rotation on or off.  You control behavior with either:
      - the $EnableAutoRotation switch, or
      - the 'enableAutoRotation' environment variable (1 = enable, 0 = disable, any boolean string via ToBoolean).

.NOTES
    https://stackoverflow.com/questions/10793108/how-to-get-the-screen-auto-rotates-status
#>

[CmdletBinding()]
param(
    [switch]$EnableAutoRotation = $(if ($env:enableAutoRotation) { [Convert]::ToBoolean($env:enableAutoRotation) } else { $false })
)

# =========================================
# BEGIN Block: Parameter Validation / Logging
# =========================================
begin {
    Write-Output "EnableAutoRotation = $EnableAutoRotation"
}

# =========================================
# PROCESS Block: Define C# Helper Type
# =========================================
process {
    $csCode = @"
using System;
using System.Runtime.InteropServices;
public static class AutoRotationHelper {
    // Imports the hidden SetAutoRotation function (ordinal 2507) from user32.dll
    [DllImport("user32.dll", EntryPoint="#2507", SetLastError=true)]
    public static extern bool SetAutoRotation(bool bEnable);
}
"@
    Add-Type -TypeDefinition $csCode -ErrorAction Stop
}

# =========================================
# END Block: Invoke & Report
# =========================================
end {
    $success = [AutoRotationHelper]::SetAutoRotation($EnableAutoRotation)
    if ($success) {
        Write-Output "AutoRotation set successfully. Enabled = $EnableAutoRotation."
    }
    else {
        $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Failed to set AutoRotation. Win32 error code: $code"
    }
}