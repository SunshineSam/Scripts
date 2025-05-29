#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-13-2025

    05-13-02025
    Addressed a bug with the Get-FreeDriveLetter function not passing the char from the charset correctly; Always resulting in failure to temp map.

    - 04-02-2025 -
    Initial relase

#>

<#
.SYNOPSIS
    Remaps network drive connections from an old UNC prefix to a new UNC prefix,
    preserving any relative pathing structure.

.DESCRIPTION
    This script scans for mapped network drives whose UNC path begins with a given old UNC prefix.
    For each matching drive, it determines the actual base UNC from the resolved drive mapping
    (could differ on mappings that host a shared network mapping instead of relying solely on the input value) 
    used to compute the relative path.
    It then builds the new UNC by concatenating the new UNC prefix with that relative portion.
    The script:
      1. Determines a free temporary drive letter.
      2. Always attempts to create a temporary mapping of the old UNC on that drive.
         If the temporary mapping fails and if ForceNewMapping is enabled, it proceeds anyway;
         otherwise, it skips that drive.
      3. Removes the current mapping on the original drive letter.
      4. Attempts to map the new UNC under the original drive letter.
      5. If successful, it deletes the temporary mapping-but only if that temp mapping was actually created.
         If mapping the new UNC fails, it attempts to revert to the original mapping.

.PARAMETER OldUNCPrefix
    The old UNC prefix for the existing network drive mappings (e.g. "\\Server1").

.PARAMETER NewUNCPrefix
    The new UNC prefix for the new network drive mappings (e.g. "\\Server2").

.PARAMETER ForceNewMapping
    When flagged, forces a new mapping even if the temporary
    mapping fails. In that case, the script unmaps the original drive letter and proceeds.

.NOTES
    Intended to run under the current user context.
#>

[CmdletBinding()]
param(
    [string]$OldUNCPrefix = $(if ($env:oldUncPrefix) { $env:oldUncPrefix } else { "Not Set!" }),
    [string]$NewUNCPrefix = $(if ($env:newUncPrefix) { $env:newUncPrefix } else { "Not Set!" }),
    
    [Switch]$ForceNewMapping = $(if ($env:forceNewMapping) { [Convert]::ToBoolean($env:forceNewMapping) } else { $false })
)

# =================================
# BEGIN Block: Initialization & Validation
# =================================
begin {
    # Safety check for required parameters
    if (-not $OldUNCPrefix -or -not $NewUNCPrefix) {
        Write-Error "Both OldUNCPrefix and NewUNCPrefix must be provided (via parameters or environment variables)."
        exit 1
    }
    
    ####################
    # Helper Functions
    ####################
    
    # Helper function: Get a free drive letter from Z: to D:
    function Get-FreeDriveLetter {
        $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
        foreach ($letter in ([char[]]"ZYXWVUTSRQPONMLKJIHGFED")) {
            if ($usedLetters -notcontains $letter) {
                return "$letter`:"
            }
        }
        return $null
    }
    
    # Helper function: Extract base prefix from a UNC string
    function Get-BasePrefix {
        param(
            [string]$UNC
        )
        # Remove leading backslashes and split on "\"
        $uncTrimmed = $UNC.TrimStart('\')
        $base = $uncTrimmed.Split('\')[0]
        return $base
    }
    
    #################
    # Sanitization
    #################

    # Remove any trailing backslashes
    $OldUNCPrefix = $OldUNCPrefix.TrimEnd("\")
    $NewUNCPrefix = $NewUNCPrefix.TrimEnd("\")
    
    # Reconstruct them as base UNC.
    $baseOldUNCPrefix = "\\" + (Get-BasePrefix $OldUNCPrefix)
    
    # Resolving Old UNC
    if ($OldUNCPrefix.ToLower() -ne $baseOldUNCPrefix.ToLower()) {
        Write-Output "Old UNC has resolution address of: $baseOldUNCPrefix"
        $OldUNCPrefix = $baseOldUNCPrefix
    }
    
    # Resolving New UNC
    $baseNewUNCPrefix = "\\" + (Get-BasePrefix $NewUNCPrefix)
    if ($NewUNCPrefix.ToLower() -ne $baseNewUNCPrefix.ToLower()) {
        Write-Output "New UNC has resolution address of: $baseNewUNCPrefix"
        $NewUNCPrefix = $baseNewUNCPrefix
    }
    
    # Display Inputs
    Write-Output "Old UNC Prefix: $OldUNCPrefix"
    Write-Output "New UNC Prefix: $NewUNCPrefix"
    
    # Force Mapping to skip temp mapping on failure
    if ($ForceNewMapping) {
        Write-Output "ForceNewMapping is enabled; if temporary mapping fails, the script will proceed without it."
    }
}

# =================================
# PROCESS Block: Calculate Drives, Compare & Tempmap/ Remap
# =================================
process {
    Write-Output "Enumerating network drive mappings..."
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=4"
    }
    catch {
        Write-Error "Unable to retrieve network drive mappings: $_"
        exit 1
    }
    
    # Go through each network drive
    foreach ($drive in $drives) {
        $oldMappingUNC = $drive.ProviderName
        # Safety check
        if ([string]::IsNullOrEmpty($oldMappingUNC)) {
          # Next drive if null for whatever reason
          Write-Error "$oldMappingUNC is invalid. Continuing to next mapping if applicable"
          continue
        }
        
        # Determine the actual base UNC of the resolved mapping
        $actualOldBase = "\\" + (Get-BasePrefix $oldMappingUNC)

        # Compare Drive logic (set to lower case for comparison)
        $resolvedBase = (Get-BasePrefix $oldMappingUNC).ToLower()
        $inputBase    = (Get-BasePrefix $OldUNCPrefix).ToLower()
        Write-Output "Comparing drive $($drive.DeviceID) - '$resolvedBase' with '$inputBase'"
        # Only execute if base prefix of DriveProviderName is equal to the sanitized OLDUNCPrefix (user input)
        if ($resolvedBase -ne $inputBase) {
            Write-Output "Drive $($drive.DeviceID) does not match. Skipping"
            # Move onto next drive
            continue
        }
        
        Write-Output "Found matching drive mapping - $($drive.DeviceID) - $oldMappingUNC"
        
        # Compute the relative path from the resolved base
        $relativePath = $oldMappingUNC.Substring($actualOldBase.Length)
        # If relative path is valid, and the first char is not "\", then sanitize
        if ($relativePath -and $relativePath[0] -ne "\") {
            $relativePath = "\" + $relativePath
        }
        
        # Build newMappingUNC
        $newMappingUNC = $NewUNCPrefix + $relativePath
        Write-Output "Computed new UNC: $newMappingUNC"
        
        # Original Letter storage
        $origLetter = $drive.DeviceID
        Write-Output "Original drive letter: $origLetter"
        
        # Determine a free temporary drive letter
        $tempLetter = Get-FreeDriveLetter
        if (-not $tempLetter) {
            Write-Warning "No free drive letter available for temporary mapping. Skipping drive $origLetter."
            # Move onto next drive
            continue
        }
        Write-Output "Using temporary drive letter: $tempLetter"
        
        # Always attempt a temporary mapping
        Write-Output "Mapping old UNC '$oldMappingUNC' to temporary drive letter $tempLetter..."
        $tempMap = Start-Process -FilePath "net.exe" -ArgumentList "use $tempLetter `"$oldMappingUNC`" /persistent:yes" -WindowStyle Hidden -PassThru
        # If probable UAC prompt
        if (-not $tempMap.WaitForExit(30000)) {
            Write-Warning "Temporary mapping operation taking too long (possible UAC prompt)."
            # End current process of mapping
            $tempMap.Kill()
            $tempMap.WaitForExit()
            # Continue current drive if ForceNewMapping
            if ($ForceNewMapping) {
                Write-Output "ForceNewMapping enabled: Proceeding without temporary mapping."
            }
            else {
                Write-Warning "Skipping drive $origLetter due to temporary mapping failure."
                # Move onto next drive
                continue
            }
        }
        # On temp mapping failure
        elseif ($tempMap.ExitCode -ne 0) {
            Write-Warning "Failed to create temporary mapping on $tempLetter."
            # Continue current drive if ForceNewMapping
            if ($ForceNewMapping) {
                Write-Output "ForceNewMapping enabled: Proceeding without temporary mapping."
                # Continue current execution
            }
            else {
                Write-Warning "Skipping drive $origLetter due to temporary mapping failure."
                # Move onto next drive
                continue
            }
        }
        # On temp mapping success
        elseif ($tempMap.ExitCode -eq 0) {
          Write-Output "Successfully mapped temporary drive $tempLetter`"$oldMappingUNC`""
        }
        
        # Remove the original mapping.
        Write-Output "Removing current mapping on $origLetter..."
        net use $origLetter /delete /yes | Out-Null
        
        # Attempt to map the new UNC under the original drive letter
        Write-Output "Mapping new UNC '$newMappingUNC' to drive letter $origLetter..."
        $newMap = Start-Process -FilePath "net.exe" -ArgumentList "use $origLetter `"$newMappingUNC`" /persistent:yes" -WindowStyle Hidden -PassThru
        # If probable UAC prompt, map old drive
        if (-not $newMap.WaitForExit(30000)) {
            Write-Warning "Mapping new UNC operation taking too long (possible UAC prompt). Attempting to revert..."
            # End current process of mapping
            $newMap.Kill()
            $newMap.WaitForExit()
            # Delete original letter; saftey check
            net use $origLetter /delete /yes | Out-Null
            # Attemp mapping original UNC
            net use $origLetter $oldMappingUNC /persistent:yes | Out-Null
            # On mapping success
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Reverted: Old UNC mapping restored on $origLetter."
            }
            else {
                Write-Warning "Reversion failed: Unable to restore the old UNC mapping on $origLetter."
            }
            # Move onto next drive
            continue
        }
        # New mapping successful
        if ($newMap.ExitCode -eq 0) {
            Write-Output "Drive $origLetter successfully remapped to $newMappingUNC."
            # If temp map was previously mapped
            if ($tempMap -and $tempMap.ExitCode -eq 0) {
                # Delete temp mapping
                $delTemp = Start-Process -FilePath "net.exe" -ArgumentList "use $tempLetter /delete /yes" -WindowStyle Hidden -PassThru
                $delTemp.WaitForExit(30000)
                Write-Output "Temporary drive mapping deleted on $tempLetter."
            }
        }
        # If failure to add new mapping. Should only occur if new UNC is not availiable
        else {
            Write-Warning "Failed to map new UNC '$newMappingUNC' to $origLetter. Attempting to revert..."
            net use $origLetter /delete /yes | Out-Null
            net use $origLetter $oldMappingUNC /persistent:yes | Out-Null
            $reversionSucceeded = ($LASTEXITCODE -eq 0)
            # On reversion success
            if ($reversionSucceeded) {
                Write-Output "Reverted: Old UNC mapping restored on $origLetter."
            }
            else {
                Write-Warning "Reversion failed: Unable to restore the old UNC mapping on $origLetter."
                # If temp map was previously mapped
                if ($tempMap -and $tempMap.ExitCode -eq 0) {
                    Write-Output "Maintaining temp mapping on drive $origLetter."
                }
            }
            # Only delete the temporary mapping if it was successfully created, and the reversion succeeded
            if ($reversionSucceeded -and $tempMap -and $tempMap.ExitCode -eq 0) {
                $delTemp = Start-Process -FilePath "net.exe" -ArgumentList "use $tempLetter /delete /yes" -WindowStyle Hidden -PassThru
                $delTemp.WaitForExit(5000)
                # On deletion success
                if ($LASTEXITCODE -eq 0) {
                    Write-Output "Deleted temp mapping on $tempLetter"
                }
                else {
                    Write-Warning "Failed to delete temp mapping on $tempLetter."
                }
            }
        }
    }
}

# =================================
#  END Block: Finalization
# =================================
end {
    Write-Output "Network drive remapping process completed."
}