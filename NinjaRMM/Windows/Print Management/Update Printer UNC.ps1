#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 03-25-2025
#>

<#
.SYNOPSIS
    Adds equivalent UNC Printer(s) from one print server to another (useful for migrations)

.DESCRIPTION
    This script scans for network printer connections whose name starts with the provided OldUNCPath 
    (for example, "\\Server1"). For each matching printer, it creates a new printer connection by 
    replacing the OldUNCPath with NewUNCPath (for example, "\\Server2") in the printers UNC path.
    If the new printer connection is successfully added (or already exists), then:
      - If configured, the script copies printer preferences.
      - If the old printer was the default, the new one is set as default.
      - The old printer connection is then removed.
      
.PARAMETER OldUNCPath
    The base UNC path of the old printer connections (e.g. "\\Server1").

.PARAMETER NewUNCPath
    The base UNC path for the new printer connections (e.g. "\\Server2").

.PARAMETER CopyPreferences
    Optional switch. If set, attempts to copy printer preferences from the old printer to the new one.

.NOTES
    Intended to run under the current user context.
#>

[CmdletBinding()]
param(
    # String inputs     Ninja Variable Resolution                    Fallback
    [string]$OldUNCPath = $(if ($env:oldUncPath) { $env:oldUncPath } else { "Not Set!" }), # Ninja Script Variable; String - Fallback will cause failure
    [string]$NewUNCPath = $(if ($env:newUncPath) { $env:newUncPath } else { "Not Set!" }), # Ninja Script Variable; String - Fallback will cause failure
    
    # Independent switches   Ninja Variable Resoution                                                                   Fallback
    [Switch]$CopyPreferences = $(if ($env:copyPrinterPreferences) { [Convert]::ToBoolean($env:copyPrinterPreferences) } else { $false }) # Ninja Script Variable; Checkbox
)

# =================================
# BEGIN Block: Validation & Helper functions
# =================================
Begin {
    # Safety check for required parameters.
    if (-not $OldUNCPath -or -not $NewUNCPath) {
        Write-Error "Both OldUNCPath and NewUNCPath must be provided (as parameters or environment variables)."
        exit 1
    }
    
    #####################
    # Helper Functions  #
    #####################
    
    # Helper function: Extract base prefix from a UNC string
    function Get-BasePrefix {
        param(
            [string]$UNC
        )
        $uncTrimmed = $UNC.TrimStart('\')
        $base = $uncTrimmed.Split('\')[0]
        return $base
    }
    
    # Helper function: Copy printer preferences (if supported - some printers do not store under this method)
    function Copy-PrinterPreferences {
        param (
            [Parameter(Mandatory=$true)]
            [string]$OldPrinterName,
            [Parameter(Mandatory=$true)]
            [string]$NewPrinterName
        )
        
        Write-Output "Attempting to copy printer preferences from '$OldPrinterName' to '$NewPrinterName'..."
        
        # May not work if Printers Driver does not store settings the universal way
        if (Get-Command Get-PrintConfiguration -ErrorAction SilentlyContinue) {
            try {
                $oldConfig = Get-PrintConfiguration -PrinterName $OldPrinterName -ErrorAction Stop
                $newConfig = Get-PrintConfiguration -PrinterName $NewPrinterName -ErrorAction Stop
                
                # DuplexingMode
                if ($oldConfig.DuplexingMode -ne $newConfig.DuplexingMode) {
                    Write-Output "Copying DuplexingMode: $($oldConfig.DuplexingMode)"
                    Set-PrintConfiguration -PrinterName $NewPrinterName -DuplexingMode $oldConfig.DuplexingMode
                }
                else {
                    Write-Output "DuplexingMode already matches."
                }
                
                # PageMediaSize
                if ($oldConfig.PageMediaSize -and $oldConfig.PageMediaSize -ne $newConfig.PageMediaSize) {
                    Write-Output "Copying PageMediaSize (tray selection): $($oldConfig.PageMediaSize)"
                    Set-PrintConfiguration -PrinterName $NewPrinterName -PageMediaSize $oldConfig.PageMediaSize
                }
                else {
                    Write-Output "PageMediaSize already matches or not available."
                }
                
                # Collate
                if ($oldConfig.Collate -ne $newConfig.Collate) {
                    Write-Output "Copying Collate setting: $($oldConfig.Collate)"
                    Set-PrintConfiguration -PrinterName $NewPrinterName -Collate $oldConfig.Collate
                }
            }
            catch {
                Write-Warning "Error copying printer preferences: $_"
            }
        }
        else {
            Write-Warning "Get-PrintConfiguration cmdlet is not available. Cannot copy printer preferences."
        }
    }
    
    # Sanitize the OldUNCPath so that it only contains the base UNC (server) portion.
    $baseOldUNC = "\\" + (Get-BasePrefix $OldUNCPath)
    if ($OldUNCPath.ToLower() -ne $baseOldUNC.ToLower()) {
        Write-Output "OldUNCPath contained extra subfolder info. Using base UNC: $baseOldUNC"
        $OldUNCPath = $baseOldUNC
    }
    
    # Sanitize the NewUNCPath so that it only contains the base UNC (server) portion.
    # Any common UNC pathing will be acceptable
    $baseNewUNC = "\\" + (Get-BasePrefix $NewUNCPath)
    if ($NewUNCPath.ToLower() -ne $baseNewUNC.ToLower()) {
        Write-Output "NewUNCPath contained relative path info. Using base UNC: $baseNewUNC"
        $NewUNCPath = $baseNewUNC
    }
    
    Write-Output "Old UNC Path: $OldUNCPath"
    Write-Output "New UNC Path: $NewUNCPath"
}

# =================================
# PROCESS Block: Update Printers to new UNC
# =================================
process {
    Write-Output "Processing printer connections..."
    
    try {
        $printers = Get-WmiObject -Class Win32_Printer | Where-Object { $_.Network -eq $true -and $_.Name -like "\\*" }
    }
    catch {
        Write-Warning "Unable to retrieve printer connections."
        $printers = @()
    }
    
    # List printers
    Write-Output "Enumerated printer connections:"
    foreach ($printer in $printers) {
        Write-Output " - $($printer.Name)"
    }
    
    foreach ($printer in $printers) {
        # Check if the printer's UNC starts with the provided OldUNCPath (case-insensitive)
        if ($printer.Name.ToLower().StartsWith($OldUNCPath.ToLower())) {
            Write-Output "Found matching printer connection: $($printer.Name)"
            
            # Compute the new printer UNC by replacing the base portion
            $newPrinterUNC = $printer.Name -replace [regex]::Escape($OldUNCPath), $NewUNCPath
            Write-Output "Computed new printer UNC: $newPrinterUNC"
            
            # Check if a printer with the new UNC already exists
            $newPrinterExists = $printers | Where-Object { $_.Name.ToLower() -eq $newPrinterUNC.ToLower() }
            
            # New printer does exist
            if ($newPrinterExists) {
                Write-Output "Printer with new UNC '$newPrinterUNC' already exists."
                if ($printer.Default) {
                    Write-Output "Old printer was default; setting new printer as default."
                    Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /y /n `"$newPrinterUNC`"" -WindowStyle Hidden -Wait -PassThru | Out-Null
                }
                
                # Remove old printer if it still exists
                Write-Output "Removing old printer connection: $($printer.Name)"
                $delProcess = Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /dn /n `"$($printer.Name)`"" -WindowStyle Hidden -Wait -PassThru
                if ($delProcess.ExitCode -eq 0) {
                    Write-Output "Old printer connection removed successfully."
                }
                else {
                    Write-Warning "Failed to remove old printer connection: $($printer.Name)"
                }
            }
            
            # New printer does not eixsts
            else {
                Write-Output "Adding new printer connection: $newPrinterUNC"
                $addProcess = Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /in /n `"$newPrinterUNC`"" -WindowStyle Hidden -PassThru
                
                # Addresses the posibillity of hanging (UAC PRompt, etc) during instillation
                # 30 Second Install timer
                if (-not $addProcess.WaitForExit(30000)) {
                    Write-Warning "Printer installation for $newPrinterUNC is taking too long. Check for UAC. Terminating process."
                    $addProcess.Kill()
                    $addProcess.WaitForExit()  # Wait for process to be terminated before continuing
                    Write-Warning "Printer installation failed for: $newPrinterUNC. Old connection preserved."
                }
                else {
                    # On success logic
                    if ($addProcess.ExitCode -eq 0) {
                        Write-Output "New printer connection added successfully: $newPrinterUNC"
                        
                        # Copy preferences flag
                        if ($CopyPreferences) {
                            Copy-PrinterPreferences -OldPrinterName $printer.Name -NewPrinterName $newPrinterUNC
                        }
                        
                        # Set defaylt if previous printer was default
                        if ($printer.Default) {
                            Write-Output "Old printer was default. Setting new printer as default."
                            Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /y /n `"$newPrinterUNC`"" -WindowStyle Hidden -Wait -PassThru | Out-Null
                        }
                        
                        # Remove previous printer
                        Write-Output "Removing old printer connection: $($printer.Name)"
                        $delProcess = Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /dn /n `"$($printer.Name)`"" -WindowStyle Hidden -Wait -PassThru
                        if ($delProcess.ExitCode -eq 0) {
                            Write-Output "Old printer connection removed successfully."
                        }
                        else {
                            Write-Warning "Failed to remove old printer connection: $($printer.Name)"
                        }
                    }
                    else {
                        Write-Warning "Failed to add new printer connection: $newPrinterUNC. Old connection preserved."
                    }
                }
            }
        }
    }
}

# =================================
#  END Block: Finalization
# =================================
end {
    Write-Output "Printer update process completed."
}