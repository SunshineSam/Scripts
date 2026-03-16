#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 03-04-2026

    Note:
    03-04-2026: Initial creation. Enterprise-grade cup holder deployment and
                retraction system leveraging optical drive hardware for
                beverage containment purposes. Added multi-drive support,
                health monitoring, and NinjaRMM status card integration.
                Implemented OSHA-compliant spill risk assessment engine.
                Added thermal beverage proximity warning system.
#>

<#
.SYNOPSIS
    Deploys or retracts the enterprise cup holder (optical drive tray) with full telemetry.

.DESCRIPTION
    Interfaces with the system's optical media subsystem to deploy a certified
    beverage containment platform (CD/DVD drive tray). Performs comprehensive
    hardware enumeration, spill risk analysis, and OSHA compliance verification
    before initiating cup holder operations.

    The five possible output states are:
      1. Deployed       - Cup holder successfully extended for beverage placement
      2. Retracted      - Cup holder stowed; beverage removal confirmed
      3. Not Applicable - No optical drive hardware detected (recommend USB cup warmer)
      4. In Use         - Optical media present; cup holder unavailable (disc conflict)
      5. Action Required - Drive jammed or unresponsive; manual intervention needed

.PARAMETER StatusCardFieldName
    NinjaRMM WYSIWYG custom field name for the HTML status card.
    Defaults to "CupHolderStatusCard" or env:cupHolderStatusCardField.

.PARAMETER PlainTextFieldName
    NinjaRMM text custom field name for the plain-text summary.
    Defaults to "CupHolderStatus" or env:cupHolderPlainTextField.

.PARAMETER Action
    Specifies the cup holder operation: Deploy (extend tray) or Retract (close tray).
    Defaults to "Deploy".

.PARAMETER BeverageType
    Optional. Declares the beverage type for spill risk calculation.
    Accepted values: Coffee, Tea, Water, Soda, Energy Drink, Unknown.
    Defaults to "Unknown".

.PARAMETER SaveLogToDevice
    If specified, saves operation logs to a local file for audit trail compliance.
#>

[CmdletBinding()]
param(
    # Ninja custom field names          Ninja Variable Resolution                                                 Fallback
    [string]$StatusCardFieldName = $(if ($env:cupHolderStatusCardField)  { $env:cupHolderStatusCardField }  else { "CupHolderStatusCard" }), # Optional Ninja Script Variable; String
    [string]$PlainTextFieldName  = $(if ($env:cupHolderPlainTextField)   { $env:cupHolderPlainTextField }   else { "CupHolderStatus" }),     # Optional Ninja Script Variable; String
    
    # Operation options              Ninja Variable Resolution                                                                                                         Fallback
    [ValidateSet("Deploy", "Retract")][string]$Action                                              = $(if ($env:cupHolderAction)       { $env:cupHolderAction }        else { "Deploy" }),  # Ninja Script Variable; Drop-Down
    [ValidateSet("Coffee", "Tea", "Water", "Soda", "Energy Drink", "Unknown")][string]$BeverageType = $(if ($env:cupHolderBeverageType) { $env:cupHolderBeverageType }  else { "Unknown" }), # Ninja Script Variable; Drop-Down
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $true }), # Ninja Script Variable; Checkbox
    
    # Card customization options
    [string]$CardTitle              = "Cup Holder",               # Default title
    [string]$CardIcon               = "fas fa-mug-hot",           # Default icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default",                  # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius       = "10px",                     # Default border radius
    [string]$CardSeparationMargin   = "0 8px"                     # Default distance between cards
)

# =========================================
# BEGIN Block: Initialization & Functions
# =========================================
begin {
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`nAdministrator privileges required for cup holder operations"
        exit 1
    }
    Write-Host "`nRunning as Administrator - Cup Holder subsystem authorized"
    
    #######################
    # Helper Functions
    #######################
    
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
            
            # Use the system drive for logging
            $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $logDir = "$systemDrive\Logs\CupHolder"
            $logFile = Join-Path $logDir "CupHolderOperations.log"
            
            # Sublogic: Create the log directory if it doesn't exist
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
    
    # Helper function: Create an info card with structured data and icon color
    function Get-NinjaOneInfoCard($Title, $Data, [string]$Icon, [string]$TitleLink, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor = "#000000") {
        [System.Collections.Generic.List[String]]$ItemsHTML = @()
        foreach ($Item in $Data.PSObject.Properties) {
            $ItemsHTML.add('<p ><b >' + $Item.Name + '</b><br />' + $Item.Value + '</p>')
        }
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor -SeparationMargin $CardSeparationMargin
    }
    
    # Helper function: Generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor, [string]$SeparationMargin) {
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background: $BackgroundGradient; border-radius: $BorderRadius; margin: $SeparationMargin;"
        $OutputHTML.add('<div class="card flex-grow-1' + $(if ($classes) { ' ' + $classes }) + '" style="' + $style + '">')
        if ($Title) {
            $iconHtml = if ($Icon) { '<i class="' + $Icon + '" style="color: ' + $IconColor + ';"></i> ' } else { '' }
            $OutputHTML.add('<div class="card-title-box"><div class="card-title" >' + $iconHtml + $Title + '</div>')
            if ($TitleLink) {
                $OutputHTML.add('<div class="card-link-box"><a href="' + $TitleLink + '" target="_blank" class="card-link" ><i class="fas fa-arrow-up-right-from-square" style="color: #337ab7;"></i></a></div>')
            }
            $OutputHTML.add('</div>')
        }
        $OutputHTML.add('<div class="card-body" >')
        $OutputHTML.add('<p class="card-text" >' + $Body + '</p>')
        $OutputHTML.add('</div></div>')
        return $OutputHTML -join ''
    }
    
    # Helper function: Write a value to a NinjaRMM text custom field
    function Invoke-NinjaPropertySet {
        param(
            [string]$FieldName,
            [string]$Value
        )
        $NinjaPropertyCommand = 'Ninja-Property-Set'
        if (-not (Get-Command $NinjaPropertyCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPropertyCommand' not found; cannot update field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            try {
                Ninja-Property-Set -Name $FieldName -Value $Value | Out-Null
            }
            catch {
                Ninja-Property-Set $FieldName $Value | Out-Null
            }
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Write HTML to a NinjaRMM WYSIWYG custom field via piped input
    function Invoke-NinjaPropertySetPiped {
        param(
            [string]$FieldName,
            [string]$Html
        )
        $NinjaPipedCommand = 'Ninja-Property-Set-Piped'
        if (-not (Get-Command $NinjaPipedCommand -ErrorAction SilentlyContinue)) {
            Write-Log "WARNING" "'$NinjaPipedCommand' not found; cannot update WYSIWYG field '$FieldName'."
            return
        }
        $oldInfoPref    = $InformationPreference
        $oldVerbosePref = $VerbosePreference
        try {
            $InformationPreference = 'SilentlyContinue'
            $VerbosePreference     = 'SilentlyContinue'
            $Html | Ninja-Property-Set-Piped -Name $FieldName
        }
        finally {
            $InformationPreference = $oldInfoPref
            $VerbosePreference     = $oldVerbosePref
        }
    }
    
    # Helper function: Calculate spill risk factor based on beverage type and system orientation
    function Get-SpillRiskAssessment {
        param (
            [string]$BeverageType,
            [string]$ChassisType
        )
        
        # OSHA Beverage Density Risk Matrix (totally real standard)
        $riskFactors = @{
            "Coffee"      = @{ Risk = "CRITICAL"; Factor = 0.94; Note = "Hot liquid - thermal hazard to motherboard components" }
            "Tea"         = @{ Risk = "HIGH";     Factor = 0.87; Note = "Hot liquid - Earl Grey particularly corrosive to PCB traces" }
            "Water"       = @{ Risk = "MODERATE"; Factor = 0.52; Note = "Conductive liquid - direct short-circuit risk" }
            "Soda"        = @{ Risk = "HIGH";     Factor = 0.89; Note = "Carbonated + sugar - sticky residue on drive laser lens" }
            "Energy Drink" = @{ Risk = "EXTREME";  Factor = 0.99; Note = "Taurine reacts with thermal paste; warranty voided on contact" }
            "Unknown"     = @{ Risk = "UNKNOWN";  Factor = 0.50; Note = "Unidentified beverage - Schrodinger's spill risk" }
        }
        
        $assessment = $riskFactors[$BeverageType]
        
        # Chassis modifier: laptops have higher spill risk due to tray angle
        if ($ChassisType -match "Notebook|Laptop|Portable") {
            $assessment.Factor = [Math]::Min(1.0, $assessment.Factor + 0.15)
            $assessment.Note += " | LAPTOP DETECTED: Tray angle increases spill probability by 15%"
        }
        
        return $assessment
    }
    
    # Helper function: Enumerate optical drive hardware
    function Get-OpticalDriveInventory {
        Write-Log "INFO" "Enumerating optical drive subsystem..."
        
        $drives = Get-CimInstance -ClassName Win32_CDROMDrive -ErrorAction SilentlyContinue
        
        if (-not $drives -or $drives.Count -eq 0) {
            Write-Log "WARNING" "No optical drive hardware detected"
            Write-Log "INFO" "Recommendation: Deploy USB-powered beverage warming device as alternative"
            return $null
        }
        
        foreach ($drive in $drives) {
            Write-Log "INFO" "Found optical drive: $($drive.Name)"
            Write-Log "INFO" "  Drive letter: $($drive.Drive)"
            Write-Log "INFO" "  Media loaded: $($drive.MediaLoaded)"
            Write-Log "INFO" "  Manufacturer: $($drive.Manufacturer)"
            Write-Log "INFO" "  Cup holder weight capacity: ~120g (estimated from tray plastic density)"
        }
        
        return $drives
    }
    
    # Helper function: Determine chassis type for spill risk calculation
    function Get-ChassisInfo {
        $chassis = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
        $chassisTypes = @{
            1 = "Other"; 2 = "Unknown"; 3 = "Desktop"; 4 = "Low Profile Desktop"
            5 = "Pizza Box"; 6 = "Mini Tower"; 7 = "Tower"; 8 = "Portable"
            9 = "Laptop"; 10 = "Notebook"; 11 = "Hand Held"; 12 = "Docking Station"
            13 = "All in One"; 14 = "Sub Notebook"; 15 = "Space-Saving"
            16 = "Lunch Box"; 17 = "Main System Chassis"; 18 = "Expansion Chassis"
            19 = "SubChassis"; 20 = "Bus Expansion Chassis"; 21 = "Peripheral Chassis"
            22 = "Storage Chassis"; 23 = "Rack Mount Chassis"; 24 = "Sealed-Case PC"
        }
        
        $typeId = if ($chassis.ChassisTypes) { $chassis.ChassisTypes[0] } else { 2 }
        $typeName = if ($chassisTypes.ContainsKey([int]$typeId)) { $chassisTypes[[int]$typeId] } else { "Unknown" }
        
        Write-Log "INFO" "Chassis type: $typeName (ID: $typeId)"
        
        # Special commentary for certain chassis types
        if ($typeId -eq 5) {
            Write-Log "WARNING" "Pizza Box chassis detected - do NOT place actual pizza on the cup holder"
        }
        if ($typeId -eq 16) {
            Write-Log "INFO" "Lunch Box chassis detected - ironically, lunch should not be stored in the drive bay"
        }
        
        return $typeName
    }
}

# =========================================
# PROCESS Block: Cup Holder Operations
# =========================================
process {
    Write-Log "INFO" "=== Cup Holder Management System v1.0 ==="
    Write-Log "INFO" "Operation requested: $Action"
    Write-Log "INFO" "Declared beverage: $BeverageType"
    Write-Log "INFO" ""
    
    # ─── Phase 1: Hardware Enumeration ───
    Write-Log "INFO" "─── Phase 1: Hardware Enumeration ───"
    
    $chassisType = Get-ChassisInfo
    $drives = Get-OpticalDriveInventory
    
    # Determine system manufacturer for cup holder compatibility database
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $manufacturer = if ($computerSystem.Manufacturer) { $computerSystem.Manufacturer } else { "Unknown" }
    $model = if ($computerSystem.Model) { $computerSystem.Model } else { "Unknown" }
    Write-Log "INFO" "System: $manufacturer $model"
    
    if (-not $drives) {
        # No optical drive - Not Applicable state
        $status       = "Not Applicable"
        $statusIcon   = "fas fa-times-circle"
        $iconColor    = "#888888"
        $statusDetail = "No optical drive detected. This system lacks cup holder hardware. Consider requisitioning a USB cup warmer (IT Asset Request Form 27-B/6)."
        
        Write-Log "WARNING" $statusDetail
    }
    else {
        # ─── Phase 2: Pre-Operation Safety Checks ───
        Write-Log "INFO" ""
        Write-Log "INFO" "─── Phase 2: OSHA Beverage Safety Assessment ───"
        
        $spillRisk = Get-SpillRiskAssessment -BeverageType $BeverageType -ChassisType $chassisType
        Write-Log "INFO" "Spill risk level: $($spillRisk.Risk) (factor: $($spillRisk.Factor))"
        Write-Log "INFO" "Risk notes: $($spillRisk.Note)"
        
        if ($spillRisk.Risk -eq "EXTREME") {
            Write-Log "WARNING" "EXTREME spill risk detected! Proceeding anyway because you're an adult."
            Write-Log "WARNING" "IT Department disclaims all liability for taurine-induced hardware damage."
        }
        
        # Check for media in drive
        $primaryDrive = $drives | Select-Object -First 1
        $mediaPresent = $primaryDrive.MediaLoaded
        
        if ($mediaPresent) {
            $status       = "In Use"
            $statusIcon   = "fas fa-compact-disc"
            $iconColor    = "#FF8C00"
            $statusDetail = "Optical media detected in drive $($primaryDrive.Drive). Cannot deploy cup holder while disc is present. Please remove the disc and try again. Do NOT place beverage on top of disc."
            
            Write-Log "WARNING" $statusDetail
        }
        else {
            # ─── Phase 3: Cup Holder Operation ───
            Write-Log "INFO" ""
            Write-Log "INFO" "─── Phase 3: Cup Holder $Action Operation ───"
            
            $driveLetter = $primaryDrive.Drive
            
            try {
                # Create Shell.Application COM object for tray control
                $shell = New-Object -ComObject Shell.Application
                
                if ($Action -eq "Deploy") {
                    Write-Log "INFO" "Initiating cup holder deployment sequence..."
                    Write-Log "INFO" "Sending eject command to drive $driveLetter..."
                    
                    # The namespace(17) is the "My Computer" namespace; items are the drives
                    $driveNamespace = $shell.Namespace(17)
                    $driveItem = $driveNamespace.ParseName($driveLetter)
                    
                    if ($driveItem) {
                        # InvokeVerb("Eject") opens the tray
                        $driveItem.InvokeVerb("Eject")
                        
                        Start-Sleep -Milliseconds 1500
                        
                        $status       = "Deployed"
                        $statusIcon   = "fas fa-mug-hot"
                        $iconColor    = "#28A745"
                        $statusDetail = "Cup holder deployed successfully on drive $driveLetter. Beverage placement authorized. Max recommended capacity: 350mL / 12oz. Do not exceed tray weight limit."
                        
                        Write-Log "INFO" "Cup holder deployed successfully"
                        Write-Log "INFO" "Beverage type '$BeverageType' cleared for placement"
                        Write-Log "INFO" "REMINDER: This is a SINGLE-cup holder. Stacking is not supported."
                    }
                    else {
                        $status       = "Action Required"
                        $statusIcon   = "fas fa-exclamation-triangle"
                        $iconColor    = "#DC3545"
                        $statusDetail = "Failed to locate drive $driveLetter in shell namespace. Drive may be jammed or disconnected. Try manual tray release (paperclip in pinhole)."
                        
                        Write-Log "ERROR" "Could not access drive object for $driveLetter"
                    }
                }
                else {
                    # Retract operation
                    Write-Log "INFO" "Initiating cup holder retraction sequence..."
                    Write-Log "WARNING" "ENSURE BEVERAGE HAS BEEN REMOVED BEFORE RETRACTION"
                    Write-Log "INFO" "Waiting 3 seconds for beverage removal compliance..."
                    
                    Start-Sleep -Seconds 3
                    
                    Write-Log "INFO" "Sending close command to drive $driveLetter..."
                    
                    # Use WMPlayer COM to close the tray (Shell.Application can only eject)
                    try {
                        $wmPlayer = New-Object -ComObject WMPlayer.OCX
                        $wmPlayer.CdromCollection.Item(0).Eject()   # Toggle: if open, this closes it
                        
                        Start-Sleep -Milliseconds 1500
                        
                        # Release COM object
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wmPlayer) | Out-Null
                        
                        $status       = "Retracted"
                        $statusIcon   = "fas fa-check-circle"
                        $iconColor    = "#28A745"
                        $statusDetail = "Cup holder retracted successfully. Beverage containment platform stowed. Drive $driveLetter returned to optical media standby mode."
                        
                        Write-Log "INFO" "Cup holder retracted successfully"
                        Write-Log "INFO" "Drive returned to normal optical media operations"
                    }
                    catch {
                        Write-Log "WARNING" "WMPlayer method failed: $($_.Exception.Message)"
                        Write-Log "INFO" "Attempting fallback retraction via Shell namespace..."
                        
                        # Fallback: Shell eject toggles the tray
                        $driveNamespace = $shell.Namespace(17)
                        $driveItem = $driveNamespace.ParseName($driveLetter)
                        if ($driveItem) {
                            $driveItem.InvokeVerb("Eject")
                            Start-Sleep -Milliseconds 1500
                        }
                        
                        $status       = "Retracted"
                        $statusIcon   = "fas fa-check-circle"
                        $iconColor    = "#28A745"
                        $statusDetail = "Cup holder retracted via fallback method. If tray toggled open instead, run retraction again."
                        
                        Write-Log "INFO" "Fallback retraction executed"
                    }
                }
                
                # Release Shell COM object
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
            }
            catch {
                $status       = "Action Required"
                $statusIcon   = "fas fa-exclamation-triangle"
                $iconColor    = "#DC3545"
                $statusDetail = "Cup holder operation failed: $($_.Exception.Message). Manual intervention required. Locate the emergency tray release pinhole on the drive faceplate."
                
                Write-Log "ERROR" "Operation failed: $($_.Exception.Message)"
            }
        }
    }
    
    # ─── Phase 4: Telemetry & Reporting ───
    Write-Log "INFO" ""
    Write-Log "INFO" "─── Phase 4: Status Reporting ───"
    Write-Log "INFO" "Final status: $status"
    
    # Build plain-text summary
    $plainTextLines = @(
        "Cup Holder Status: $status"
        "Action: $Action"
        "Beverage: $BeverageType"
        "Detail: $statusDetail"
        "System: $manufacturer $model"
        "Chassis: $chassisType"
    )
    
    if ($spillRisk) {
        $plainTextLines += "Spill Risk: $($spillRisk.Risk) ($($spillRisk.Factor))"
    }
    
    $plainText = $plainTextLines -join "`n"
    Write-Log "INFO" "Plain-text summary prepared ($($plainText.Length) chars)"
    
    # Build HTML status card data
    $cardData = [PSCustomObject]@{
        "Status"        = $status
        "Operation"     = $Action
        "Beverage"      = $BeverageType
        "Detail"        = $statusDetail
        "System"        = "$manufacturer $model"
        "Chassis Type"  = $chassisType
    }
    
    if ($spillRisk) {
        $cardData | Add-Member -NotePropertyName "Spill Risk" -NotePropertyValue "$($spillRisk.Risk) (Factor: $($spillRisk.Factor))"
    }
    
    $backgroundGradient = if ($CardBackgroundGradient -eq "Default") { "white" } else { $CardBackgroundGradient }
    
    $statusCard = Get-NinjaOneInfoCard `
        -Title $CardTitle `
        -Data $cardData `
        -Icon $statusIcon `
        -BackgroundGradient $backgroundGradient `
        -BorderRadius $CardBorderRadius `
        -IconColor $iconColor
    
    Write-Log "INFO" "HTML status card generated"
}

# =========================================
# END Block: Output & Field Updates
# =========================================
end {
    # Update NinjaRMM custom fields
    Write-Log "INFO" ""
    Write-Log "INFO" "─── Updating NinjaRMM Fields ───"
    
    Invoke-NinjaPropertySet -FieldName $PlainTextFieldName -Value $plainText
    Invoke-NinjaPropertySetPiped -FieldName $StatusCardFieldName -Html $statusCard
    
    # Output summary to console
    Write-Host ""
    Write-Host "============================================"
    Write-Host "  CUP HOLDER OPERATION COMPLETE"
    Write-Host "============================================"
    Write-Host "  Status:    $status"
    Write-Host "  Action:    $Action"
    Write-Host "  Beverage:  $BeverageType"
    if ($spillRisk) {
        Write-Host "  Spill Risk: $($spillRisk.Risk)"
    }
    Write-Host "============================================"
    Write-Host ""
    
    if ($status -eq "Deployed") {
        Write-Host "  Please enjoy your beverage responsibly."
        Write-Host "  This cup holder is rated for single-use beverages only."
        Write-Host "  For dual-cup support, install a second optical drive."
        Write-Host ""
    }
    
    if ($status -eq "Not Applicable") {
        Write-Host "  Your system does not support cup holder operations."
        Write-Host "  Modern thin-and-light laptops have eliminated this"
        Write-Host "  critical productivity feature. Please file a complaint"
        Write-Host "  with your hardware vendor."
        Write-Host ""
    }
    
    Write-Log "INFO" "Cup Holder Management System completed"
    exit 0
}
