#Requires -Version 5.1

<#
    === Developed by Sam ===
    Last Edit: 05-18-2025
#>

<#
.SYNOPSIS
    Manage Windows content-delivery, Spotlight, and related suggestions for all users based on selected groups.

.DESCRIPTION
    Loads each user's NTUSER.DAT under HKU (and optionally the Default user hive) then manages registry-backed content-delivery and UI suggestions in these groups:
      - Welcome               : SubscribedContent-310093Enabled -> Control the "Welcome Experience" during occasional login that pushes tips/new-feature notifications
      - LockScreen            : SubscribedContent-338387Enabled, SubscribedContent-338389Enabled, RotatingLockScreenEnabled, RotatingLockScreenOverlayEnabled -> Control "Fun facts", "Ads", and Spotlight on the lock screen
      - Start                 : SubscribedContent-338388Enabled, SystemPaneSuggestionsEnabled -> Control Start menu app suggestions and suggestion pane
      - Settings              : SubscribedContent-338393Enabled, SubscribedContent-353696Enabled -> Settings app suggestions
      - Install               : SilentInstalledAppsEnabled -> Auto-install recommended apps
      - PreInstalledApps      : OemPreInstalledAppsEnabled, PreInstalledAppsEnabled, PreInstalledAppsEverEnabled -> Control OEM and preinstalled apps
      - Suggestions           : SubscribedContentEnabled, SoftLandingEnabled -> Control general suggested apps and Windows tips
      - SyncProviders         : SubscribedContent-280810Enabled, SubscribedContent-280811Enabled, ShowSyncProviderNotifications -> Control OneDrive sync provider notifications
      - WindowsInk            : SubscribedContent-280813Enabled, PenWorkspaceAppSuggestionsEnabled -> Control Windows Ink suggestions
      - Sharing               : SubscribedContent-280815Enabled -> Control sharing suggestions (e.g., Facebook, Instagram)
      - FeatureManagement     : FeatureManagementEnabled, SubscribedContent-310091Enabled, SubscribedContent-310092Enabled, SubscribedContent-338380Enabled -> Control feature management settings
      - Apps                  : SubscribedContent-314559Enabled, SubscribedContent-338381Enabled -> Control specific app suggestions (e.g., BingWeather, Candy Crush, Windows Maps)
      - People                : SubscribedContent-314563Enabled -> Control MyPeople suggested apps
      - Timeline              : SubscribedContent-353698Enabled -> Control timeline suggestions; This is the underlying stack in Task View (Win + Tab), and removed Suggested card.
      - Spotlight             : SubscribedContent-202914Enabled -> Additional Windows Spotlight control
      - BackgroundAccess      : Disabled (under BackgroundAccessApplications) -> Control ContentDeliveryManager background activity
      - DisableCDM            : ContentDeliveryAllowed -> DisableCDM content-delivery on/off switch
      - UserProfileEngagement : ScoobeSystemSettingEnabled -> "Get even more out of Windows" pop-ups in Settings
    
    Uses RegistryShouldBe to set each DWORD value based on the selected state ("Enabled" or "Disabled").

.PARAMETER WelcomeContent
    String:
      - "Enabled"  -> enable the Welcome group
      - "Disabled" -> disable the Welcome group

.PARAMETER LockScreenContent
    String:
      - "Enabled"  -> enable the LockScreen group
      - "Disabled" -> disable the LockScreen group

.PARAMETER StartContent
    String:
      - "Enabled"  -> enable the Start group
      - "Disabled" -> disable the Start group

.PARAMETER SettingsContent
    String:
      - "Enabled"  -> enable the Settings group
      - "Disabled" -> disable the Settings group

.PARAMETER InstallContent
    String:
      - "Enabled"  -> enable the Install group
      - "Disabled" -> disable the Install group

.PARAMETER PreInstalledAppsContent
    String:
      - "Enabled"  -> enable the PreInstalledApps group
      - "Disabled" -> disable the PreInstalledApps group

.PARAMETER SuggestionsContent
    String:
      - "Enabled"  -> enable the Suggestions group
      - "Disabled" -> disable the Suggestions group

.PARAMETER SyncProvidersContent
    String:
      - "Enabled"  -> enable the SyncProviders group
      - "Disabled" -> disable the SyncProviders group

.PARAMETER WindowsInkContent
    String:
      - "Enabled"  -> enable the WindowsInk group
      - "Disabled" -> disable the WindowsInk group

.PARAMETER SharingContent
    String:
      - "Enabled"  -> enable the Sharing group
      - "Disabled" -> disable the Sharing group

.PARAMETER FeatureManagementContent
    String:
      - "Enabled"  -> enable the FeatureManagement group
      - "Disabled" -> disable the FeatureManagement group

.PARAMETER AppsContent
    String:
      - "Enabled"  -> enable the Apps group
      - "Disabled" -> disable the Apps group

.PARAMETER PeopleContent
    String:
      - "Enabled"  -> enable the People group
      - "Disabled" -> disable the People group

.PARAMETER TimelineContent
    String:
      - "Enabled"  -> enable the Timeline group
      - "Disabled" -> disable the Timeline group

.PARAMETER SpotlightContent
    String:
      - "Enabled"  -> enable the Spotlight group
      - "Disabled" -> disable the Spotlight group

.PARAMETER BackgroundAccessContent
    String:
      - "Enabled"  -> enable the BackgroundAccess group
      - "Disabled" -> disable the BackgroundAccess group

.PARAMETER UserProfileEngagementContent
    String:
      - "Enabled"  -> enable the UserProfileEngagement group
      - "Disabled" -> disable the UserProfileEngagement group

.PARAMETER IncludeDefault
    Switch:
      - $true  -> also apply settings to the Default user hive  
      - $false -> skip the Default user hive

.PARAMETER DisableCDM
    Switch:
      - $true  -> disable the master content-delivery switch (all Sub IDs are Disabled with this)

.ENVIRONMENT VARIABLE
    includeDefaultHive               : 1/true to enable IncludeDefault; 0/false to disable  
    disableCDM                       : 1/true to enable DisableCDM; 0/false to disable  
    welcomeContent                   : "Enabled" or "Disabled" for Welcome group  
    lockScreenContent                : "Enabled" or "Disabled" for LockScreen group  
    startContent                     : "Enabled" or "Disabled" for Start group  
    settingsContent                  : "Enabled" or "Disabled" for Settings group  
    installContent                   : "Enabled" or "Disabled" for Install group  
    preInstalledAppsContent          : "Enabled" or "Disabled" for PreInstalledApps group  
    suggestionsContent               : "Enabled" or "Disabled" for Suggestions group  
    syncProvidersContent             : "Enabled" or "Disabled" for SyncProviders group  
    windowsInkContent                : "Enabled" or "Disabled" for WindowsInk group  
    sharingContent                   : "Enabled" or "Disabled" for Sharing group  
    featureManagementContent         : "Enabled" or "Disabled" for FeatureManagement group  
    appsContent                      : "Enabled" or "Disabled" for Apps group  
    peopleContent                    : "Enabled" or "Disabled" for People group  
    timelineContent                  : "Enabled" or "Disabled" for Timeline group  
    spotlightContent                 : "Enabled" or "Disabled" for Spotlight group  
    backgroundAccessContent          : "Enabled" or "Disabled" for BackgroundAccess group  
    userProfileEngagementContent     : "Enabled" or "Disabled" for UserProfileEngagement group  
#>

# Param names do matter here for logic. Please only modify env: strings
# Note: Anything being defined explicitly will set values
[CmdletBinding()]
param(
    # Main options                                  Ninja Variable Resolution                                                          Fallback
    [ValidateSet('Allow','Block')][string]$CDMState = $(if ($env:cdmState) { $env:cdmState }                                           else { $null }),  # Ninja Script Variable; Dropdown - Overides for all non-explicitly set CDM options; Fallback will cause failure
    [switch]$IncludeDefaultHive                     = $(if ($env:includeDefaultHive) { [Convert]::ToBoolean($env:includeDefaultHive) } else { $false }), # Ninja Script Variable; Checkbox
    [switch]$SaveLogToDevice                        = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) }       else { $true }),  # Ninja Script Variable; Checkbox

    # CDM only settings (CDMState overides when not explicitly set)      Ninja Variable Resolution                                                Fallback
    [ValidateSet('Enabled','Disabled')][string]$WelcomeContent           = $(if ($env:welcomeContent) { $env:welcomeContent }                     else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$LockScreenContent        = $(if ($env:lockScreenContent) { $env:lockScreenContent }               else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$StartContent             = $(if ($env:startContent) { $env:startContent }                         else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$SettingsContent          = $(if ($env:settingsContent) { $env:settingsContent }                   else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$InstallContent           = $(if ($env:installContent) { $env:installContent }                     else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$PreInstalledAppsContent  = $(if ($env:preInstalledAppsContent) { $env:preInstalledAppsContent }   else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$SuggestionsContent       = $(if ($env:suggestionsContent) { $env:suggestionsContent }             else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$FeatureManagementContent = $(if ($env:featureManagementContent) { $env:featureManagementContent } else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$AppsContent              = $(if ($env:appsContent) { $env:appsContent }                           else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$PeopleContent            = $(if ($env:peopleContent) { $env:peopleContent }                       else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$TimelineContent          = $(if ($env:timelineContent) { $env:timelineContent }                   else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$SpotlightContent         = $(if ($env:spotlightContent) { $env:spotlightContent }                 else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    
    # Mixed CDM + other hives.                                       Ninja Variable Resolution                                                    Fallback         Note: will only set the CDM options (CDMState overides when not explicitly set)
    [ValidateSet('Enabled','Disabled')][string]$SyncProvidersContent = $(if ($env:syncProvidersContent) { $env:syncProvidersContent }             else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$WindowsInkContent    = $(if ($env:windowsInkContent) { $env:windowsInkContent }                   else { $null }), # Static - Optional Ninja Script Variable; Dropdown
    
    # Non CDM settings                                                       Ninja Variable Resolution                                                        Fallback
    [ValidateSet('Enabled','Disabled')][string]$UserProfileEngagementContent = $(if ($env:userProfileEngagementContent) { $env:userProfileEngagementContent } else { $null }), # Ninja Script Variable; Dropdown - Removed quietly by microsoft for 23H2 and up... This will result in a single error if explicitley set on new versions.
    [ValidateSet('Enabled','Disabled')][string]$BackgroundAccessContent      = $(if ($env:backgroundAccessContent) { $env:backgroundAccessContent }           else { $null }), # Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$SyncProvidersExtrasContent   = $(if ($env:syncProvidersExtrasContent) { $env:syncProvidersExtrasContent }     else { $null }), # Ninja Script Variable; Dropdown
    [ValidateSet('Enabled','Disabled')][string]$WindowsInkExtrasContent      = $(if ($env:windowsInkExtrasContent) { $env:windowsInkExtrasContent }           else { $null })  # Ninja Script Variable; Dropdown
)

# =========================================
# BEGIN Block: Functions & Setup
# =========================================
begin {
    # Helper function: Ensure script runs elevated
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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
            $logDir = "$driveLetter`:\Logs\CDM"
            $logFile = Join-Path $logDir "CDMPreferences.log"
            
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
    
    # Helper function: Retrieve all user SIDs and their NTUSER hive paths
    function Get-UserHives {
        [CmdletBinding()]
        param(
            [ValidateSet('AzureAD','DomainAndLocal','All')][string]$Type = 'All'
        )
        
        # 1) Pick SID patterns for real accounts
        $patterns = switch ($Type) {
            'AzureAD'        { 'S-1-12-1-(\d+-?){4}$' }
            'DomainAndLocal' { 'S-1-5-21-(\d+-?){4}$' }
            'All'            { 'S-1-12-1-(\d+-?){4}$','S-1-5-21-(\d+-?){4}$' }
        }
        
        # 2) Enumerate live user hives
        $hives = foreach ($pat in $patterns) {
            Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
            Where-Object { $_.PSChildName -match $pat } |
            ForEach-Object {
                [PSCustomObject]@{
                    SID      = $_.PSChildName
                    HivePath = Join-Path $_.ProfileImagePath 'NTUSER.DAT'
                }
            }
        }
        
        # 3) Optionally tack on the Default User hive
        if ($IncludeDefaultHive) {
            $defaultPath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
            if (Test-Path $defaultPath) {
                $hives += [PSCustomObject]@{
                    SID      = 'DefaultUser'
                    HivePath = $defaultPath
                }
            }
            else {
                Write-Log "WARNING" "Default hive not found at $defaultPath"
            }
        }
        
        return $hives
    }
    
    # Helper function: Set or create a registry value, retrying until correct
    function RegistryShouldBe {
        param(
            [Parameter(Mandatory)][string]$KeyPath,
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$Value,
            [ValidateSet('DWord','String','ExpandString','MultiString','Binary','QWord')][string]$Type = 'DWord'
        )
        # Ensure the key exists before setting the property
        if (-not (Test-Path $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
        $attempt = 0
        do {
            $attempt++
            $current = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
            if ($current -ne $Value) {
                if ($null -eq $current) {
                    Write-Log "VERBOSE" "Creating $KeyPath\$Name = $Value"
                    New-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                }
                else {
                    #Write-Log "VERBOSE" "Updating $KeyPath\$Name from $current to $Value"
                    Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -Force
                }
            }
            Start-Sleep -Milliseconds 200
        }
        while (((Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue).$Name -ne $Value) -and ($attempt -lt 5))
        
        $final = (Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($final -eq $Value) {
            #Write-Log "VERBOSE" "$KeyPath\$Name confirmed $Value"
        }
        else {
            #Write-Log "WARNING" "$KeyPath\$Name failed to set to $Value"
        }
    }
    
    # Helper function: apply a "disable/enable" pass over one group of registry toggles
    function Apply-RegistryGroup {
        param(
            [Parameter(Mandatory)][string]     $RegRoot,     # e.g. "HKEY_USERS\$sid"
            [Parameter(Mandatory)][hashtable]  $Groups,      # e.g. $CDMOnly or $MixedCDM or $Other
            [Parameter(Mandatory)][string]     $GroupName,   # one key from $Groups.Keys
            [Parameter(Mandatory)][bool]       $ShouldDisable
        )
        
        foreach ($name in $Groups[$GroupName].Keys) {
            $info     = $Groups[$GroupName][$name]
            # Use Registry:: prefix with $RegRoot instead of HKU:\
            $fullPath = "Registry::$RegRoot\$($pathMap[$info.Path])"
            
            # Decide what to write based on ValueLogic:
            #  - 'DisableTo0':   when disabling -> 0, when enabling -> 1
            #  - 'EnableTo0':    when enabling  -> 0, when disabling-> 1
            switch ($info.ValueLogic) {
                'DisableTo0' {
                    if ($ShouldDisable) {
                        $value = '0'
                    }
                    else {
                        $value = '1'
                    }
                    RegistryShouldBe -KeyPath $fullPath -Name $name -Value $value
                }
                'EnableTo0' {
                    if ($ShouldDisable) {
                        $value = '1'
                    }
                    else {
                        $value = '0'
                    }
                    RegistryShouldBe -KeyPath $fullPath -Name $name -Value $value
                }
                default {
                    throw "Unknown ValueLogic '$($info.ValueLogic)' for key '$name'"
                }
            }
        }
    }
    
    # Expanded path mappings
    $pathMap = @{
        'ContentDeliveryManager'   = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        'UserProfileEngage'    = 'SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement' # Removed quietly by microsoft for 23H2 and up... This will result in a single error
        'PenWorkspace'             = 'SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace'
        'ExplorerAdvanced'         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        'BackgroundAccessApplications' = 'SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy'
    }
    
    # Key Groups (bucketed) - Registry groups and IDs
    $CDMOnly = @{
        'DisableCDM'     = @{ 'ContentDeliveryAllowed'                = @{ Path='ContentDeliveryManager'; Label='Allow content delivery';     ValueLogic='DisableTo0' } }
        'Welcome'        = @{ 'SubscribedContent-310093Enabled'       = @{ Path='ContentDeliveryManager'; Label='Welcome Experience';         ValueLogic='DisableTo0' } }
        'LockScreen'     = @{
            'SubscribedContent-338387Enabled'       = @{ Path='ContentDeliveryManager'; Label='Lock screen facts';         ValueLogic='DisableTo0' }
            'SubscribedContent-338389Enabled'       = @{ Path='ContentDeliveryManager'; Label='Lock screen ads';           ValueLogic='DisableTo0' }
            'RotatingLockScreenEnabled'             = @{ Path='ContentDeliveryManager'; Label='Spotlight rotation';        ValueLogic='DisableTo0' }
            'RotatingLockScreenOverlayEnabled'      = @{ Path='ContentDeliveryManager'; Label='Spotlight overlay';         ValueLogic='DisableTo0' }
        }
        'Start'          = @{ 
            'SubscribedContent-338388Enabled'       = @{ Path='ContentDeliveryManager'; Label='Start suggestions';         ValueLogic='DisableTo0' }
            'SystemPaneSuggestionsEnabled'          = @{ Path='ContentDeliveryManager'; Label='Start suggestion pane';     ValueLogic='DisableTo0' }
        }
        'Settings'       = @{
            'SubscribedContent-338393Enabled'       = @{ Path='ContentDeliveryManager'; Label='Settings suggestions';      ValueLogic='DisableTo0' }
            'SubscribedContent-353696Enabled'       = @{ Path='ContentDeliveryManager'; Label='Settings-General tips';     ValueLogic='DisableTo0' }
        }
        'Install'        = @{ 'SilentInstalledAppsEnabled'            = @{ Path='ContentDeliveryManager'; Label='Silent app installs';       ValueLogic='DisableTo0' } }
        'PreInstalledApps' = @{
            'OemPreInstalledAppsEnabled'            = @{ Path='ContentDeliveryManager'; Label='OEM pre-installs';          ValueLogic='DisableTo0' }
            'PreInstalledAppsEnabled'               = @{ Path='ContentDeliveryManager'; Label='Pre-installs';              ValueLogic='DisableTo0' }
            'PreInstalledAppsEverEnabled'           = @{ Path='ContentDeliveryManager'; Label='Ever pre-installs';         ValueLogic='DisableTo0' }
        }
        'Suggestions'    = @{
            'SubscribedContentEnabled'              = @{ Path='ContentDeliveryManager'; Label='Generic suggested apps';    ValueLogic='DisableTo0' }
            'SoftLandingEnabled'                    = @{ Path='ContentDeliveryManager'; Label='Tips about Windows';        ValueLogic='DisableTo0' }
        }
        'FeatureManagement' = @{
            'FeatureManagementEnabled'              = @{ Path='ContentDeliveryManager'; Label='Feature Management Master'; ValueLogic='DisableTo0' }
            'SubscribedContent-310091Enabled'       = @{ Path='ContentDeliveryManager'; Label='Feature Management ID1';    ValueLogic='DisableTo0' }
            'SubscribedContent-310092Enabled'       = @{ Path='ContentDeliveryManager'; Label='Feature Management ID2';    ValueLogic='DisableTo0' }
            'SubscribedContent-338380Enabled'       = @{ Path='ContentDeliveryManager'; Label='Feature Management ID3';    ValueLogic='DisableTo0' }
        }
        'Apps'           = @{
            'SubscribedContent-314559Enabled'       = @{ Path='ContentDeliveryManager'; Label='Bing & CandyCrush';         ValueLogic='DisableTo0' }
            'SubscribedContent-338381Enabled'       = @{ Path='ContentDeliveryManager'; Label='Windows Maps';              ValueLogic='DisableTo0' }
        }
        'People'         = @{ 'SubscribedContent-314563Enabled'       = @{ Path='ContentDeliveryManager'; Label='MyPeople suggestions';      ValueLogic='DisableTo0' } }
        'Timeline'       = @{ 'SubscribedContent-353698Enabled'       = @{ Path='ContentDeliveryManager'; Label='Timeline suggestions';      ValueLogic='DisableTo0' } }
        'Spotlight'      = @{ 'SubscribedContent-202914Enabled'       = @{ Path='ContentDeliveryManager'; Label='Extra Spotlight control';   ValueLogic='DisableTo0' } }
    }
    
    $MixedCDM = @{
        'SyncProviders' = @{
            'SubscribedContent-280810Enabled'       = @{ Path='ContentDeliveryManager'; Label='SyncProviders-generic';     ValueLogic='DisableTo0' }
            'SubscribedContent-280811Enabled'       = @{ Path='ContentDeliveryManager'; Label='SyncProviders-OneDrive';    ValueLogic='DisableTo0' }
        }
        'WindowsInk'    = @{
            'SubscribedContent-280813Enabled'       = @{ Path='ContentDeliveryManager'; Label='Ink tips & promos';         ValueLogic='DisableTo0' }
        }
    }
    
    $Other = @{
        'SyncProvidersExtras' = @{ 'ShowSyncProviderNotifications' = @{ Path='ExplorerAdvanced'; Label='Explorer sync prompts';           ValueLogic='DisableTo0' } }
        'WindowsInkExtras'    = @{ 'PenWorkspaceAppSuggestionsEnabled' = @{ Path='PenWorkspace'; Label='Ink Workspace suggestions';   ValueLogic='DisableTo0' } }
        'BackgroundAccess'    = @{ 'Disabled'                      = @{ Path='BackgroundAccessApplications'; Label='CDM background task'; ValueLogic='EnableTo0' } }
        'UserProfileEngagement' = @{ 'ScoobeSystemSettingEnabled'  = @{ Path='UserProfileEngage'; Label='Settings welcome pop-ups'; ValueLogic='DisableTo0' } }
    }
}

# =========================================
# PROCESS Block: Apply Settings
# =========================================
process {
    # Ensure elevation
    if (-not (Test-IsElevated)) {
        Write-Log "ERROR" "Administrator privileges are required."
        exit 1
    }
    
    # Load and configure each user hive
    $loaded = @()
    $hives = Get-UserHives
    foreach ($hive in $hives) {
        $sid = $hive.SID
        Write-Log "INFO" "Processing hive for $sid"
        $regRoot = "HKEY_USERS\$sid"
        if (-not (Test-Path "Registry::$regRoot")) {
            Write-Log "VERBOSE" "Loading hive from $($hive.HivePath)"
            reg.exe LOAD "HKEY_USERS\$sid" $hive.HivePath | Out-Null
            $loaded += $sid
        }
        
        if ($CDMState -eq "Block") {
            Write-Log "INFO" "Blocking all CDM options"
            # Disable master switch
            Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName 'DisableCDM' -ShouldDisable $true
            # Disable all CDMOnly groups
            $cdmOnlyGroups = $CDMOnly.Keys | Where-Object { $_ -ne 'DisableCDM' }
            foreach ($group in $cdmOnlyGroups) {
                Write-Log "INFO" "Applying $group with state: $state"
                Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName $group -ShouldDisable $true
            }
            # Disable all MixedCDM groups
            foreach ($group in $MixedCDM.Keys) {
                Write-Log "INFO" "Applying $group with state: $state"
                Apply-RegistryGroup -RegRoot $regRoot -Groups $MixedCDM -GroupName $group -ShouldDisable $true
            }
            # Check if any individual CDM parameters are provided and log a warning
            $allCdmGroups = $cdmOnlyGroups + $MixedCDM.Keys
            $cdmParams = $allCdmGroups | ForEach-Object { "${_}Content" }
            $providedCdmParams = @()
            foreach ($param in $cdmParams) {
                $paramValue = Get-Variable -Name $param -ValueOnly -ErrorAction SilentlyContinue
                if ($null -ne $paramValue) {
                    $providedCdmParams += $param
                }
            }
            if ($providedCdmParams) {
                Write-Log "WARNING" "Individual CDM parameters ($($providedCdmParams -join ', ')) are ignored because CDMState is 'Block'"
            }
        }
        elseif ($CDMState -eq "Allow") {
            Write-Log "INFO" "Allowing all CDM options"
            # Enable master switch
            Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName 'DisableCDM' -ShouldDisable $false
            # Handle CDMOnly groups
            $cdmOnlyGroups = $CDMOnly.Keys | Where-Object { $_ -ne 'DisableCDM' }
            foreach ($group in $cdmOnlyGroups) {
                $paramName = "${group}Content"
                $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
                if ($null -ne $paramValue) {
                    $state = $paramValue
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $group with state: $state (override)"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName $group -ShouldDisable $disable
                }
                else {
                    # Default to enable
                    Write-Log "INFO" "Applying $group with state: $state"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName $group -ShouldDisable $false
                }
            }
            # Handle MixedCDM groups
            foreach ($group in $MixedCDM.Keys) {
                $paramName = "${group}Content"
                $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
                if ($null -ne $paramValue) {
                    $state = $paramValue
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $group with state: $state (override)"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $MixedCDM -GroupName $group -ShouldDisable $disable
                }
                else {
                    # Default to enable
                    Write-Log "INFO" "Applying $group with state: $state"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $MixedCDM -GroupName $group -ShouldDisable $false
                }
            }
        }
        else {
            Write-Log "VERBOSE" "CDMState not set, applying individual CDM parameters if provided"
            # Apply individual CDMOnly groups if parameters provided
            $cdmOnlyGroups = $CDMOnly.Keys | Where-Object { $_ -ne 'DisableCDM' }
            foreach ($group in $cdmOnlyGroups) {
                $paramName = "${group}Content"
                $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
                if ($null -ne $paramValue) {
                    $state = $paramValue
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $group with state: $state (override)"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $CDMOnly -GroupName $group -ShouldDisable $disable
                }
                else {
                    Write-Log "VERBOSE" "Skipping $group (no value provided)"
                }
            }
            # Apply individual MixedCDM groups if parameters provided
            foreach ($group in $MixedCDM.Keys) {
                $paramName = "${group}Content"
                $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
                if ($null -ne $paramValue) {
                    $state = $paramValue
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $group with state: $state"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $MixedCDM -GroupName $group -ShouldDisable $disable
                }
                else {
                    Write-Log "VERBOSE" "Skipping $group (no value provided)"
                }
            }
        }
        
        ### Extras for Mixed CDM Groups (non-CDM)
        foreach ($extraGroup in @('SyncProvidersExtras', 'WindowsInkExtras')) {
            $paramName = "${extraGroup}Content"
            $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $paramValue) {
                $state = $paramValue
                if ($state -in @('Enabled', 'Disabled')) {
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $extraGroup with state: $state"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $Other -GroupName $extraGroup -ShouldDisable $disable
                }
            }
            else {
                Write-Log "VERBOSE" "Skipping $extraGroup (no value provided)"
            }
        }
        
        ### Non-CDM Groups (all others)
        foreach ($group in $Other.Keys | Where-Object { $_ -notlike '*Extras' }) {
            $paramName = "${group}Content"
            $paramValue = Get-Variable -Name $paramName -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $paramValue) {
                $state = $paramValue
                if ($state -in @('Enabled', 'Disabled')) {
                    $disable = ($state -eq 'Disabled')
                    Write-Log "INFO" "Applying $group with state: $state"
                    Apply-RegistryGroup -RegRoot $regRoot -Groups $Other -GroupName $group -ShouldDisable $disable
                }
            }
            else {
                Write-Log "VERBOSE" "Skipping $group (no value provided)"
            }
        }
        
        # Unload any hives that were loaded
        foreach ($sid in $loaded) {
            Start-Sleep -Milliseconds 200
            reg.exe UNLOAD "HKEY_USERS\$sid" | Out-Null
            Write-Log "VERBOSE" "Unloaded hive for $sid"
        }
    }
}

# =========================================
# END Block: Completion
# =========================================
end {
    Write-Log "INFO" "Content Delivery preferences complete."
}