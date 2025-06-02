#Requires -Version 5.1
<#
    === Created by Sam ===
    
    Last Edit: 04-17-2025
    Added: General improvements and enhancements
    
    Thanks to Mat Dew in the NinjaOne Discord for the base script.
#>

<#
.SYNOPSIS
    Retrieve OneDrive and folder redirection information and update NinjaRMM custom field.

.DESCRIPTION
    This script retrieves information about folder redirection and OneDrive sync status,
    generates HTML cards with the information, and updates a NinjaRMM custom field.
    It is designed to run on a schedule for monitoring purposes.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to C:\Logs\OneDrive\OneDriveInfo.log on the device.

.PARAMETER OneDriveSyncClientFieldName
    The name of the NinjaRMM custom field to update with OneDrive sync information.
    Defaults to the value of the environment variable $env:oneDriveSyncClientFieldName if set,
    otherwise defaults to "onedriveSyncClient".
#>

[CmdletBinding()]
param(
    # Individual switch      Ninja Vairable Resolution                                                    Fallback
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }), # Ninja Script Variable; Checkbox

    # Ninja custom field names          Ninja Variable Resolution                                                    Fallback
    [string]$OneDriveWYSIWYGCustomField = $(if ($env:onedriveWysiwygCustomField) { $env:onedriveWysiwygCustomField } else { "OneDriveStatusCard" }), # Optional Ninja Script Variable - String
    
    # Card customization options
    [string]$CardTitle = "OneDrive Config Details", # Default Card title
    [string]$CardIcon = "fas fa-cloud",             # Default Card icon (Ninja uses font awesome)
    [string]$CardBackgroundGradient = "Default",    # Gradiant not supported with Ninja. 'Default' omitts the style.
    [string]$CardBorderRadius = "10px",             # Default Card border radius
    [string]$CardIconColor = "#0364b8"              # Default Card Icon color
)

# =========================================
# BEGIN Block: Initialization & Validation
# =========================================
begin {
    
    # Track initial Nuget install state for future use and cleanup
    $NuGetAlreadyInstalled = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    
    # Define helper function to create an info card with structured data and icon color
    function Get-NinjaOneInfoCard($Title, $Data, [string]$Icon, [string]$TitleLink, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor = "#000000") {
        <#
        .SYNOPSIS
            Creates an info card for display in NinjaRMM with customizable background gradient, border radius, and icon color.
        
        .DESCRIPTION
            Generates an HTML string for an info card displaying structured data with customizable styles and icon color.
        #>
        [System.Collections.Generic.List[String]]$ItemsHTML = @()
        foreach ($Item in $Data.PSObject.Properties) {
            $ItemsHTML.add('<p ><b >' + $Item.Name + '</b><br />' + $Item.Value + '</p>')
        }
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor
    }
    
    # Helper function to generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor) {
        <#
        .SYNOPSIS
            Creates an HTML card for display in NinjaRMM with customizable background gradient, border radius, and icon color.
        
        .DESCRIPTION
            Generates an HTML string representing a card with a title, body, optional icon with color, title link, additional classes, background gradient, and border radius.
        #>
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background-color: $BackgroundGradient; border-radius: $BorderRadius;"
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
    
    # Define logging function for consistent output and optional file logging
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        # Output log message to console
        Write-Host "[$Level] $Message"
        
        # Save log message to file if enabled
        if ($SaveLogToDevice) {
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            $logDir = "C:\Logs\OneDrive"
            $logFile = Join-Path $logDir "OneDriveInfo.log"
            
            # Create log directory if it doesn’t exist
            if (-not (Test-Path $logDir)) {
                try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
                catch {
                
                }
            }
            
            # Add daily header to log file if not present
            $today = Get-Date -Format 'yyyy-MM-dd'
            $header = "=== $today ==="
            $existingContent = if (Test-Path $logFile) { Get-Content $logFile -Raw } else { "" }
            if (-not $existingContent -or -not ($existingContent -match [regex]::Escape($header))) {
                Add-Content -Path $logFile -Value "`r`n$header"
            }
            
            Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
        }
    }
    
    # Define cleanup function to remove temporary files and modules
    function Clean-Up {
        <#
        .SYNOPSIS
            Cleans up temporary files and installed modules.
            
        .DESCRIPTION
            Removes temporary JSON files and the RunAsUser module if it was installed by the script.
        #>
        # Remove temporary JSON files
        $tempFiles = @('C:\temp\folderredirectionstatus.json', 'C:\temp\OneDriveLibraries.json')
        foreach ($file in $tempFiles) {
            if (Test-Path $file) {
                try {
                    Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                    Write-Log "INFO" "Removed temporary file: $file"
                }
                catch {
                    Write-Log "WARNING" "Failed to remove temporary file ${file}: $_"
                }
            }
        }
        
        # Remove RunAsUser module if installed
        if (Get-Module -Name RunAsUser -ErrorAction SilentlyContinue) {
            try {
                Remove-Module -Name RunAsUser -Force -ErrorAction Stop
                Write-Log "INFO" "Removed RunAsUser module"
            }
            catch {
                Write-Log "WARNING" "Failed to remove RunAsUser module: $_"
            }
        }
    }
    
    Write-Log "INFO" "Starting OneDrive and folder redirection information retrieval"
    Write-Log "INFO" "Using custom field name: $OneDriveWYSIWYGCustomField"
}

# =========================================
# PROCESS Block: Retrieve and Process Information
# =========================================
process {
    try {
        # Check and install Nuget provider dependency if not present
        if (-not $NuGetAlreadyInstalled) {
            Write-Log "INFO" "Installing NuGet provider"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        }
        # Check and install RunAsUser module if not present
        if (-not (Get-Command Invoke-AsCurrentUser -ErrorAction SilentlyContinue)) {
            Write-Log "INFO" "Installing RunAsUser module"
            Install-Module -Name RunAsUser -Confirm:$false -Force -ErrorAction Stop
        }
        
        # Define script block to run as current user
        $ScriptBlock = {
            Function Get-FolderRedirectionStatus {
                # Get current user and SID
                $User = whoami
                $SID = $user | ForEach-Object { ([System.Security.Principal.NTAccount]$_).Translate([System.Security.Principal.SecurityIdentifier]).Value }
                $UserProfile = (Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object SID -EQ $SID)
                $UserFolders = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\' -ErrorAction Stop | Select-Object 'Personal', 'My Video', 'My Pictures', 'Desktop', 'Favorites', 'My Music'
                
                # Define OneDrive constants
                $typeOneDrive = 'Business1'
                $warningFileSyncedDelayHours = 72                       
                $statusOneDriveUpToDate = 16777216, 42, 0     # Up-to-date statuses
                $statusOneDrivePaused = 65536                 # Paused status
                $statusOneDriveNotSyncing = 8194              # Not syncing status
                $statusOneDriveSyncingProblems = 1854         # Syncing problems status
                
                # Helper function to convert status codes to readable names
                Function Convert-ResultCodeToName {
                    param([Parameter(Mandatory = $true)][int] $status)
                    switch ($status) {
                        { ($statusOneDriveUpToDate.Contains($_)) } { 'Up-to-Date' }
                        $statusOneDrivePaused { 'Paused - Might be Syncing' }
                        $statusOneDriveNotSyncing { 'Not syncing' }
                        $statusOneDriveSyncingProblems { 'Having syncing problems' }
                        default { "Unknown - ($status)" }
                    }
                }
                
                # Retrieve OneDrive sync log data
                $folderMask = "$env:localAppData\Microsoft\OneDrive\logs\" + $typeOneDrive + '\*.log'  
                $files = Get-ChildItem -Path $folderMask -Filter SyncDiagnostics.log | Where-Object { $_.LastWriteTime -gt [datetime]::Now.AddMinutes(-1440) }
                $progressState = Get-Content $files | Where-Object { $_.Contains('SyncProgressState') } 
                $checkLogDate = Get-Content $files | Where-Object { $_.Contains('UtcNow:') }  
                
                # Parse sync status
                $status = $progressState | ForEach-Object { -split $_ | Select-Object -Index 1 }
                $resultText = Convert-ResultCodeToName $status
                
                # Determine if OneDrive is actively syncing
                $state = ($progressState -match 16777216) -or ($progressState -match 42) -or ($progressState -match 0) 
                
                # Parse last sync time
                $rawLogDate = $checkLogDate | ForEach-Object { -split $_ | Select-Object -Index 1 }
                $convertLogDate = $rawLogDate -as [DateTime]
                $utcLogDate = $convertLogDate.ToUniversalTime()
                $timezone = [System.TimeZoneInfo]::Local.DisplayName
                
                # Calculate time since last sync
                $dateNow = Get-Date
                $utcNow = $dateNow.ToUniversalTime()
                $timeSpan = New-TimeSpan -Start $utcLogDate -End $utcNow
                $difference = $timeSpan.hours
                $results = @{}
                $results.StatusCode = $status
                $results.LastSynced = $convertLogDate
                
                # Determine sync health based on state and time difference
                try {
                    if ($state -eq $true -and $difference -le $warningFileSyncedDelayHours) {
                        $results.SyncHealth = "$resultText"
                    } 
                    elseif ($state -eq $true -and $difference -gt $warningFileSyncedDelayHours) {
                        $results.SyncHealth = "$resultText (Onedrive appears active but no files synced in $difference hours)"
                    } 
                    elseif ($progressState -eq $statusOneDrivePaused -and $difference -le $warningFileSyncedDelayHours) {
                        $results.SyncHealth = "$resultText (User logged in | OneDrive paused | Synced $difference hours ago)"
                    }
                    elseif ($progressState -eq $statusOneDrivePaused -and $difference -gt $warningFileSyncedDelayHours) {
                        $results.SyncHealth = "$resultText (User logged in | OneDrive paused | Synced $difference hours ago)"
                    }
                    elseif ($state -eq $false) {
                        $results.SyncHealth = "OneDrive Not Syncing or Signed In"
                    }
                    else {
                        $results.SyncHealth = "$resultText ($status | Synced $difference hours ago)"
                    }
                }
                catch {
                    $results.SyncHealth = "Error: $($_.Exception.Message)"
                }
                
                # Return collected data as PSCustomObject
                return [pscustomobject] @{ 
                    User                = $user 
                    # SID                 = $SID 
                    # Computer            = $env:COMPUTERNAME
                    'Sync Health'          = $results.SyncHealth
                    'Last Synced'          = If ($convertLogDate) {"$($convertLogDate) $($timezone)"} else {'Never'}
                    'Desktop Redirected'   = $UserProfile.Desktop.Redirected -or $UserFolders.Desktop -match 'OneDrive'
                    'Documents Redirected' = $UserProfile.documents.redirected -or $UserFolders.Personal -match 'OneDrive'
                    'Pictures Redirected'  = $UserProfile.Pictures.redirected -or $UserFolders.'My Pictures' -match 'OneDrive'
                    'Documents Path'       = $UserFolders.Personal
                    'Videos Path'          = $UserFolders.'My Video'
                    'Pictures Path'        = $UserFolders.'My Pictures'
                    'Music Path'           = $UserFolders.'My Music'
                    'Desktop Path'         = $UserFolders.Desktop
                    'Favorites Path'       = $UserFolders.Favorites
                }
            }
            
            # Save folder redirection status to JSON
            Get-FolderRedirectionStatus | ConvertTo-Json | Out-File 'c:\temp\folderredirectionstatus.json'
            
            # Check for synced SharePoint libraries
            $IniFiles = Get-ChildItem "$ENV:LOCALAPPDATA\Microsoft\OneDrive\settings\Business1" -Filter 'ClientPolicy*' -ErrorAction SilentlyContinue
            if (!$IniFiles) {
                'No Sharepoint Libraries synced.' | ConvertTo-Json | Out-File 'C:\temp\OneDriveLibraries.json'
                exit 1
            }
            
            # Gather OneDrive provider data
            $OneDriveProviders = Get-ChildItem -Path 'HKCU:\Software\SyncEngines\Providers\OneDrive' | ForEach-Object { Get-ItemProperty $_.PSpath }
            $LatestProviders = $OneDriveProviders | Group-Object -Property MountPoint | ForEach-Object {
                $_.Group | Sort-Object -Property LastModifiedTime -Descending | Select-Object -First 1
            }
            $AllMountPoints = $LatestProviders.MountPoint
            
            # Process synced libraries
            $SyncedLibraries = foreach ($inifile in $IniFiles) {
                $IniContent = Get-Content $inifile.fullname -Encoding Unicode
                $ItemCount = ($IniContent | Where-Object { $_ -like 'ItemCount*' }) -split '= ' | Select-Object -Last 1
                $URL = ($IniContent | Where-Object { $_ -like 'DavUrlNamespace*' }) -split '= ' | Select-Object -Last 1
                $Mountpoint = ($LatestProviders | Where-Object { $_.UrlNamespace -eq $URL }).MountPoint
                If (Test-Path $Mountpoint -ErrorAction SilentlyContinue) {
                    $FilteredItems = Get-ChildItem $Mountpoint -Attributes !SparseFile -Recurse | Where-Object {
                        # Exclude subfolders of other mount points
                        $file = $_.FullName | Out-String
                        $isSubfolder = $AllMountPoints | Where-Object { $file.StartsWith($_) -and $file -ne $_ -and $_ -ne $Mountpoint }
                        $isSubfolder.Count -eq 0
                    }
                    $diskUsage = $([math]::Truncate((($FilteredItems | Measure-Object -Property Length -Sum).Sum / 1GB * 100)) / 100)
                }
                [PSCustomObject]@{
                    'Site Name'       = ($IniContent | Where-Object { $_ -like 'SiteTitle*' }) -split '= ' | Select-Object -Last 1
                    'Site URL'        = $URL
                    'Local Disk Used' = If ($diskUsage) { "$diskUsage GB" } elseif ($diskUsage -eq 0) { '< 10 MB' } else { 'Err' }
                    'Item Count'      = $ItemCount
                }
            }
            $SyncedLibraries | ConvertTo-Json | Out-File 'C:\temp\OneDriveLibraries.json'
        }
        
        # Create temp directory for JSON files
        New-Item -ItemType Directory -Path 'C:\temp' -ErrorAction SilentlyContinue
        
        # Execute script block as current user
        $null = Invoke-AsCurrentUser -ScriptBlock $ScriptBlock -ErrorAction Stop
        
        # Read JSON data
        $frs = (Get-Content 'c:\temp\folderredirectionstatus.json' | ConvertFrom-Json)
        $SyncedLibraries = (Get-Content 'C:\temp\OneDriveLibraries.json' | ConvertFrom-Json)
        
        # Evaluate sync health
        if (($SyncedLibraries.'Item count' | Measure-Object -Sum).sum -gt '280000') {
            Write-Log "WARNING" "Unhealthy - Currently syncing more than 280k files. Please investigate."
        }
        elseif ($SyncedLibraries -eq 'No Sharepoint Libraries synced.') {
            Write-Log "INFO" "No Sharepoint Libraries found."
            $noSP = $true
        }
        else {
            Write-Log "INFO" "Healthy - Syncing less than 280k files, or none."
        }
        
        # Generate HTML cards for display
        if ($frs) {
            $ODHTML = (Get-NinjaOneInfoCard -Title $CardTitle -Data $frs -Icon $CardIcon -BackgroundGradient $CardBackgroundGradient -BorderRadius $CardBorderRadius -IconColor $CardIconColor) -replace 'True', '<i class="fas fa-check-circle" style="color:#26A644;"></i> True'
        }
        if ($SyncedLibraries -and -not $noSP) {
            $LibraryTableHTML = $SyncedLibraries | ConvertTo-Html -As Table -Fragment
            $LibraryHTML = Get-NinjaOneCard -Title 'Synced Libraries' -Body $LibraryTableHTML -Icon $CardIcon' style="color:#0364b8;'
        }
        
        # Combine cards into a responsive layout
        $CombinedHTML = '<div class="row g-1 rows-cols-2">' + 
                        '<div class="col-xl-4 col-lg-4 col-md-4 col-sm-4 d-flex">' + $ODHTML + 
                        '</div><div class="col-xl-8 col-lg-8 col-md-8 col-sm-8 d-flex">' + $LibraryHTML +
                        '</div></div>'
        
        # Set the custom field in NinjaRMM using the parameterized field name
        $CombinedHTML | Ninja-Property-Set-Piped -Name $OneDriveWYSIWYGCustomField
    }
    catch {
        Write-Log "ERROR" "An error occurred: $($_.Exception.Message)"
    }
}

# =========================================
# END Block: Finalization
# =========================================
end {
    # Perform cleanup of temporary files and modules
    Clean-Up
    
    Write-Log "INFO" "OneDrive and folder redirection information retrieval completed"
}