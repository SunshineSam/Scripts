#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-21-2025
#>

<#
.SYNOPSIS
    Creates or updates a specified local administrator account with a randomized password,
    configurable behaviors, and writes that password into a named NinjaRMM secure field.
    Variables are handled with the shortest possible window, correct logic execution, and handling.

.DESCRIPTION
    This script manages a local administrator account according to these parameters:
      - AdminUsername (optional)
          Name of the admin account to create or update. Pulled from env if not passed.
      - PasswordSecureFieldName (optional)
          The NinjaRMM secure field name to write the password into. Pulled from env if not passed.
      - OverridePasswordForExistingAccount (optional)
          Force a password reset on existing account.
      - PasswordNeverExpires (optional)
          Mark account & password to never expire.
      - AddToAdministrators (optional)
          Add or remove from local Administrators group.
    
    Steps:
      1. Auto resolve AdminUsername and PasswordSecureFieldName from parameters or env.
      2. Validate required values and script elevation.
      3. Generate a strong random plaintext password for Ninja Secure Field Storage
      4. Convert to SecureString for account cmdlets.
      5. Create or update the local user.
      6. Immediatly handles plaintext and SecureString based on local account creation result (Store the plaintext password in NinjaRMM secure field on success)
      7. Apply behaviors:
           - Override password
           - Set never-expire flags
           - Add or remove Administrators membership
#>

[CmdletBinding()]
param(
    # String input         Ninja Variable Resolution                          Fallback
    [String]$AdminUsername = $(if ($env:adminUsername) { $env:adminUsername } else { "Admin" }), # Ninja Script Variable; String
    
    # Independent switches           Ninja Variable Resolution                                                                                          Fallback
    [Switch]$OverridePassword        = $(if ($env:overridePasswordForExistingAccount) { [Convert]::ToBoolean($env:overridePasswordForExistingAccount) } else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$PasswordNeverExpires    = $(if ($env:passwordNeverExpires) { [Convert]::ToBoolean($env:passwordNeverExpires) }                             else { $false }), # Ninja Script Variable; Checkbox
    [Switch]$AddToAdministrators     = $(if ($env:addToAdministrators) { [Convert]::ToBoolean($env:addToAdministrators) }                               else { $false }), # Ninja Script Variable; Checkbox
    
    # Ninja custom field names       Ninja Variable Resolution                                              Fallback
    [String]$PasswordSecureFieldName = $(if ($env:passwordSecureFieldName) { $env:passwordSecureFieldName } else { "LocalAdminPassword" }) # Static - Optional Ninja Script Variable; String
)

# ===========================================
# BEGIN Block: Parameter Resolution & Validation
# ===========================================
begin {
    
    Write-Host "[INFO] Using AdminUsername = '$AdminUsername'"
    
    # Ensure the script is running elevated
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    if (-not (Test-IsElevated)) {
        Write-Host "[ERROR] Script must be run as Administrator."
        exit 1
    }
    
    #----------------------------------------------------------------------------
    # Helper Function: Clear-Memory
    #   Securely clears sensitive variables from memory by nulling and removing them
    #   Accepts one or more variable names as strings
    #----------------------------------------------------------------------------
    function Clear-Memory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string[]]$VariableNames
        )
        
        foreach ($name in $VariableNames) {
            # Null out the variable
            Set-Variable -Name $name -Value $null -Scope Local -ErrorAction SilentlyContinue
            
            # Remove it entirely
            Clear-Variable -Name $name -Scope Local -ErrorAction SilentlyContinue
        }
        Write-Host "[INF] Cleared memory for password variables" #: $($VariableNames -join ', ')
    }

    # Helper function: add or remove account as a member of Administrator
    function Set-AdministratorsGroup {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string] $UserName,
            [Parameter(Mandatory)][switch] $AddToAdministrators
        )
        # Add to local 'Administrators' group
        if ($AddToAdministrators) {
            try {
                Add-LocalGroupMember -Group Administrators -Member $UserName -ErrorAction Stop
                Write-Host "[SUCCESS] Ensured '$UserName' is in Administrators."
            }
            catch {
                Write-Host "[WARNING] Could not add '$UserName' to Administrators: $_"
            }
        }
        # Remove from local 'Administrators' group
        else {
            try {
                if (Get-LocalGroupMember -Group Administrators -Member $UserName -ErrorAction SilentlyContinue) {
                    Remove-LocalGroupMember -Group Administrators -Member $UserName -ErrorAction Stop
                    Write-Host "[SUCCESS] Removed '$UserName' from Administrators."
                }
                else {
                    Write-Host "[INFO] '$UserName' was not in Administrators; nothing to do."
                }
            }
            catch {
                Write-Host "[WARNING] Failed to remove '$UserName' from Administrators: $_"
            }
        }
    }
}

# ===========================================
# PROCESS Block: Create or Update Account
# ===========================================
process {
    # Check for existing local user by name
    $Existing = Get-LocalUser -Name $AdminUsername -ErrorAction SilentlyContinue
    
    if (-not $Existing) {
        # Create new account
        Write-Host "[INFO] Creating user '$AdminUsername'..."
        
        # Generate a strong random plaintext password
        Add-Type -AssemblyName System.Web
        
        # Generate dynamic password length (14-18) and non-alphanumeric count (4-6)
        $PasswordLength = Get-Random -Minimum 14 -Maximum 18
        $NonAlphaCount  = Get-Random -Minimum 4 -Maximum 7
        
        # Generate password with randomized parameters
        $PlainPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $NonAlphaCount)
        
        # Convert plaintext to SecureString for use with New/Set-LocalUser
        $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
        
        try {
            $params = @{ Name = $AdminUsername; Password = $SecurePassword }
            if ($PasswordNeverExpires) {
                $params['PasswordNeverExpires'] = $true
                $params['AccountNeverExpires']   = $true
            }
            New-LocalUser @params -ErrorAction Stop
            Write-Host "[SUCCESS] '$AdminUsername' created."
        }
        catch {
            Write-Host "[ERROR] Failed to create '$AdminUsername': $_"
            # Clear plaintext and secure string variables from memory immediately on failure 
            Clear-Memory -VariableNames PlainPassword, SecurePassword
            exit 1
        }
        
        # Immediately store and clear the plaintext after success
        try {
            Ninja-Property-Set $PasswordSecureFieldName $PlainPassword | Out-Null
            Write-Host "[SUCCESS] Stored password in secure field '$PasswordSecureFieldName'."
        }
        # Clear password vars on failure and exit
        catch {
            Write-Host "[WARNING] Failed to set NinjaRMM secure field '$PasswordSecureFieldName': $_"
            Clear-Memory -VariableNames PlainPassword, SecurePassword
            exit 1
        }
        # Clear plaintext and secure string variables from memory immediately on success
        finally {
            Clear-Memory -VariableNames PlainPassword, SecurePassword
        }
        
        # Manage Administrators Group Membership
        Set-AdministratorsGroup -UserName $AdminUsername -AddToAdministrators:$AddToAdministrators
    }
    else {
        # Update existing account
        Write-Host "[INFO] User '$AdminUsername' already exists."
        
        # Password override
        if ($OverridePassword) {
            Write-Host "[INFO] Overriding password for '$AdminUsername'..."
            
            # Generate a strong random plaintext password
            Add-Type -AssemblyName System.Web
            
            # Generate dynamic password length (14-18) and non-alphanumeric count (4-6)
            $PasswordLength = Get-Random -Minimum 14 -Maximum 19
            $NonAlphaCount  = Get-Random -Minimum 4 -Maximum 7
            
            # Generate password with randomized parameters
            $PlainPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $NonAlphaCount)
            
            # Convert plaintext to SecureString for use with New/Set-LocalUser
            $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
            
            try {
                Set-LocalUser -Name $AdminUsername -Password $SecurePassword -ErrorAction Stop
                Write-Host "[SUCCESS] Password reset for '$AdminUsername'."
            }
            # Clear password vars on failure and exit
            catch {
                Write-Host "[ERROR] Failed to reset password: $_. Exiting execution."
                Clear-Memory -VariableNames PlainPassword, SecurePassword
                exit 1
            }
            # Clear plaintext and secure‑string variables from memory immediately after existing Account Password update
            finally {
                # Set Ninja secure field property and then clear mem
                Ninja-Property-Set $PasswordSecureFieldName $PlainPassword | Out-Null
                Write-Host "[SUCCESS] Stored password in secure field '$PasswordSecureFieldName'."
                
                Clear-Memory -VariableNames PlainPassword, SecurePassword
            }
        }
        else {
            Write-Host "[INFO] OverridePasswordForExistingAccount not set; skipping password reset."
        }
        
        # PasswordNeverExpires
        if ($PasswordNeverExpires) {
            try {
                Set-LocalUser -Name $AdminUsername `
                    -PasswordNeverExpires:$true `
                    -AccountNeverExpires:$true `
                    -ErrorAction Stop
                Write-Host "[INFO] Marked '$AdminUsername' password/account never expire."
            }
            catch {
                Write-Host "[WARNING] Could not set never-expire flags: $_"
            }
        }
        
        # Administrators group for existing account
        Set-AdministratorsGroup -UserName $AdminUsername -AddToAdministrators:$AddToAdministrators
    }
}

# ===========================================
# END Block: Completion
# ===========================================
end {
    
}