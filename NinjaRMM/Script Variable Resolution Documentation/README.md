# 🔧 NinjaRMM Variable Implementation for PowerShell

## 🧭 Purpose

> This README explains how NinjaRMM "script variables" (set in the RMM script automation) become temporary environment variables within a PowerShell script, and how to reference them correctly. You'll learn:

- How NinjaRMM variables map to `env:` variables in PowerShell
- How to define parameters that automatically pull from `env:` (with sensible default fallbacks)
- Examples for dropdown-style (ValidateSet) inputs, string inputs, and checkbox inputs

> **Note:** This focuses **only** on the mechanics of NinjaRMM variable resolution

---

## ⚙️ How NinjaRMM Script Variables Resolve

1. **"Script Variable" Name**
   - In the NinjaRMM automation script creation, you add a "Script Variable" and select the type, then give it a display name (e.g., `My Fancy Option`).
   - NinjaRMM automatically converts that display name into a temporary environment variable by removing spaces (and preserving case).
   - Example:
     - Script Variable Menu name: `Save Log To Device`
     - Resulting environment variable: `env:saveLogToDevice`

2. **PowerShell Access**  
   - Inside the PowerShell script, it should be referenced as `"$env:variableNameNoSpaces"`.  
   - If the automation script does not includes the variable (or left it completley empty), `$env:variableNameNoSpaces` will be null, resulting in the fallback value (which can be utilized in many cases such as custom fields, etc)

3. **Defaulting & Validation**  
   - To avoid "null or empty" values, wrap `$env:...` in an `if` check.
   - If it exists, use `"$env:..."`; otherwise, fall back to the hard-coded value.
   - For dropdowns (ValidateSet), fall back to one of the allowed values.
   - For checkboxes (boolean), convert `"0"`/`"1"` (or `"false"`/`"true"`) to `[bool]`, using a fallback if missing.

---

## 💡 Examples: Dropdown Input (ValidateSet), Checkbox (ConvertToBool), String/Text

Imagine you want a two-option dropdown called **`Example Dropdown`** (with options: `Allow`, `Deny`). In the Script Variable menu, you would label it "Example Dropdown," but the internal name (shown under the hood) is `exampleDropdown`, shown in the top right corner of the script variable menu. NinjaRMM creates an environment variable `env:exampleDropdown`.

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Script%20Variable%20Resolution%20Documentation/images/NinjaScriptVariableResolution.png" alt="Ninja Variable Resolution Preview" width="320px" />


```powershell
<#
.SYNOPSIS
  Examples of a parameters that reads from NinjaRMM script variables.
#>

param (
    # Dropdown Option                                      Ninja Variable Resolution                              Fallback
    [ValidateSet("Allow", "Deny")][string]$ExampleDropdown = $(if ($env:exampleDropdown) { $env:exampleDropdown } else { "Ensure" })

    # Checkbox Option        Ninja Variable Resolution               Converting Ninja Checkbox Binary to bool               Fallback
    [switch]$ExampleCheckbox = $(if ($env:useBitlockerTpmProtector) { [Convert]::ToBoolean($env:useBitlockerTpmProtector) } else { $true }),  # Ninja Script Variable; Checkbox

    # Custom field name       Ninja Variable Resolution                                            Fallback
    [String]$ExampleFieldName = $(if ($env:exampleSecureFieldName) { $env:exampleSecureFieldName } else { "ExampleSecureField" }) # Could be Static - Optional Ninja Script Variable; String
)
