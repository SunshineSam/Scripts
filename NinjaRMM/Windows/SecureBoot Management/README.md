# 🛡️ SecureBoot (CA 2023) Certificate - Complete Solution & Audit Insight

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot is only half the battle...

This script tells you the other half, and what actions are required.
---
**What it does:**
Rather than just reporting Secure Boot state, it audits the actual certificate database (`db`/`dbDefault`/`KEK`/`dbx`), checks the TPM-WMI event log for rotation progress (including BucketId/confidence/skip reason extraction), reads the Secure Boot **servicing registry** (`UEFICA2023Status`, `WindowsUEFICA2023Capable`, error codes, `CanAttemptUpdateAfter`), decodes the **AvailableUpdates bitmask** into human-readable pending operations, cross-checks **2011 CA revocation status** in the DBX, performs a **passive UEFI variable attributes check** to determine if Windows can write to the BIOS cert db directly, and where possible, **automatically triggers the OS-side update** (registry key + WinCsFlags + scheduled task) and reports the result.

**Seven distinct states, all handled:**

- :red_circle: **Action Required** - 2023 certs missing and Windows cannot write to the BIOS db; OEM firmware update or manual key reset required
- :yellow_circle: **Action Optional** - 2023 certs missing (or in `dbDefault` only), but Windows is capable of writing to the BIOS cert db directly; Windows Update will eventually push the cert automatically, or a manual BIOS update / key reset can expedite
- :yellow_circle: **Pending** - Rotation in progress; includes Event 1799 (boot manager installed), post-trigger monitoring, and cases where certs are in `db`/`dbDefault` but completion hasn't been confirmed yet
- :green_circle: **Compliant** - Event 1808 or `UEFICA2023Status='Updated'` confirmed; BIOS updated
- :black_circle: **Disabled** - Secure Boot off; cert check not applicable
- :black_circle: **Not Applicable** - Legacy BIOS / non-UEFI
- :grey_question: **Unknown** - Secure Boot enabled but no data available to determine state

> **Pending Reboot** is a sub-state of Pending when Event 1800 is detected - the script differentiates this in the card detail and plain-text output.

---

## Script Structure

The script uses PowerShell's `begin`/`process`/`end` blocks:

| Block | Contents |
|-------|----------|
| `begin` | Initialization & Functions - admin check, parameter validation, helper functions (cert parsing, P/Invoke, event lookup, servicing reads, bitmask decoding), constants |
| `process` | Data Gathering & Logic (Steps 1–2.6) - Secure Boot status, cert parsing, dbx revocation cross-check, event log query, servicing registry, opt-in check, trigger logic, 1799/1808 annotation |
| `end` | State Mapping, Card Building & Output (Steps 3–6) - final state resolution, HTML/local card construction, NinjaRMM custom field writes, console summary |

---

## Certificate Audit

The script checks for all four 2023 certificates Microsoft is rotating to:

| Variable | Certificate | Purpose |
|----------|-------------|---------|
| `db` | Windows UEFI CA 2023 | Signs Windows boot binaries |
| `db` | Microsoft UEFI CA 2023 | Signs third-party UEFI drivers/apps |
| `db` | Microsoft Option ROM UEFI CA 2023 | Signs option ROMs (add-in cards) |
| `KEK` | Microsoft Corporation KEK 2K CA 2023 | **Authority** that signs updates to db/dbx |

Each certificate is individually tracked in the status card with ✅/❌ indicators.

When `dbDefault` is checked (because no certs are in `db` yet), the script reports **which specific certs** are found in firmware defaults - not just a boolean "present/absent."

### 2011 CA Revocation Cross-Check

The script cross-references the `dbx` (revocation list) for the old 2011 CAs:
- `Microsoft Corporation UEFI CA 2011`
- `Microsoft Windows Production PCA 2011`

If found in `dbx`, they are displayed in the certificate inventory with a 🚫 ban icon, indicating **Stage 3** (Event 1037) has completed and the old CA can no longer be used to sign boot components.

### Why the KEK matters

The **Key Exchange Key (KEK)** is the authority certificate that signs any updates to the `db` and `dbx` variables. Even if the UEFI `db` attributes allow runtime writes (`RUNTIME_ACCESS` + `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`), the firmware will **reject** the write if the payload isn't signed by a trusted KEK. Without `Microsoft Corporation KEK 2K CA 2023` in the KEK database, Windows Update cannot authorize pushing the new db certificates - meaning the machine is **not effectively OS-writable** regardless of what the UEFI attributes report.

The script checks for the 2023 KEK and overrides `$dbIsOsWritable` to `$false` if it's missing, ensuring the status card correctly shows "Action Required" instead of "Action Optional."

---

## Passive UEFI Variable Attributes Check

The script uses `GetFirmwareEnvironmentVariableExA` (P/Invoke) to read the UEFI `db` variable attributes at runtime. This determines whether the firmware allows authenticated writes from the OS, the mechanism Windows Update uses to push certificates directly into the BIOS signature database without a firmware update.

- Enables `SeSystemEnvironmentPrivilege` via token adjustment (required for UEFI variable access)
- Reads the `db` variable under the EFI Image Security Database GUID (`{d719b2cb-3d3a-4596-a3bc-dad00e67656f}`)
- Checks for `RUNTIME_ACCESS` (0x04) and `TIME_BASED_AUTHENTICATED_WRITE_ACCESS` (0x20)
- Validates the 2023 KEK authority cert is present (required to sign the payload)
- If all conditions are met, the machine is marked as OS-writable, downgrading "Action Required" to "Action Optional"

This check is entirely passive and read-only; it does not modify any UEFI variables.

---

## Event Log (TPM-WMI)

The script queries all 19 Secure Boot event IDs from the `Microsoft-Windows-TPM-WMI` provider in the System log ([KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)). Events are aggregated by ID with occurrence counts and displayed as a color-coded timeline in the status card.

**State events** (determine the overall deployment status):

| Event ID | Description | Status |
|----------|-------------|--------|
| `1808` | Fully updated - all certs + boot manager applied | :green_circle: Compliant |
| `1801` | Certs available but not applied | :red_circle: Action Required |
| `1800` | Reboot required to continue | :yellow_circle: Pending Reboot |
| `1799` | Boot manager signed with UEFI CA 2023 installed successfully | :yellow_circle: Pending |

> **1799 → 1808 Note:** When Event 1799 is the latest state event and servicing confirms `Updated` but Event 1808 hasn't appeared yet, the script annotates this in the card. The `Secure-Boot-Update` scheduled task runs at startup + every 12 hours and will produce 1808 on its next cycle. Per Microsoft MVP confirmation, this can take up to 9+ days - no manual intervention needed.

**Reboot correlation:** When Event 1800 (reboot required) is followed by Event 1799 (boot manager installed), the script checks the System event log for boot events (`Kernel-General` ID 12) between those timestamps to confirm a reboot bridged them.

**Deployment events** (track individual cert/variable operations):

| Event ID | Description |
|----------|-------------|
| `1043` | KEK updated with KEK CA 2023 |
| `1044` | Option ROM CA 2023 added to DB |
| `1045` | UEFI CA 2023 added to DB |
| `1036` | DB variable applied |
| `1034` | DBX variable applied |
| `1037` | 2011 CA revoked from DBX (Mitigation 3 / Stage 3) |
| `1042` | Boot Manager SVN applied to DBX (Mitigation 4 / Stage 4) |

**Blocker / warning events:**

| Event ID | Description |
|----------|-------------|
| `1032` | BitLocker conflict (would enter recovery) |
| `1033` | Vulnerable bootloader in EFI partition |

**Firmware / prerequisite error events:**

| Event ID | Description |
|----------|-------------|
| `1795` | Firmware returned an error (rejected the variable write) |
| `1796` | Unexpected error during update (Windows retries on reboot) |
| `1797` | Windows UEFI CA 2023 not present in DB (prerequisite failure) |
| `1798` | Boot manager not signed with 2023 cert (DBX update blocked) |
| `1802` | Update blocked - known firmware/hardware limitation |
| `1803` | PK-signed KEK not found for device (OEM hasn't provided signed KEK) |

---

## Servicing Registry

The script reads the Secure Boot servicing state from the Windows registry, providing a secondary compliance signal and diagnostic information independent of the event log.

**`HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing`**

| Value | Type | Description |
|-------|------|-------------|
| `UEFICA2023Status` | String | Definitive servicing state - `"Updated"` = compliant. The ground truth signal, used as the primary compliance check alongside Event 1808. |
| `WindowsUEFICA2023Capable` | DWORD | Boot manager readiness: `0` = cert not in DB, `1` = cert in DB, `2` = cert in DB + booting from 2023-signed boot manager. Displayed in the Servicing card section with color-coded icons. |
| `UEFICA2023Error` | DWORD | Win32 error code from the last failed update attempt. Decoded to human-readable message via `[System.ComponentModel.Win32Exception]`. |
| `UEFICA2023ErrorEvent` | DWORD | Maps to the event ID that describes the failure (e.g., 1795, 1802, 1803). |

**`HKLM:\...\SecureBoot\Servicing\DeviceAttributes`**

| Value | Type | Description |
|-------|------|-------------|
| `CanAttemptUpdateAfter` | FILETIME | Next allowed update attempt time. If in the future, the update is intentionally delayed. |
| `OEMManufacturerName` | String | OEM manufacturer name from servicing metadata |
| `OEMModelNumber` | String | Device model number |
| `FirmwareVersion` | String | Current firmware version |
| `FirmwareReleaseDate` | String | Firmware release date |

---

## AvailableUpdates Bitmask

The `AvailableUpdates` registry value is not just a magic number - it's a bitmask where each bit requests a specific certificate operation. The script decodes it into human-readable descriptions in the status card.

| Bit(s) | Hex | Meaning |
|--------|-----|---------|
| 2 | `0x0004` | Install Microsoft KEK 2023 signed by OEM PK |
| 6 | `0x0040` | Apply Windows UEFI CA 2023 to DB |
| 8 | `0x0100` | Install boot manager signed with UEFI CA 2023 |
| 11 | `0x0800` | Apply Microsoft Option ROM UEFI CA 2023 |
| 12 | `0x1000` | Apply Microsoft UEFI CA 2023 |
| 14 | `0x4000` | Conditional qualifier (apply only if UEFI CA 2011 already trusted) - always present, not displayed in output |
| 2+14 | `0x4004` | KEK needs to be updated (combo) |

The script also reads `AvailableUpdatesPolicy` (GPO/MDM-driven, persists across reboots) and `HighConfidenceOptOut` (opts the device out of Microsoft's automatic high-confidence deployment).

> Unknown/undocumented bits are detected and flagged separately.

---

## Rollout Metadata

Event 1801 and 1808 messages contain Microsoft's rollout metadata, which the script extracts via regex:

| Field | Description |
|-------|-------------|
| `BucketId` | SHA256-based device grouping hash used by Microsoft's rollout orchestration |
| `BucketConfidenceLevel` | Rollout tier - **"High Confidence"** devices are auto-eligible for deployment; **"Action Required"** devices need manual opt-in |
| `SkipReason` | `KI_<number>` known firmware issue identifier - indicates the device was skipped due to a documented firmware problem |

The **Rollout Tier** is displayed in the status card when available. High Confidence devices will receive the update automatically via Windows Update (if telemetry is sufficient); Action Required devices need explicit opt-in via `secureBootAction`.

> Bucket metadata is only extracted from Event 1801/1808 messages. Event 1800 messages contain these fields but with non-meaningful values.

---

## `secureBootAction` - NinjaRMM Script Variable (Drop-down)

The certificate audit **always runs** regardless of the selected action. The `secureBootAction` script variable controls whether the script also takes action on the Windows Update opt-in configuration for Secure Boot certificate management.

> Configure as a **Drop-down** script variable in NinjaRMM with the values below, or pass directly via `-SecureBootAction`.

| Drop-down Value | What It Does |
|-----------------|--------------|
| `Enable opt-in for Secure Boot management` | Sets telemetry to minimum required level (`AllowTelemetry=1`, `MaxTelemetryAllowed=1`, per-user `ShowedToastAtLevel=1`), sets `MicrosoftUpdateManagedOptIn=0x5944` and `AvailableUpdates=0x5944`, then triggers the `\Microsoft\Windows\PI\Secure-Boot-Update` scheduled task. If already compliant (1808 present), proceeds anyway but notes it wasn't strictly necessary. |
| `Remove opt-in for Secure Boot management` | Removes telemetry enforcement keys (`AllowTelemetry`, `MaxTelemetryAllowed`) and `MicrosoftUpdateManagedOptIn`. Does **not** remove `AvailableUpdates` (already-triggered updates should complete). |
| `Audit Secure Boot management status` | Read-only check of all opt-in and telemetry keys. Reports current state without making any changes. |
| *(empty / not set)* | No action taken - audit only. |

---

## Opt-In Status Check

Regardless of the selected action, the script always checks the current opt-in configuration and reports it in the status card under **Opt-In Status**. This uses the `Check-OptInStatus` function which reads:

| Registry Key | Path | Expected Value | Notes |
|---|---|---|---|
| `AllowTelemetry` | `HKLM:\...\Policies\DataCollection` | ≥ 1 (Required) | Must be ≥ 1 for WU to manage Secure Boot |
| `MaxTelemetryAllowed` | `HKLM:\...\Policies\DataCollection` | ≥ 1 | |
| `MicrosoftUpdateManagedOptIn` | `HKLM:\...\Control\SecureBoot` | `0x5944` | Opt-in gate |
| `AvailableUpdates` | `HKLM:\...\Control\SecureBoot` | Non-zero bitmask | Volatile trigger (cleared after use) |
| `AvailableUpdatesPolicy` | `HKLM:\...\Control\SecureBoot` | Non-zero bitmask | GPO/MDM-driven persistent trigger |
| `HighConfidenceOptOut` | `HKLM:\...\Control\SecureBoot` | `0` or absent | If non-zero, device opts out of auto-deployment |

The card displays:
- :green_circle: **Enabled** - opted in + telemetry meets minimum
- :yellow_circle: **Blocked** - opted in but `AllowTelemetry=0` prevents WU from managing certs
- :black_circle: **Not enabled** - opt-in key not set
- Additional indicators for `HighConfidenceOptOut` (if set) and `AvailableUpdatesPolicy` (if GPO/MDM is driving deployment)

---

## Smart Handling
- Stale 1801 events (cert already in `db`) are flagged as such (no false alarms)
- OS-writable firmware correctly differentiates "wait for Windows Update" from "manual action needed"
- KEK presence validated before declaring db as OS-writable
- Opt-in status always checked and surfaced in the status card (including GPO/MDM policy and auto-deployment opt-out)
- `UEFICA2023Status = "Updated"` used as the definitive compliance signal - catches cases where Event 1808 is missing from the log but the servicing stack confirms completion
- `WindowsUEFICA2023Capable` surfaced in the Servicing card section - shows boot manager readiness (0/1/2)
- Auto-trigger skipped when servicing already reports "Updated", even without Event 1808
- Auto-trigger skipped when Event 1800 (reboot required) or 1799 (boot manager installed) is already present - these are in-progress states that need time (up to 9+ days per MS MVP), not another push
- 1799 → 1808 informational note when servicing confirms Updated but 1808 hasn't appeared yet - no nudge, just annotation
- 1800 → 1799 reboot correlation - confirms a reboot bridged the two events via System boot event cross-check
- `CanAttemptUpdateAfter` checked - explains "why isn't it updating yet?" when the update is intentionally delayed
- 2011 CA revocation cross-check - detects whether old CAs have been revoked in `dbx` (Stage 3 completion)
- Servicing error codes decoded via `[System.ComponentModel.Win32Exception]` with the associated error event surfaced
- AvailableUpdates bitmask decoded into specific pending operations (0x4000 conditional qualifier suppressed - always present, not actionable)
- BucketId/BucketConfidenceLevel/SkipReason extracted from Event 1801/1808 messages - shows rollout tier and known firmware issues
- All four 2023 certificates individually tracked in a Certificate Inventory card section
- `dbDefault` cert tracking reports which specific certs are in firmware defaults (not just a boolean)
- Three-way logic for missing KEK: OS-writable → Action Optional, Event 1803 → Action Required, no 1803 → Pending with opt-in guidance
- OEM-specific BIOS update and key reset guide links included per manufacturer (Dell, HP, Lenovo, ASUS, Microsoft)
- Scheduled task `\Microsoft\Windows\PI\Secure-Boot-Update` existence check with reporting
- BitLocker warnings surfaced before any key reset guidance
- Reboot-pending detection with source (Windows Update / Component Servicing) when the trigger stalls

---

## NinjaRMM Variables

### Custom Fields (Device)

These must be created in NinjaRMM before the script can write to them.

| Field Name | Type | Description |
|------------|------|-------------|
| `SecureBootCertStatusCard` | WYSIWYG | Color-coded, detailed HTML status card with certificate inventory, event log, servicing status, and opt-in state |
| `SecureBootCertStatus` | Text (200 char) | Plain-text summary line; add to the device table for quick at-a-glance viewing |

### Script Variables (Inputs)

Configure these as Script Variables in NinjaRMM attached to the script.

| Variable Name | Type | Default | Description |
|---------------|------|---------|-------------|
| `securebootAction` | Drop-down | `Audit SecureBoot management status` | Controls whether the script takes action on opt-in configuration (see [secureBootAction](#securebootaction--ninjarmm-script-variable-drop-down)) |
| `saveStatusLocal` | Checkbox | `false` | Saves the status card (HTML) and plain-text status to local files at `C:\Windows\Logs\SecureBoot` |
| `saveLogToDevice` | Checkbox | `true` | Saves the script activity log to the device |
| `includeDefaultHive` | Checkbox | `true` | Include the Default user profile hive when setting per-user telemetry keys |
| `secureBootStatusCardField` | Text | `SecureBootCertStatusCard` | Override the WYSIWYG custom field name |
| `secureBootPlainTextField` | Text | `SecureBootCertStatus` | Override the plain-text custom field name |

### Card Customization (Parameters)

These can be passed directly as script parameters but are generally left at defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `CardTitle` | `Secure Boot` | Title displayed at the top of the status card |
| `CardIcon` | `fas fa-shield` | Font Awesome icon class for the card header |
| `CardBorderRadius` | `10px` | CSS border radius for the card |
| `CardSeparationMargin` | `0 8px` | CSS margin between cards |

---

## Output

The script writes to the NinjaRMM custom fields listed above. When `saveStatusLocal` is enabled, it also saves to:
- `C:\Windows\Logs\SecureBoot\SecureBootCertStatusCard.html`
- `C:\Windows\Logs\SecureBoot\SecureBootCertStatus.txt`

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-Example.png" alt="SecuerBoot-Card-Example" width="420px" />

[Powershell Script](https://github.com/SunshineSam/Scripts/blob/main/NinjaRMM/Windows/SecureBoot%20Management/SecureBoot-CertCheck.ps1)


