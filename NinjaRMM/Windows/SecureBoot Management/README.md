# 🛡️ SecureBoot (CA 2023) Certificate - Complete Solution & Audit Insight

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot is only half the battle...

This script tells you the other half, and what actions are required.
---
**What it does:**
Rather than just reporting Secure Boot state, it audits the actual certificate database (`db`/`dbDefault`/`KEK`), checks the TPM-WMI event log for rotation progress, performs a **passive UEFI variable attributes check** to determine if Windows can write to the BIOS cert db directly, and where possible, **automatically triggers the OS-side update** (registry key + WinCsFlags + scheduled task) and reports the result.

**Seven distinct states, all handled:**

- :red_circle: **Action Required** - 2023 cert missing and Windows cannot write to the BIOS db; OEM firmware update or manual key reset required
- :yellow_circle: **Action Optional** - 2023 cert missing (or in `dbDefault` only), but Windows is capable of writing to the BIOS cert db directly; Windows Update will eventually push the cert automatically, or a manual BIOS update / key reset can be applied to expedite
- :yellow_circle: **Pending** - 2023 cert in `db` or `dbDefault` but rotation not yet complete; OS update triggered where applicable
- :yellow_circle: **Pending (Post-Trigger)** - Update triggered; monitors for Event 1799 → 1808 progression, with reboot detection if stalled
- :green_circle: **Compliant** - Event 1808 confirmed, BIOS updated
- :black_circle: **Disabled** - Secure Boot off; cert check not applicable
- :black_circle: **Not Applicable** - Legacy BIOS / non-UEFI

---

## Certificate Audit

The script checks for all four 2023 certificates Microsoft is rotating to:

| Variable | Certificate | Purpose |
|----------|-------------|---------|
| `db` | Windows UEFI CA 2023 | Signs Windows boot binaries |
| `db` | Microsoft Corporation UEFI CA 2023 | Signs third-party UEFI drivers/apps |
| `db` | Microsoft Option ROM UEFI CA 2023 | Signs option ROMs (add-in cards) |
| `KEK` | Microsoft Corporation KEK 2K CA 2023 | **Authority** that signs updates to db/dbx |

### Why the KEK matters

The **Key Exchange Key (KEK)** is the authority certificate that signs any updates to the `db` and `dbx` variables. Even if the UEFI `db` attributes allow runtime writes (`RUNTIME_ACCESS` + `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`), the firmware will **reject** the write if the payload isn't signed by a trusted KEK. Without `Microsoft Corporation KEK 2K CA 2023` in the KEK database, Windows Update cannot authorize pushing the new db certificates — meaning the machine is **not effectively OS-writable** regardless of what the UEFI attributes report.

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

## `secureBootAction` — NinjaRMM Script Variable (Drop-down)

The certificate audit **always runs** regardless of the selected action. The `secureBootAction` script variable controls whether the script also takes action on the Windows Update opt-in configuration for Secure Boot certificate management.

> Configure as a **Drop-down** script variable in NinjaRMM with the values below, or pass directly via `-SecureBootAction`.

| Drop-down Value | What It Does |
|-----------------|--------------|
| `Enable opt-in for Secure Boot management` | Sets telemetry to minimum required level (`AllowTelemetry=1`, `MaxTelemetryAllowed=1`, per-user `ShowedToastAtLevel=1`), sets `MicrosoftUpdateManagedOptIn=0x5944` and `AvailableUpdates=0x5944`, then triggers the `\Microsoft\Windows\PI\Secure-Boot-Update` scheduled task. If already compliant (1808 present), proceeds anyway but notes it wasn't strictly necessary. |
| `Remove opt-in for Secure Boot management` | Removes telemetry enforcement keys (`AllowTelemetry`, `MaxTelemetryAllowed`) and `MicrosoftUpdateManagedOptIn`. Does **not** remove `AvailableUpdates` (already-triggered updates should complete). |
| `Audit Secure Boot management status` | Read-only check of all opt-in and telemetry keys. Reports current state without making any changes. |
| *(empty / not set)* | No action taken — audit only. |

---

## Opt-In Status Check

Regardless of the selected action, the script always checks the current opt-in configuration and reports it in the status card under **Opt-In Status**. This uses the `Check-OptInStatus` function which reads:

| Registry Key | Path | Expected Value |
|---|---|---|
| `AllowTelemetry` | `HKLM:\...\Policies\DataCollection` | ≥ 1 (Required) |
| `MaxTelemetryAllowed` | `HKLM:\...\Policies\DataCollection` | ≥ 1 |
| `MicrosoftUpdateManagedOptIn` | `HKLM:\...\Control\SecureBoot` | `0x5944` |
| `AvailableUpdates` | `HKLM:\...\Control\SecureBoot` | `0x5944` |

The card displays one of three states:
- :green_circle: **Enabled** — opted in + telemetry meets minimum
- :yellow_circle: **Blocked** — opted in but `AllowTelemetry=0` prevents WU from managing certs
- :black_circle: **Not enabled** — opt-in key not set

---

## Smart Handling
- Stale 1801 events (cert already in `db`) are flagged as such (no false alarms)
- OS-writable firmware correctly differentiates "wait for Windows Update" from "manual action needed"
- KEK presence validated before declaring db as OS-writable
- Opt-in status always checked and surfaced in the status card
- OEM-specific BIOS update and key reset guide links included per manufacturer (Dell, HP, Lenovo, ASUS, Microsoft)
- Scheduled task `\Microsoft\Windows\PI\Secure-Boot-Update` existence check with reporting
- BitLocker warnings surfaced before any key reset guidance
- Reboot-pending detection with source (Windows Update / Component Servicing) when the trigger stalls

---

## Output

Writes a WYSIWYG status card + plain-text field (you may add to device table) to NinjaRMM custom fields.

**Fields Required**
| Field Name                   | Type        | Description                                                                 |
|-------------------------------|------------|-----------------------------------------------------------------------------|
| `SecureBootCertStatusCard`   | WYSIWYG    | Color-coded, detailed HTML status card                                     |
| `SecureBootCertStatus`       | Text       | Plain-text summary; add to the device table for quick viewing              |
| **OR**                       |            |                                                                             |
| `saveStatusLocal`            | CheckBox   | Optional parameter input that saves the status card and status text to two local files at `C:\Windows\Logs\SecureBoot` |

> :gear: Both fallback values can be overridden manually or via Script Variables (`secureBootStatusCardField`, `secureBootPlainTextField`).
>
[Powershell Script](https://github.com/SunshineSam/Scripts/blob/main/NinjaRMM/Windows/SecureBoot%20Management/SecureBoot-CertCheck.ps1)

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-CardExample.png" alt="SecureBoot Card Example" width="660px" />
