# 🛡️ SecureBoot (CA 2023) Certificate - Complete Solution & Audit Insight

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot is only half the battle...

This script tells you the other half, and what actions are required.
---
**What it does:**
Rather than just reporting Secure Boot state, it audits the actual certificate database (`db`/`dbDefault`), checks the TPM-WMI event log for rotation progress, performs a **passive UEFI variable attributes check** to determine if Windows can write to the BIOS cert db directly, and where possible, **automatically triggers the OS-side update** (registry key + WinCsFlags + scheduled task) and reports the result.

**Seven distinct states, all handled:**

- :red_circle: **Action Required** - 2023 cert missing and Windows cannot write to the BIOS db; OEM firmware update or manual key reset required
- :yellow_circle: **Action Optional** - 2023 cert missing (or in `dbDefault` only), but Windows is capable of writing to the BIOS cert db directly; Windows Update will eventually push the cert automatically, or a manual BIOS update / key reset can be applied to expedite
- :yellow_circle: **Pending** - 2023 cert in `db` or `dbDefault` but rotation not yet complete; OS update triggered where applicable
- :yellow_circle: **Pending (Post-Trigger)** - Update triggered; monitors for Event 1799 → 1808 progression, with reboot detection if stalled
- :green_circle: **Compliant** - Event 1808 confirmed, BIOS updated
- :black_circle: **Disabled** - Secure Boot off; cert check not applicable
- :black_circle: **Not Applicable** - Legacy BIOS / non-UEFI

**Passive UEFI variable attributes check**

The script uses `GetFirmwareEnvironmentVariableExA` (P/Invoke) to read the UEFI `db` variable attributes at runtime. This determines whether the firmware allows authenticated writes from the OS, the mechanism Windows Update uses to push certificates directly into the BIOS signature database without a firmware update.

- Enables `SeSystemEnvironmentPrivilege` via token adjustment (required for UEFI variable access)
- Reads the `db` variable under the EFI Image Security Database GUID (`{d719b2cb-3d3a-4596-a3bc-dad00e67656f}`)
- Checks for `RUNTIME_ACCESS` (0x04) and `TIME_BASED_AUTHENTICATED_WRITE_ACCESS` (0x20)
- If both are present, the machine is marked as OS-writable, downgrading "Action Required" to "Action Optional"

This check is entirely passive and read-only; it does not modify any UEFI variables.

**Smart handling**
- Stale 1801 events (cert already in `db`) are flagged as such (no false alarms)
- OS-writable firmware correctly differentiates "wait for Windows Update" from "manual action needed"
- OEM-specific BIOS update and key reset guide links included per manufacturer (Dell, HP, Lenovo, ASUS, Microsoft)
- Bitlocker warnings surfaced before any key reset guidance
- Reboot-pending detection with source (Windows Update / Component Servicing) when the trigger stalls

**Output:** Writes a WYSIWYG status card + plain-text field (you may add to device table) to NinjaRMM custom fields.
---
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
