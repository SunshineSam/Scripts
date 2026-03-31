# 🛡️ SecureBoot (CA 2023) Certificate - Complete Solution & Audit Insight

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot is only half the battle...

This script tells you the other half, and what actions are required.

---

## What It Does

Most tools just tell you whether Secure Boot is on or off. This script goes deeper - it audits the actual certificate databases in your firmware, tracks where each machine is in Microsoft's multi-stage certificate rotation, and tells you exactly what (if anything) needs to happen next.

At a glance, it answers:
- **Are the new 2023 certificates installed?** Checks all four certs across `db`, `KEK`, and `dbDefault`
- **Is the old stuff revoked?** Cross-checks whether the 2011 CAs have been removed from the trust chain
- **Can Windows handle this automatically?** Tests whether the firmware allows OS-level writes (so Windows Update can push certs without a BIOS update)
- **What's actually happening right now?** Reads the event log, servicing registry, and update manifest to show exactly where the rotation stands
- **Is SVN (rollback protection) in place?** Checks boot manager version numbers to confirm the device can't be rolled back to a vulnerable state
- **What stage is this device at?** Maps everything to one of four deployment stages with clear next steps

It then outputs a color-coded status card to NinjaRMM (or local files) with all the detail you need for fleet-wide visibility.

**On newer systems (KB5077241+, February 2025):** The script automatically uses the newer `Get-SecureBootUEFI -Decoded` and `Get-SecureBootSVN` cmdlets for richer data, falling back to raw byte parsing on older systems. You don't need to worry about compatibility - it handles both transparently.

---

## Output States

Every device lands in one of eight states. The status card and plain-text field both reflect this.

| State | Meaning |
|-------|---------|
| :green_circle: **Compliant** | Certificate rotation confirmed complete (Event 1808 or servicing registry confirms "Updated") |
| :yellow_circle: **Pending** | Rotation in progress - certs are deploying, waiting on reboots, or the OS is working through the stages |
| :yellow_circle: **Pending (Trigger)** | The script triggered the OS-side update and is monitoring for progress |
| :yellow_circle: **Action Optional** | Certs are missing, but Windows *can* push them automatically - it'll happen on its own, or you can expedite with a BIOS update |
| :red_circle: **Action Required** | Certs are missing and Windows *cannot* update them - a firmware update or manual key reset is needed |
| :black_circle: **Disabled** | Secure Boot is off; certificate rotation doesn't apply until it's enabled |
| :black_circle: **Not Applicable** | Legacy BIOS or non-UEFI hardware; not relevant |
| :grey_question: **Unknown** | Secure Boot is on but there's not enough data to determine the state |

> **Pending Reboot** appears as a sub-state of Pending when Event 1800 is detected - the card and plain-text output call this out specifically.

---

## NinjaRMM Variables & Parameters

### Custom Fields (Device - Output)

Create these in NinjaRMM before deploying the script.

| Field Name | Type | Description |
|------------|------|-------------|
| `SecureBootCertStatusCard` | WYSIWYG | Detailed HTML status card with certificate inventory, event timeline, servicing status, SVN compliance, and more |
| `SecureBootCertStatus` | Text (200 char) | One-line summary for the device table - great for quick at-a-glance views and filtering |

### Script Variables (Inputs)

Configure these as Script Variables in NinjaRMM attached to the script, or pass directly as PowerShell parameters.

| Variable Name | Type | Default | Description |
|---------------|------|---------|-------------|
| `securebootAction` | Drop-down | `Audit SecureBoot management status` | What to do about Windows Update opt-in ([details below](#securebootaction)) |
| `enforceSvnCompliance` | Drop-down | `Passive` | Whether to actively apply SVN hardening mitigations ([details below](#enforcesvncompliance)) |
| `saveStatusLocal` | Checkbox | `false` | Save output to local files (useful outside NinjaRMM) |
| `saveLogToDevice` | Checkbox | `true` | Save a timestamped activity log to the device |
| `includeDefaultHive` | Checkbox | `true` | Apply per-user telemetry keys to the Default profile template (only matters when running as SYSTEM) |
| `secureBootStatusCardField` | Text | `SecureBootCertStatusCard` | Override the WYSIWYG custom field name |
| `secureBootPlainTextField` | Text | `SecureBootCertStatus` | Override the plain-text custom field name |

#### `securebootAction`

The certificate audit **always runs** regardless of this setting. This controls whether the script also configures the Windows Update opt-in for Secure Boot certificate management.

| Value | What It Does |
|-------|--------------|
| **Enable opt-in for SecureBoot management** | Configures the machine so Windows Update will manage the certificate rotation automatically. Sets the required telemetry level, opt-in registry keys, and kicks the scheduled task. If the machine is already compliant, it proceeds but notes it wasn't needed. |
| **Remove opt-in for SecureBoot management** | Removes the opt-in configuration and telemetry enforcement. Already-triggered updates will still complete - this just prevents future WU-managed pushes. |
| **Audit SecureBoot management status** | Read-only. Reports the current opt-in and telemetry configuration without touching anything. |
| *(empty / not set)* | Same as Audit - no changes made. |

#### `enforceSvnCompliance`

Controls whether the script actively applies Microsoft's Secure Boot hardening mitigations ([KB5025885](https://support.microsoft.com/en-us/topic/kb5025885) / [KB5053946](https://support.microsoft.com/en-us/topic/kb5053946)). See [SVN Enforcement](#svn-enforcement) for the full details.

| Value | What It Does |
|-------|--------------|
| **Enforce SVN** | Applies all four mitigations in sequence when safe to do so. Checks current state first (won't re-apply what's already done). Has built-in safety gates to prevent dangerous out-of-order application. **If you use BitLocker, make sure recovery keys are backed up first.** |
| **Passive** | Audit only - reports which stage the device is at and what's left. Does **not** apply any mitigations, but **does** run a safety check to clean up any prematurely triggered bits. This is the recommended default until Microsoft begins enforcement (June 2026). |

### Card Customization

Optional parameters - generally left at defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `CardTitle` | `Secure Boot` | Title at the top of the status card |
| `CardIcon` | `fas fa-shield` | Font Awesome icon class |
| `CardBorderRadius` | `10px` | CSS border radius |
| `CardSeparationMargin` | `0 8px` | CSS margin between cards |

### Output Files

When local output is enabled, files are written to `C:\Logs\SecureBoot\`:

| File | Enabled By | Description |
|------|------------|-------------|
| `SecureBootStatusCard.html` | `saveStatusLocal` | Full HTML status card |
| `SecureBootStatus.txt` | `saveStatusLocal` | Plain-text summary |
| `SecureBootStatus.log` | `saveLogToDevice` | Timestamped activity log |

---

## What the Script Checks

### Certificate Audit

Microsoft is rotating to four new certificates. The script checks for each one individually:

| Location | Certificate | Role |
|----------|-------------|------|
| `db` | Windows UEFI CA 2023 | Signs Windows boot binaries |
| `db` | Microsoft UEFI CA 2023 | Signs third-party UEFI drivers/apps |
| `db` | Microsoft Option ROM UEFI CA 2023 | Signs option ROMs (add-in cards) |
| `KEK` | Microsoft Corporation KEK 2K CA 2023 | **Authority** that signs updates to db/dbx |

Each cert is shown in the status card with a three-state icon: green (confirmed installed), blue (pending - triggered but not yet confirmed), or red (absent).

The script also checks `dbDefault` (firmware defaults) and reports exactly which certs are there - useful for understanding what a BIOS key reset would restore.

**Why the KEK matters:** The KEK is the authority that authorizes changes to the cert databases. Without the 2023 KEK, Windows Update can't push new certs into the firmware - even if the hardware supports it. The script checks for this and won't falsely report a machine as "Action Optional" when the KEK is missing.

**2011 CA Revocation:** The script checks whether the old 2011 CAs have been revoked in `dbx`. This is the Stage 3 milestone - once revoked, old boot components can no longer load. The status card shows this with color-coded icons (green = done, blue = pending reboot, yellow = status unclear).

### Can Windows Update the Firmware Directly?

The script reads the UEFI `db` variable attributes using a low-level system call to determine if the firmware allows authenticated writes from the OS. This is how Windows Update pushes certificates into the BIOS without needing a firmware update.

It checks two things:
1. **UEFI attributes** - Does the firmware allow runtime writes? (`RUNTIME_ACCESS` + `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`)
2. **KEK authority** - Is the 2023 KEK present to sign the payload?

If both pass, the machine is marked as OS-writable, which downgrades "Action Required" to "Action Optional" (Windows will handle it automatically).

This check is entirely passive and read-only - nothing is modified.

### Event Log

The script queries all 19 Secure Boot event IDs from the `Microsoft-Windows-TPM-WMI` provider ([KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)). Events are aggregated with counts and timestamps, displayed as a color-coded timeline in the card.

**Key state events:**

| Event ID | What It Means |
|----------|---------------|
| `1808` | Fully updated - all done |
| `1799` | Boot manager installed - nearly done, waiting for final confirmation |
| `1801` | Certs are available but haven't been applied yet |
| `1800` | Reboot needed to continue the update |

**Deployment events** track individual operations (1043 KEK updated, 1036 DB applied, 1037 2011 CA revoked, 1042 SVN applied, etc.).

**Blocker events** flag issues like BitLocker conflicts (1032), vulnerable bootloaders (1033), or OEM firmware problems (1803).

> **1799 -> 1808 timing:** After Event 1799, it can take up to 9+ days for 1808 to appear. The scheduled task runs at startup + every 12 hours. The script notes this so you don't waste time investigating a normal delay.

### Servicing Registry

The Windows servicing registry provides the definitive compliance signal, independent of the event log.

| Value | What It Tells You |
|-------|-------------------|
| `UEFICA2023Status` | The ground truth - `"Updated"` means done. Used alongside Event 1808 as the primary compliance check. |
| `WindowsUEFICA2023Capable` | Boot manager readiness: `0` = cert not in DB, `1` = cert in DB, `2` = booting from 2023-signed boot manager |
| `UEFICA2023Error` | Last error code (decoded to a readable message) |
| `CanAttemptUpdateAfter` | If in the future, the update is intentionally delayed - explains "why isn't it updating?" |
| OEM info | Manufacturer, model, firmware version |

### SVN Compliance

**Security Version Numbers (SVN)** are the rollback protection piece. Once applied, firmware will refuse to boot anything older than the recorded version - preventing attackers from rolling back to a vulnerable boot manager.

The script checks SVN through two paths:
1. **`Get-SecureBootSVN` cmdlet** (KB5077241+) - provides firmware, boot manager, and staged SVN values
2. **Raw DBX byte parsing** (all devices) - extracts SVN from the firmware variables directly and compares against the Windows Update staging file to detect pending updates

SVN progression: `0.0` (nothing applied) -> `2.0` (2011 CA revoked) -> `7.0` (full enforcement)

### Rollout Metadata

Events 1801 and 1808 contain Microsoft's rollout targeting metadata. The script extracts:

- **BucketConfidenceLevel** - "High Confidence" devices get auto-deployed; "Action Required" devices need manual opt-in
- **BucketId** - Device grouping hash for Microsoft's rollout orchestration
- **SkipReason** - `KI_<number>` flags indicating known firmware issues that blocked deployment

### Opt-In Status

Regardless of the selected action, the script always reports the current opt-in configuration:

| Status | Meaning |
|--------|---------|
| :green_circle: **Enabled** | Opted in and telemetry meets the minimum - Windows Update will manage certs |
| :yellow_circle: **Blocked** | Opted in but telemetry is too low (`AllowTelemetry=0`) - WU can't proceed |
| :black_circle: **Not enabled** | Opt-in key not set - Windows won't manage certs until opted in or Microsoft's enforcement begins |

Also surfaces `AvailableUpdatesPolicy` (GPO/MDM-driven deployment) and `HighConfidenceOptOut` (if the device has opted out of auto-deployment).

---

## SVN Deployment Stages

Microsoft's Secure Boot hardening rolls out in four stages. The script detects and reports which stage each device is at.

| Stage | Timeline | What Happens | Mitigation |
|-------|----------|--------------|------------|
| Stage 1 | May 2024 | 2023 certificates added to the firmware `db` | Mitigation 1 (`0x40`) |
| Stage 2 | Feb 2025 | New boot manager deployed, signed with 2023 cert | Mitigation 2 (`0x100`) |
| Stage 3 | June 2026 | Old 2011 CA revoked in `dbx` - old boot components blocked | Mitigation 3 (`0x80`) |
| Stage 4 | est. 2027 | Full enforcement - SVN written to firmware | Mitigation 4 (`0x200`) |

Stage detection uses multiple signals: event log entries, manifest bits in `AvailableUpdates`, and direct certificate/DBX inspection.

---

## SVN Enforcement

When [`enforceSvnCompliance`](#enforcesvncompliance) is set to `Enforce SVN`, the script applies Microsoft's mitigations per [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885) / [KB5053946](https://support.microsoft.com/en-us/topic/kb5053946). In `Passive` mode, only the safety check runs.

### Mitigation Sequence

Mitigations are applied in order. Each one sets a specific bit in the `AvailableUpdates` registry key and triggers the `Secure-Boot-Update` scheduled task.

| Mitigation | Operation | How It's Confirmed |
|-----------|-----------|-------------------|
| 1 (`0x40`) | Add Windows UEFI CA 2023 to DB | Certificate appears in db (re-read after 30s) |
| 2 (`0x100`) | Install 2023-signed boot manager | Event 1799 or 1808 |
| 3 (`0x80`) | Revoke PCA 2011 in DBX | Event 1037 |
| 4 (`0x200`) | Apply SVN to DBX firmware | Event 1042 |
| 3+4 (`0x280`) | Combined - per KB5053946, applied together when both are needed | Events 1037 + 1042 |

If Mitigation 1 fails, the script stops. If Mitigation 2 triggers but can't be confirmed, it marks a reboot as required and blocks Mitigations 3+4.

### Safety Gate: Why Stages 3+4 Are Gated

**Stages 3 and 4 are irreversible.** Once the old CAs are revoked (Stage 3) or SVN is written to firmware (Stage 4), there's no going back without a BIOS factory reset. If these are applied before the new certs and boot manager are in place (Stages 1+2), the device could fail to boot.

The script enforces a strict prerequisite gate before allowing Mitigations 3+4:

| Prerequisite | What's Checked |
|-------------|----------------|
| Stage 1 complete | Cert **physically present** in db AND the `0x40` bit has been **consumed** (processed by Windows) |
| Stage 2 complete | Event 1799 or 1808 **confirmed** AND the `0x100` bit has been **consumed** |
| No pending reboot | Event 1800 (reboot required) is **not** the current state |

Both the ground truth (is the cert actually there?) and the manifest (did Windows finish processing it?) must pass. If anything fails, Mitigations 3+4 are blocked with a clear reason.

### Safety Repair

The script includes a repair function that runs automatically in **both Enforce and Passive modes**:

- **If Stage 3+4 bits are in the manifest but prerequisites aren't met:** The bits are cleared from the registry before the next reboot can process them. This is reversible - the DBX hasn't been modified yet.
- **If Events 1037/1042 have already fired:** The DBX has been modified and it's too late to undo from Windows. The script detects this and provides OEM-specific BIOS key reset instructions.

> Per [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885): *"After the mitigation is enabled on a device, it cannot be reverted if you continue to use Secure Boot on that device."*

---

## AvailableUpdates Bitmask

The `AvailableUpdates` registry value is a bitmask where each bit requests a specific update operation. The script decodes it into readable descriptions in the status card.

| Bit | Hex | Meaning |
|-----|-----|---------|
| 2 | `0x0004` | Install Microsoft KEK 2023 (signed by OEM PK) |
| 6 | `0x0040` | Apply Windows UEFI CA 2023 to DB (Mitigation 1) |
| 7 | `0x0080` | Revoke PCA 2011 in DBX (Mitigation 3) |
| 8 | `0x0100` | Install boot manager signed with UEFI CA 2023 (Mitigation 2) |
| 9 | `0x0200` | Apply SVN to DBX firmware (Mitigation 4) |
| 11 | `0x0800` | Apply Microsoft Option ROM UEFI CA 2023 |
| 12 | `0x1000` | Apply Microsoft UEFI CA 2023 |
| 14 | `0x4000` | Conditional qualifier (always present, not shown in output) |
| 2+14 | `0x4004` | KEK needs to be updated (combo) |

The script also reads `AvailableUpdatesPolicy` (GPO/MDM-driven, persists across reboots) and `HighConfidenceOptOut`. Unknown/undocumented bits are detected and flagged.

---

## Smart Handling

The script handles a lot of edge cases so you don't have to investigate them manually:

- **Stale events** - A 1801 event when the cert is already in `db` is flagged as stale (no false alarms)
- **OS-writable vs. not** - Correctly differentiates "Windows will handle it" from "you need to update the BIOS"
- **KEK validation** - Won't falsely report OS-writable when the KEK authority cert is missing
- **Trigger intelligence** - Won't re-trigger updates when Event 1800 (reboot needed) or 1799 (in progress) is present; these need time, not another push
- **Delay detection** - `CanAttemptUpdateAfter` explains why an update hasn't happened yet
- **Error decoding** - Servicing error codes are translated to readable messages
- **Reboot correlation** - Confirms reboots actually happened between Event 1800 and 1799 using boot event cross-checks
- **Three-way KEK logic** - Missing KEK with OS-writable = Action Optional; with Event 1803 (OEM blocker) = Action Required; neither = Pending with opt-in guidance
- **OEM-specific guidance** - BIOS update and key reset links for Dell, HP, Lenovo, ASUS, and Microsoft
- **BitLocker warnings** - Surfaced before any key reset guidance
- **SVN safety** - Stage 1+2 prerequisite gate, passive mode safety checks, post-enforcement repair, boot-time cross-reference for reboot-pending detection
- **Automatic fallback** - `Get-SecureBootUEFI -Decoded` when available, raw byte parsing when not; `Get-SecureBootSVN` cmdlet + raw DBX parsing together for complete coverage
- **`WinCsFlags.exe`** - Used when available for more precise configuration application

---

## Script Internals

### Architecture

The script uses PowerShell's `begin`/`process`/`end` blocks:

| Block | What Happens |
|-------|--------------|
| `begin` | Loads all functions, runs admin check, detects KB5077241 capabilities |
| `process` | Gathers all data (certs, events, servicing, SVN, opt-in), runs enforcement or safety checks, executes the selected action |
| `end` | Maps everything to a final state, builds the status card, writes to NinjaRMM fields or local files |

### Card Rendering

The status card is built from modular `Build-*` functions that accept a `-Format` parameter (`'Html'` or `'Local'`). This means the HTML card (Font Awesome icons, colors) and plain-text output (emoji) are generated from the same logic - no drift between the two.

| Function | Section |
|----------|---------|
| `Build-CertInventorySection` | Certificate inventory (three-state icons) |
| `Build-ServicingSection` | Servicing registry status |
| `Build-UpdatesSection` | AvailableUpdates manifest (decoded bitmask) |
| `Build-SvnComplianceSection` | SVN compliance and enforcement results |
| `Build-EnforcementMitigationLines` | Per-mitigation status lines |
| `Build-RolloutTierSection` | Rollout tier / confidence metadata |
| `Build-UpdateTaskSection` | Scheduled task presence |
| `Build-OptInSection` | Opt-in configuration |
| `Build-EventLogSection` | Color-coded event timeline |

### Certificate Parsing

The `Get-UefiDatabaseCerts` function handles cert parsing transparently:
- Uses `Get-SecureBootUEFI -Decoded` when available (KB5077241+)
- Falls back to raw `EFI_SIGNATURE_LIST` byte parsing on older systems
- Returns X509 certificate objects either way

---

## Sources

- [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885) - Secure Boot hardening mitigations
- [KB5053946](https://support.microsoft.com/en-us/topic/kb5053946) - Combined Mitigation 3+4 guidance
- [KB5077241](https://support.microsoft.com/en-us/topic/kb5077241) - February 2025 update (Get-SecureBootSVN, -Decoded)
- [KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69) - Secure Boot event IDs
- [KB5084567](https://support.microsoft.com/en-us/topic/kb5084567) - AvailableUpdates bitmask reference
- [garlin/SecureBoot-CA-2023-Updates](https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates) - SVN parsing, DBX byte reading
- [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) - Microsoft Secure Boot reference objects
- [cjee21/Check-UEFISecureBootVariables](https://github.com/cjee21/Check-UEFISecureBootVariables) - UEFI variable inspection reference
- [HorizonSecured/Get-SecureBootCertInfo.ps1](https://github.com/HorizonSecured) - Bitmask decoding reference
- [Microsoft Official scripts](Microsoft%20Official/) - Detection and orchestration reference scripts
