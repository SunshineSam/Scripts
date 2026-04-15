# 🛡️ SecureBoot (CA 2023) - Complete Solution & Audit Insight

## 🧠 Purpose

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot being "on" is only half the battle - this script tells you the other half, and what actions are required.

- ✅ **Audits the actual certificate databases** in firmware (`db`, `KEK`, `dbDefault`, `dbx`)
- ✅ **Tracks rotation progress** across Microsoft's multi-stage deployment
- ✅ **Detects OS-writable firmware** so you know if Windows Update can handle it automatically
- ✅ **Maps every device** to one of seven clear deployment states with next-step guidance
- ✅ **Enforces SVN hardening** (optional) with strict safety gates to prevent bricking
- ✅ **Outputs formatted WYSIWYG/HTML cards** for fleet-wide visibility in NinjaRMM or local use-case

> ⚙️ Gain full auditing insight to the actual firmware state, correlaation with servicing telemetry, and reports exactly what (if anything) needs to happen next.

---

## 📦 Prerequisites

- PowerShell **5.1** or later
- **Administrator** privileges
- UEFI firmware with Secure Boot (legacy BIOS is reported as Not Applicable)
- NinjaRMM custom fields created for the status card and plain-text summary **OR** run saveStatusLocal (see below).

---

## 🔧 SecureBoot Management
_Audits CA 2023 rotation state, optionally configures Windows Update opt-in or applies SVN hardening, and publishes a consolidated HTML status card_

### 💻 RMM Input Options

| **Variable**                | **Type**     | **Description**                                                                                       |
|-----------------------------|--------------|-------------------------------------------------------------------------------------------------------|
| **$securebootAction**       | *dropdown*   | Windows Update opt-in action: Enable, Remove, or Audit. See [`securebootAction`](#securebootaction).  |
| **$enforceSvnCompliance**   | *dropdown*   | SVN hardening mode: Enforce SVN or Passive. See [`enforceSvnCompliance`](#enforcesvncompliance).      |
| **$saveStatusLocal**        | *switch*     | Save status card and plain-text summary to `C:\Logs\SecureBoot\`. Defaults to false.                  |
| **$saveLogToDevice**        | *switch*     | Save a timestamped activity log to `C:\Logs\SecureBoot\SecureBootStatus.log`. Defaults to true.       |
| **$includeDefaultHive**     | *switch*     | Apply per-user telemetry keys to the Default profile template (SYSTEM context only). Defaults to true.|

---

## Parameter Deep-Dive

### `securebootAction`

The certificate audit **always runs** regardless of this setting. This controls whether the script also configures the Windows Update opt-in for Secure Boot certificate management.

| Value | What It Does |
|-------|--------------|
| **Enable opt-in for SecureBoot management** | Configures the machine so Windows Update will manage the certificate rotation automatically. Sets the required telemetry level, opt-in registry keys, and kicks the scheduled task. If the machine is already compliant, it proceeds but notes it wasn't needed. |
| **Remove opt-in for SecureBoot management** | Removes the opt-in configuration and telemetry enforcement. Already-triggered updates will still complete - this just prevents future WU-managed pushes. |
| **Audit SecureBoot management status** | Read-only. Reports the current opt-in and telemetry configuration without touching anything. |
| *(empty / not set)* | Same as Audit - no changes made. |

### `enforceSvnCompliance`

Controls whether the script actively applies Microsoft's Secure Boot hardening mitigations ([KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) / [CVE-2023-24932 enterprise guidance](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967)). See [SVN Enforcement](#svn-enforcement) for the full details.

| Value | What It Does |
|-------|--------------|
| **Enforce SVN** | Applies all four mitigations in sequence when safe to do so. Checks current state first (won't re-apply what's already done). Has built-in safety gates to prevent dangerous out-of-order application. **If you use BitLocker, make sure recovery keys are backed up first.** |
| **Passive** | Audit only - reports which stage the device is at and what's left. Does **not** apply any mitigations, but **does** run a safety check to clean up any prematurely triggered bits. This is the recommended default until Microsoft begins enforcement (June 2026). |

> **The certificate audit always runs** regardless of `$securebootAction`. That parameter controls only whether the script *also* configures the Windows Update opt-in flow. The audit itself is non-destructive.

### 🛡️ Safety Options

| **Variable**                | **Type**     | **Description**                                                                                       |
|-----------------------------|--------------|-------------------------------------------------------------------------------------------------------|
| **$enforceSvnCompliance**   | *dropdown*   | In **Passive** mode (default), runs a safety repair to clean up prematurely staged Stage 3/4 bits before the next reboot can process them. In **Enforce SVN** mode, applies mitigations only when strict prerequisites are met - see [SVN Enforcement](#svn-enforcement). |

> **Stages 3 and 4 are irreversible.** Once the 2011 CAs are revoked (Stage 3) or SVN is written to firmware (Stage 4), there's no going back without a BIOS factory reset. The safety gate is enforced automatically in both modes.
>
> **BitLocker warning**: If the device uses BitLocker, ensure recovery keys are backed up before running in Enforce mode. Firmware changes can trigger recovery prompts on next boot.

### 🔐 Custom-Field Options

| **Variable**                     | **Type**   | **Description**                                                                                |
|----------------------------------|------------|------------------------------------------------------------------------------------------------|
| **$secureBootStatusCardField**   | *string*   | Custom WYSIWYG field name for the status card. Defaults to "SecureBootCertStatusCard."         |
| **$secureBootPlainTextField**    | *string*   | Custom text (200 char) field for the one-line summary. Defaults to "SecureBootCertStatus."     |

> **Required custom fields** (create before first run):
> - **WYSIWYG** - Full HTML status card with certificate inventory, event timeline, servicing status, and SVN compliance
> - **Text (200 char)** - One-line summary for the device table, ideal for at-a-glance views and filtering

### 🎨 Card Customization

| **Variable**                 | **Type**   | **Description**                                                         |
|------------------------------|------------|-------------------------------------------------------------------------|
| **$CardTitle**               | *string*   | Card title. Defaults to "Secure Boot."                                  |
| **$CardIcon**                | *string*   | FontAwesome icon (e.g., fas fa-shield). Defaults to fas fa-shield.      |
| **$CardBorderRadius**        | *string*   | Border radius (e.g., 10px). Defaults to 10px.                           |
| **$CardSeparationMargin**    | *string*   | Margin between cards (e.g., 0 8px). Defaults to 0 8px.                  |

### 📂 Output Files

When `$saveStatusLocal` or `$saveLogToDevice` is enabled, files are written to `C:\Logs\SecureBoot\`:

| **File**                      | **Enabled By**        | **Description**                     |
|-------------------------------|-----------------------|-------------------------------------|
| **SecureBootStatusCard.html** | `$saveStatusLocal`    | Full HTML status card               |
| **SecureBootStatus.txt**      | `$saveStatusLocal`    | Plain-text summary                  |
| **SecureBootStatus.log**      | `$saveLogToDevice`    | Timestamped activity log            |

---

## 📜 Script Details

- **Audit (always)**
  Inspects `db`/`KEK`/`dbDefault`/`dbx` firmware variables, event log history, servicing registry, and SVN values. Maps the device to a deployment state and renders a status card.

- **Opt-In Management (optional)**
  Enables or removes the Windows Update opt-in for SecureBoot certificate management, including required telemetry level and scheduled task kick.

- **SVN Enforcement (optional)**
  Applies Microsoft's [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) hardening mitigations in sequence, gated by strict Stage 1+2 prerequisites.

---

## ✅ Use Cases

- Audit **fleet-wide CA 2023 rotation progress** with per-device next steps
- Prepare for the **June 2026 enforcement deadline** proactively
- Enable **Windows Update-managed cert rotation** at scale via opt-in configuration
- Detect devices that need **firmware updates vs. OS-handled rotation**
- Apply **SVN hardening mitigations** safely with built-in prerequisite gates
- Surface **BitLocker conflicts, OEM blockers, and rollout skip reasons** before it's a problem
- Deliver **single-click visibility** via WYSIWYG device fields in NinjaRMM or local HTML cards
- Provide **OEM-specific BIOS/key-reset guidance** for Dell, HP, Lenovo, ASUS, and Microsoft

<br>

---

# 📚 Technical Reference

_Everything below this line describes **what the script actually checks** and **why**. SecureBoot rotation involves firmware state, multi-stage Microsoft deployments, and operations that are not reversible without phsyical access to a device (secuerboot key management via BIOS)._

---

## Output States

Every device resolves to exactly **one of seven primary states**. The status card and plain-text field both reflect this. Sub-state overlays (below) add deployment nuance to the primary state when mid-rotation conditions apply — they don't replace it.

### Primary States

| State | Trigger | Meaning |
|-------|---------|---------|
| ✅ **Compliant** | Event 1808 fired **or** `UEFICA2023Status = Updated` in the servicing registry | Certificate rotation confirmed complete by the OS ground truth. Remaining cert/SVN deltas are surfaced via overlays. |
| ⚠️ **Pending** | Secure Boot enabled, rotation mid-flight (Event 1801, 1800, 1799, deployment events, or silent in-progress) | WU-driven update progressing, reboot awaited, or stages partially consumed. Branches on `has2023InDb`, `has2023InDbDefault`, and opt-in state. |
| ⚠️ **Action Optional** | Certs missing from `db`, **but** firmware is OS-writable (`RUNTIME_ACCESS` + `TIME_BASED_AUTH_WRITE`) and KEK 2023 is present or deliverable | Windows Update will eventually push certs into the BIOS directly - no human action strictly required. A BIOS update or key reset can expedite. |
| ❌ **Action Required** | Certs missing from both `db` and `dbDefault` with firmware not OS-writable, **or** Event 1803 (OEM did not provide a PK-signed KEK), **or** Event 1795 (firmware actively rejected the KEK write) | Windows *cannot* resolve this on its own. OEM firmware/BIOS update or manual Secure Boot key reset is required. OEM-specific guide links are surfaced in the card. |
| ⚠️ **Disabled** | UEFI hardware present, Secure Boot switched off in firmware | Certificate rotation does not apply until Secure Boot is re-enabled. |
| ❔ **Not Applicable** | Legacy BIOS / non-UEFI environment | 2023 CA rotation is not relevant to this device. |
| ❔ **Unknown** | Fallback - no branch matched (should be rare) | State machine did not resolve. Review script output and event log manually. |

### Sub-State Overlays

Appended to the primary state on the card when relevant. The **primary state** still drives ticket/filter logic; overlays add deployment nuance.

| Overlay | Applies To | Meaning |
|---------|------------|---------|
| **(reboot pending)** | Compliant | Servicing registry confirms `Updated`, but some `db` certs are still missing and Event 1800 is present - one more reboot finalizes the remaining certs. |
| **(pending 1808)** | Compliant | All four mitigations applied (cert in `db`, Events 1799 + 1037 + 1042) but 1808 has not fired yet. Scheduled task runs at startup + every 12 hours; 1808 can take up to 9+ days. |
| **Pending Cert Reboot** | Pending | Event 1800 is the active state - a reboot is required to continue the cert update. Pending reboot source (CBS, WU, etc.) is surfaced when detected. |
| **(Pending SVN Reboot)** | Any Enabled state | SVN enforcement applied Mitigation 3/4 this run (or prior) and is awaiting the reboot that finalizes the DBX write. |
| **Pending (Not Opted In)** | Pending | Certs/KEK missing, no OEM blocker (no 1803), but WU opt-in for cert management is not enabled. Detail text prompts `securebootAction = "Enable opt-in"`. |
| **Triggered - \<result\>** | Compliant / Pending | When `securebootAction = Enable opt-in` runs the update this execution, the script re-checks servicing + events and overrides the resolved state to `Compliant` (servicing confirmed Updated / 1808 fired), `Pending` (1799 logged, in progress), or `Pending Cert Reboot` (reboot pending from CBS/WU). |

### Resolution Priority

The state machine combines multiple signals rather than relying on any single one. In priority order:

1. **Hardware class** - `NotApplicable` (non-UEFI) and `Disabled` short-circuit the rest.
2. **Compliance ground truth** - Event 1808 **or** `UEFICA2023Status = Updated` → Compliant (with sub-state check for remaining cert deltas).
3. **All-mitigations-applied** - `has2023InDb` + Events 1799 + 1037 + 1042 → Compliant (pending 1808).
4. **Event-driven Pending** - Event 1801 or 1800 branches, refined by `has2023InDb`, `has2023InDbDefault`, `dbIsOsWritable`, KEK presence, Event 1803, and Event 1795.
5. **Silent Pending** - Secure Boot enabled, no state events - branches on cert location and OS-writability as above.
6. **Post-trigger override** - If the script triggered an OS-side update this run, final state is re-resolved against the post-trigger servicing registry and event re-read.
7. **Default** - `Unknown` (should only occur if signals contradict one another).

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

**Why the KEK matters:** The KEK is the authority that authorizes changes to the cert databases. Without the 2023 KEK, Windows Update can't push new certs into the firmware - even if the hardware supports it.

**2011 CA Revocation:** The script checks whether the old 2011 CAs have been revoked in `dbx`. This is the Stage 3 milestone - once revoked, old boot components can no longer load. The status card shows this with color-coded icons (green = done, blue = pending reboot, yellow = status unclear).

### Can Windows Update the Firmware Directly?

The script reads the UEFI `db` variable attributes using a low-level system call to determine if the firmware allows authenticated writes from the OS. This is how Windows Update pushes certificates into the BIOS without needing a firmware update.

It checks two things:
1. **UEFI attributes** - Does the firmware allow runtime writes? (`RUNTIME_ACCESS` + `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`)
2. **KEK authority** - Is the 2023 KEK present to sign the payload?

If both pass, the machine is marked as OS-writable, which downgrades "Action Required" to "Action Optional" (Windows will handle it automatically).

This check is passive and read-only.

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
| ✅ **Enabled** | Opted in and telemetry meets the minimum - Windows Update will manage certs |
| ⚠️ **Blocked** | Opted in but telemetry is too low (`AllowTelemetry=0`) - WU can't proceed |
| ℹ️ **Not enabled** | Opt-in key not set - Windows won't manage certs until opted in or Microsoft's enforcement begins |

Also surfaces `AvailableUpdatesPolicy` (GPO/MDM-driven deployment) and `HighConfidenceOptOut` (if the device has opted out of auto-deployment).

---

## SVN Deployment Stages

Microsoft's Secure Boot hardening rolls out in four stages. The script detects and reports which stage each device is at.

| Stage | Timeline | What Happens | Breaking? | Mitigation |
|-------|----------|--------------|-----------|------------|
| Stage 1 | May 2024 | **UEFI Update** - adds Windows UEFI CA 2023 to the signature database (`db`) | Non-breaking | Mitigation 1 (`0x40`) |
| Stage 2 | Feb 2025 | **Boot Manager Update** - installs a boot manager signed by the 2023 key; `Get-SecureBootSVN` cmdlet added (KB5077241) | Non-breaking | Mitigation 2 (`0x100`) |
| Stage 3 | June 2026 | **Revocation** - updates `dbx` to revoke the old PCA 2011 certificate, blocking old boot components | Breaking | Mitigation 3 (`0x80`) |
| Stage 4 | 2027 *(est.)* | **SVN Update** - writes the Secure Version Number to firmware to prevent rollback to vulnerable bootloaders | Breaking | Mitigation 4 (`0x200`) |

> Microsoft's scheduled enforcement date is **June 24, 2026** (per the script's internal `$msEnforcementDate`).The stage 4 timeline is estimated until Microsoft formally announces this.

Stage detection uses multiple signals: event log entries, manifest bits in `AvailableUpdates`, and direct certificate/DBX inspection.

---

## SVN Enforcement

When [`enforceSvnCompliance`](#enforcesvncompliance) is set to `Enforce SVN`, the script applies Microsoft's mitigations per [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) / [CVE-2023-24932 enterprise guidance](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967). In `Passive` mode, only the safety check runs.

### Mitigation Sequence

Mitigations are applied in order. Each one sets a specific bit in the `AvailableUpdates` registry key and triggers the `Secure-Boot-Update` scheduled task.

| Mitigation | Operation | How It's Confirmed |
|-----------|-----------|-------------------|
| 1 (`0x40`) | Add Windows UEFI CA 2023 to DB | Certificate appears in db (re-read after 30s) |
| 2 (`0x100`) | Install 2023-signed boot manager | Event 1799 or 1808 |
| 3 (`0x80`) | Revoke PCA 2011 in DBX | Event 1037 |
| 4 (`0x200`) | Apply SVN to DBX firmware | Event 1042 |
| 3+4 (`0x280`) | Combined - per CVE-2023-24932 enterprise guidance, applied together when both are needed | Events 1037 + 1042 |

If Mitigation 1 fails, the script stops. If Mitigation 2 triggers but can't be confirmed, it marks a reboot as required and blocks Mitigations 3+4.

### Safety Gate: Why Stages 3+4 Are Gated

**Stages 3 and 4 are irreversible.** Once the old CAs are revoked (Stage 3) or SVN is written to firmware (Stage 4), there's no going back without a BIOS SecureBoot key reset. If these are applied before the new certs and boot manager are in place (Stages 1+2), the device could fail to boot.

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
- **If Events 1037/1042 have already fired:** The DBX has been modified and it's too late to undo from Windows. The script detects this and provides OEM-specific BIOS SecureBoot key reset instructions.

> Per [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d): *"After the mitigation is enabled on a device, it cannot be reverted if you continue to use Secure Boot on that device."*

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
Suppo
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

- [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) - Secure Boot hardening mitigations
- [CVE-2023-24932 Enterprise Deployment Guidance](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967) - Enterprise deployment steps, combined Mitigation 3+4 (0x280)
- [KB5077241](https://support.microsoft.com/en-us/topic/february-24-2026-kb5077241-os-builds-26200-7922-and-26100-7922-preview-b8cc7bc8-d640-4f18-9437-3ee59298b970) - February 2025 update (Get-SecureBootSVN, -Decoded)
- [SecureBoot UEFI Boot Media](https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f) - Update Boot Media to Pass updated SecureBoot verification
- [KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69) - Secure Boot event IDs
- [KB5084567](https://support.microsoft.com/en-us/topic/sample-secure-boot-e2e-automation-guide-f850b329-9a6e-40d1-823a-0925c965b8a0) - AvailableUpdates bitmask reference
- [garlin/SecureBoot-CA-2023-Updates](https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates) - SVN parsing, DBX byte reading
- [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) - Microsoft Secure Boot reference objects
- [cjee21/Check-UEFISecureBootVariables](https://github.com/cjee21/Check-UEFISecureBootVariables) - UEFI variable inspection reference
- [Microsoft Official scripts](https://support.microsoft.com/en-us/topic/sample-secure-boot-e2e-automation-guide-f850b329-9a6e-40d1-823a-0925c965b8a0) - Detection and orchestration reference scripts

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-NewExample.png" alt="SecureBoot-Card-Example" width="420px" />
<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-LocalExampleLight.png" alt="SecureBoot-LocalCard-Example" width="420px" />
<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-LocalExampleDark.png" alt="SecureBoot-LocalCard-Example" width="420px" />

[PowerShell Script](https://github.com/SunshineSam/Scripts/blob/main/NinjaRMM/Windows/SecureBoot%20Management/SecureBoot-Management-CA2023.ps1)
