# 🛡️ SecureBoot (CA 2023) - Complete Solution & Audit Insight

## 🧠 Purpose

**The June 2026 deadline is around the corner.** Microsoft's Windows UEFI CA 2023 certificate rotation is already in motion, and machines that miss it risk security compliance and future security fixes. Secure Boot being "on" is only half the battle. This script tells you the other half, and what actions are required.

- ✅ **Audits the actual certificate databases** in firmware, and flags [PKFail / CVE-2024-8105](https://nvd.nist.gov/vuln/detail/CVE-2024-8105)
- ✅ **Tracks rotation progress** across Microsoft's multi-stage deployment
- ✅ **Detects OS-writable firmware** so you know if Windows Update can handle it automatically
- ✅ **Maps every device** to one of nine clear deployment states with next-step guidance
- ✅ **Cross-checks DBX** against what Windows has staged.
- ✅ **Scans attached removable / optical media** for 2011-signed boot managers that will fail after June deadline
- ✅ **Enforces SVN hardening** (optional) with strict safety gates to prevent bricking
- ✅ **Outputs formatted WYSIWYG/HTML cards** for fleet-wide visibility in NinjaRMM or local use-case

> ⚙️ Gain full auditing insight to the firmware state, and reports exactly what (if anything) needs to happen next.
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
| **$suspendBitlockerForSVN** | *checkbox*   | Suspend encrypted OS/fixed-data BitLocker volumes for two reboots before SVN Stage 3/4. Checked by default. |
| **$saveStatusLocal**        | *switch*     | Save status card and plain-text summary to `C:\Logs\SecureBoot\`. Defaults to false.                  |
| **$saveLogToDevice**        | *switch*     | Save a timestamped activity log to `C:\Logs\SecureBoot\SecureBootStatus.log`. Defaults to true.       |
| **$includeDefaultHive**     | *switch*     | Apply per-user telemetry keys to the Default profile template (SYSTEM context only). Defaults to true.|
| **$deepBootMediaScan**      | *switch*     | Optionally expand the boot-media scan to inspect WIM images inside removable / optical recovery media (scans further than `\EFI\boot\boot*.efi`). Slower - requires DISM / `Get-WindowsImage`. Defaults to false. See [Boot Media Scan](#boot-media-scan). |

---

## 🎯 Parameter Deep-Dive

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
| **Enforce SVN** | Applies all 4 mitigations in 2 step sequence, only when safe to do so. Checks current state first (won't re-apply what's already done). Has built-in prerequisite and BitLocker safety gates to prevent dangerous application. |
| **Passive** | Audit only - reports which stage the device is at and what's left. Does **not** apply any mitigations, but **does** run a safety check to clean up any prematurely triggered bits. This is the recommended default until Microsoft begins enforcement (June 2026). |

### `suspendBitlockerForSVN`

Controls the BitLocker safety boundary immediately before irreversible SVN Stage 3 and/or Stage 4 processing. This checkbox is checked (`$true`) by default.

| Value | What It Does |
|-------|--------------|
| **Checked (`$true`)** | Suspends every encrypted Operating System and Fixed Data BitLocker volume for **2 reboots** before writing a new Stage 3/4 trigger. It also prepares BitLocker whenever Stage 3 or Stage 4 bits are already pending in `AvailableUpdates`, including Microsoft/WU, policy, or third-party pushes detected during Passive/Audit. A failure blocks a new trigger; if bits are already pending, the script reports **do not reboot** until the failed volume is resolved. |
| **Unchecked (`$false`)** | Leaves BitLocker unchanged and permits otherwise-safe SVN enforcement to continue. The status card and log clearly report that automatic suspension was disabled. |

Newly suspended volumes, already-suspended volumes, skipped unencrypted volumes, and failures are reported separately in the **SVN BitLocker Safety** card section and console/log output. Existing suspensions are left unchanged rather than being silently reset.

> **The certificate audit always runs** regardless of `$securebootAction`. That parameter controls only whether the script *also* configures the Windows Update opt-in flow. The audit itself is non-destructive.

### 🛡️ Safety Options

| **Variable**                | **Type**     | **Description**                                                                                       |
|-----------------------------|--------------|-------------------------------------------------------------------------------------------------------|
| **$enforceSvnCompliance**   | *dropdown*   | In **Passive** mode (default), runs a safety repair to clean up prematurely staged Stage 3/4 bits before the next reboot can process them. In **Enforce SVN** mode, applies mitigations only when strict prerequisites are met - see [SVN Enforcement](#svn-enforcement). |
| **$suspendBitlockerForSVN** | *checkbox*   | **Checked by default.** Before combined Stage 3+4, Stage 3-only, or Stage 4-only processing, suspend all encrypted OS/fixed-data volumes for 2 reboots and report each affected volume. |

> **Stages 3 and 4 are irreversible.** Once the 2011 CAs are revoked (Stage 3) or SVN is written to firmware (Stage 4), there's no going back without a BIOS SecureBoot key reset. The safety gate is enforced automatically in both modes.
>
> **BitLocker safety**: With `$suspendBitlockerForSVN` checked, encrypted OS and fixed-data volumes are automatically suspended for 2 reboots at the Stage 3/4 safety boundary. Recovery keys should still be escrowed and verified before irreversible enforcement.

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

_Everything below this line describes **what the script checks** and **why**. SecureBoot rotation involves firmware state, multi-stage Microsoft deployments, and operations that are not reversible without phsyical access to a device (secuerboot key management via BIOS)._

---

## Output States

Every device resolves to exactly **one of nine primary states**. The status card and plain-text field both reflect this. Sub-state overlays (below) add deployment nuance to the primary state when mid-rotation conditions apply.

### Primary States

| State | Trigger | Meaning |
|-------|---------|---------|
| ✅ **Compliant** | Event 1808 fired **or** `UEFICA2023Status = Updated` in the servicing registry | Certificate rotation confirmed complete by the OS ground truth. Remaining cert/SVN deltas are surfaced via overlays. |
| ⚠️ **Pending** | Secure Boot enabled, rotation mid-flight (Event 1801, 1800, 1799, deployment events, or silent in-progress) | WU-driven update progressing, reboot awaited, or stages partially consumed. Branches on `has2023InDb`, `has2023InDbDefault`, and opt-in state. |
| ⚠️ **Action Optional** | Certs missing from `db`, **but** firmware is OS-writable (`RUNTIME_ACCESS` + `TIME_BASED_AUTH_WRITE`) and KEK 2023 is present or deliverable | Windows Update will eventually push certs into the BIOS directly - no human action strictly required. A BIOS update or key reset can expedite. |
| ❌ **Action Required** | Certs missing from both `db` and `dbDefault` with firmware not OS-writable, **or** Event 1795 (firmware actively rejected the KEK write - PK authority issue), **or** Event 1803 (no PK-signed KEK 2023 update available via WU - OEM publication gap) | Windows *cannot* resolve this on its own in its current state. **1795** needs an OEM BIOS/firmware update that extends PK trust (or a manual key reset from `dbDefault`). **1803** needs the OEM to publish a PK-signed KEK 2023 update to Microsoft so WU can serve it, alternatively it could also be solved with a BIOS update. OEM-specific guide links are surfaced in the card. |
| ❌ **PK Untrusted** | Platform Key subject matches a known placeholder (`AMI\|DO NOT TRUST\|Example`) - most commonly the AMI Test PK from [PKFail / CVE-2024-8105](https://nvd.nist.gov/vuln/detail/CVE-2024-8105) | Secure Boot's chain of trust is broken: the PK private key is publicly known, so anyone can sign KEK/db/dbx updates the firmware accepts as authoritative. Structural presence of 2023 certs is moot. Overrides Compliant/Pending/Action Required. **OEM BIOS/firmware update required.** See [PK Trust & PKFail](#platform-key-pk-trust--pkfail). |
| 🔵 **Virtualized** | VMware PK signed with hypervisor owner GUID `a3d5e95b-0a8f-4753-8735-445afb708f62` (empty cert payload), **or** PK subject regex match on `VirtualBox` | Guest OS inherits Secure Boot from hypervisor firmware; cert rotation is hypervisor-managed. Routed to a neutral state instead of false-flagging Action Required. See [Hypervisor Detection](#hypervisor-detection-vmware--virtualbox). |
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
| **(Pending SVN Update)** | Any Enabled state | 1-2 SVN components missing, each with a prior firmware SVN. Next reboot should absorb. **Suppressed when firmware ≥ compliance floor.** |
| **(SVN Update Not Applied)** | Any Enabled state | Firmware booted after the DBX write and refused the SVN (`LastBootUpTime > max(Event 1034, Event 1042)`). OEM BIOS/firmware update may be required. Overrides Compliant. **Suppressed when firmware ≥ compliance floor.** |
| **(Pending SVN Reboot)** | Any Enabled state | All 3 SVN components missing and firmware hasn't booted past the DBX write yet - reboot will absorb. Falls through when none of the more-specific SVN overlays apply. **Suppressed when firmware ≥ compliance floor.** |
| **Pending (Not Opted In)** | Pending | Certs/KEK missing, no WU-delivery gap (no 1803), but WU opt-in for cert management is not enabled. Detail text prompts `securebootAction = "Enable opt-in"`. |
| **Triggered - \<result\>** | Compliant / Pending | When `securebootAction = Enable opt-in` runs the update this execution, the script re-checks servicing + events and overrides the resolved state to `Compliant` (servicing confirmed Updated / 1808 fired), `Pending` (1799 logged, in progress), or `Pending Cert Reboot` (reboot pending from CBS/WU). |

### Resolution Priority

The state machine combines multiple signals rather than relying on any single one. In priority order:

1. **Hardware class** - `NotApplicable` (non-UEFI) and `Disabled` short-circuit the rest.
2. **Hypervisor guest** - `Virtualized` short-circuits on VMware (PK signed with the hypervisor owner GUID) and VirtualBox (PK subject regex) guests; cert rotation is hypervisor-managed.
3. **PK trust** - If the Platform Key subject matches a placeholder (`AMI|DO NOT TRUST|Example`), `PKUntrusted` is resolved **before** any compliance check. Structural cert presence is irrelevant when the chain of trust is broken.
4. **Compliance ground truth** - Event 1808 **or** `UEFICA2023Status = Updated` → Compliant (with sub-state check for remaining cert deltas).
5. **All-mitigations-applied** - `has2023InDb` + Events 1799 + 1037 + 1042 → Compliant (pending 1808).
6. **Event-driven Pending** - Event 1801 or 1800 branches, refined by `has2023InDb`, `has2023InDbDefault`, `dbIsOsWritable`, KEK presence, Event 1803, and Event 1795.
7. **Silent Pending** - Secure Boot enabled, no state events - branches on cert location and OS-writability as above.
8. **Post-trigger override** - If the script triggered an OS-side update this run, final state is re-resolved against the post-trigger servicing registry and event re-read.
9. **Default** - `Unknown` (should only occur if signals contradict one another).

---

## What the Script Checks

### Certificate Audit

Microsoft is rotating to four new certificates. The script checks for each one individually:

| Location | New Certificate                                     | Old Certificate                                             | Role                                              |
|----------|-----------------------------------------------------|-------------------------------------------------------------|---------------------------------------------------|
| `db`     | Windows UEFI CA 2023 - Expires 2038                 | Microsoft Windows Production PCA 2011 - Expires Oct. 2026   | Signs Windows boot binaries                       |
| `db`     | Microsoft UEFI CA 2023 - Expires 2038               | Microsoft Corporation UEFI CA 2011 - Expires June 2026      | Signs third-party UEFI drivers/apps               |
| `db`     | Microsoft Option ROM UEFI CA 2023 - New             | Microsoft Corporation UEFI CA 2011 - Expires June 2026      | Now seperate CA, signs option ROMs (add-in cards) |
| `KEK`    | Microsoft Corporation KEK 2K CA 2023 - Expires 2038 | Microsoft Corporation KEK CA 2011 - Expires June 2026       | Signs updates to db/dbx                           |

Each cert is shown in the status card with a three-state icon: green (confirmed installed), blue (pending - triggered but not yet confirmed), or red (absent).

The script also checks `dbDefault` (firmware defaults) and reports exactly which certs are there - useful for understanding what a BIOS key reset would restore.

**Why the KEK matters:** The KEK is the authority that authorizes changes to the cert databases. Without the 2023 KEK, Windows Update can't push new certs into the firmware - even if the hardware supports it.

**2011 CA Revocation:** The script checks whether the old 2011 CAs have been revoked in `dbx`. This is the Stage 3 milestone - once revoked, old boot components can no longer load. The status card shows this with color-coded icons (green = done, blue = pending reboot, yellow = status unclear).

### Platform Key (PK) Trust & PKFail

The Platform Key is the apex of Secure Boot's chain of trust - it authorizes every KEK, which in turn authorizes every db/dbx change. If the PK is a placeholder or a publicly-leaked cert, the entire chain is compromised: anyone holding the private key can enroll rogue KEKs and sign arbitrary db/dbx updates.

The script parses the PK certificate subject and branches as follows:

| PK Subject Pattern | Result |
|--------------------|--------|
| `CN=DO NOT TRUST - AMI Test PK` (and variants matching `AMI\|DO NOT TRUST`) | **PK Untrusted** state - [PKFail / CVE-2024-8105](https://nvd.nist.gov/vuln/detail/CVE-2024-8105). `ERROR` logged. A dedicated "PK Security Alert" section is added to the card with a three-tier fix ladder. |
| Other placeholders matching `DO NOT\|Example` | **PK Untrusted** state - generic placeholder. `WARNING` logged. |
| Legitimate OEM CN (`CN=LENOVO`, `CN=Dell Inc.`, etc.) | No action - proceeds with normal audit. |

**Fix ladder (in order of preference):**

1. **Permanent:** OEM BIOS/firmware update that ships a legitimate PK from factory. OEM-specific links surfaced (Dell, HP, Lenovo, ASUS, Microsoft).
2. **Temporary:** The [CERT/CC PKFail script](https://github.com/CERTCC/PKfail/) uses the known AMI private key to re-sign and enroll [Microsoft's Windows OEM Devices PK](https://go.microsoft.com/fwlink/?linkid=2255361). Enrollment may not persist across firmware resets on all devices.
3. **Before either:** Suspend BitLocker on every protected volume - replacing the PK can invalidate TPM-sealed recovery keys.

Plain-English background: [Ars Technica - Secure Boot is completely compromised on 200 models from 5 big device makers](https://arstechnica.com/security/2024/07/secure-boot-is-completely-compromised-on-200-models-from-5-big-device-makers).

> When Event 1795 fires and the 2023 KEK is still missing on a device with a **legitimate** OEM PK, the PK inventory row is re-labeled `does not authorize KEK 2K CA 2023 - BIOS update required`. This is the OEM-KEK-authority blocker - distinct from PKFail. See [KEK Update Map](#kek-update-map-oem-signed-kek-availability).

### Factory Defaults (PKDefault / KEKDefault / dbDefault / dbxDefault)

Every UEFI system carries a set of *default* variables that are restored when the user performs "Reset Secure Boot to factory defaults" from BIOS. The script reads all four defaults and reports what would be restored:

| Default | What It Tells You |
|---------|-------------------|
| `PKDefault` | Whether the factory PK is a legitimate OEM cert or a placeholder (some OEMs ship with AMI Test PK in both live PK *and* PKDefault) |
| `KEKDefault` | Whether a BIOS key reset would restore the 2023 KEK, or kick you back to 2011-only |
| `dbDefault` | Which db certs a key reset would restore - exactly which 2023 certs are included |
| `dbxDefault` | Whether the factory DBX includes the PCA 2011 revocation (some OEM firmware updates bake this in) |

This matters because a BIOS key reset is a common troubleshooting step for Secure Boot problems, and knowing what state it lands in prevents surprise regressions.

### DBX Validation (Windows-Staged Revocation Files)

Whenever Secure Boot is Enabled, the script parses every `dbx*.bin` file Windows has staged under `C:\Windows\System32\SecureBootUpdates\` and compares each signature to the live firmware DBX. Output is classified three ways:

| Status | Meaning |
|--------|---------|
| **matched** | Signature is present in firmware DBX - the revocation landed. |
| **superseded** | SVN-keyed entry already covered by firmware. Two routes: (1) firmware SVN ≥ the staged entry's SVN (direct supersede), or (2) firmware SVN ≥ the documented [compliance floor](#svn-compliance-floor) for that component (floor supersede - prevents false flags when Microsoft pushes a staged file ahead of any actual enforcement bump, e.g. staged `8.0` while Stage 4 still enforces `8.0`). Not counted as missing. |
| **missing** | Signature is staged but firmware has not absorbed it yet. Deduped across `.bin` variants (Legacy twin counts once). |

A per-file breakdown surfaces on the card when anything is outstanding, so operators can see which `.bin` didn't land.

#### SVN-component miss classification

When any of the three SVN-keyed entries (`BootMgr` / `CdBoot` / `WdsMgr`) are outstanding, the card narrates **which** of four states the device is in:

| State | Signal | Meaning |
|-------|--------|---------|
| **Pre-rollout** | Every missing SVN component has no firmware SVN at all | Expected Stage 1/2 state - Microsoft has not pushed the revocation yet (rollout: June 2026 - 2027). Reassuring notice replaces the alarming per-component callout; per-file sub-rows are suppressed. |
| **Pending SVN Update** | 1-2 components missing, every missing component has a prior firmware SVN | Firmware at a prior SVN; the next reboot will absorb the update. |
| **SVN Update Not Applied** | All 3 missing, firmware has a prior SVN, and `LastBootUpTime > max(Event 1034, Event 1042)` | Firmware booted after the DBX write and still refused the SVN. OEM BIOS/firmware update may be required - surfaced in red to override "Compliant". |
| **Pending SVN Reboot** | All 3 missing, firmware has not booted past the DBX write yet | Staged update waiting on the next reboot. Generic catch-all - the three more-specific states above take precedence. |

> **Floor takes precedence over all four states.** When firmware SVN ≥ the documented [compliance floor](#svn-compliance-floor), every staged-but-firmware-newer SVN entry is reclassified as `superseded` (route 2 in the DBX Validation table above). With nothing left in `MissingComponents`, none of the four states fire and no overlay is rendered - the device is simply Compliant. The staged-vs-firmware delta still shows on the card as `Staged SVN: 8.0` next to `Firmware SVN: 8.0`, but it's informational only.

The pre-rollout branch is gated strictly on the SVN components having no firmware SVN. Unrelated missing hashes in `dbxupdate.bin` (a separate pre-1808 signal) do not block the reassurance - they surface under their own per-file row.

### KEK Update Map (OEM-Signed KEK Availability)

When firmware rejects the Microsoft-signed KEK 2K CA 2023 update (**Event 1795**), the OEM PK must re-sign the KEK payload before the firmware will accept it. The script consults Microsoft's [`kek_update_map.json`](https://github.com/microsoft/secureboot_objects/blob/main/PostSignedObjects/KEK/kek_update_map.json) to tell you whether a vendor-signed KEK package exists for this OEM yet.

When Event 1795 is present **and** the KEK 2023 is missing, the PK inventory row is re-labeled to make the blocker explicit:

> ❌ **PK: CN=OEM** *(does not authorize KEK 2K CA 2023 - BIOS update required)*

The card then surfaces the OEM BIOS update guide link. Without a legitimate OEM-signed KEK update, future db **and** dbx updates will break after the 2011 KEK expires (June 2026).

#### 1795 vs 1803 - two different root causes, two different fixes

| Event | What it means | Why KEK 2023 is missing | How it gets fixed |
|-------|---------------|-------------------------|-------------------|
| **1795** | Firmware **actively rejected** a KEK 2023 write attempt | The OEM PK does not carry the authority chain to sign/validate KEK 2K CA 2023 | **OEM BIOS/firmware update** that extends PK trust (or a manual BIOS key reset if `KEKDefault` already holds 2023). PK row flips to red X. |
| **1803** | OS **could not locate** a PK-signed KEK 2023 update to install | The OEM has not yet published a PK-signed KEK 2023 update to Microsoft for Windows Update to serve | **OEM publication** to Microsoft so WU delivers the KEK. **Not** a user BIOS update unless the OEM happens to bundle the new KEK into that firmware image. PK stays green - the PK itself is valid. |

1803 is a distribution gap rather than a PK authority issue. While this could be solved with an OEM firmware upadte, Windows should also be able to serve this when the OEM pushes it to Microsoft to serve vis WU. The script routes both to **Action Required** but narrates them separately in the card's Detail text so the correct remediation is obvious.

### Boot Media Scan

Attached removable / optical recovery media can carry **2011-signed boot managers** that become unbootable once PCA 2011 is revoked in DBX. The script scans for this risk:

| Mode | What It Checks | When to Use |
|------|----------------|-------------|
| **Default (surface scan)** | `\EFI\boot\boot*.efi` on each attached removable / optical volume. Flags 2011-signed binaries. | Always-on; fast. |
| **Deep scan** (`$deepBootMediaScan = $true`) | Additionally mounts `sources\boot.wim` and `sources\install.{wim,esd,swm}` via DISM / `Get-WindowsImage` and inspects the boot managers *inside* those images. | When install USBs look clean on the surface but may carry older bootmgr inside the WIM payload. Slower. |

Flagged media are called out in the card so the operator can re-image them with a 2023-signed boot manager **before** the DBX revocation lands. Microsoft's own guide: [Update Windows bootable media to use the PCA2023-signed boot manager](https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f).

### Hypervisor Detection (VMware / VirtualBox)

Virtual machines inherit Secure Boot from their hypervisor's virtual firmware rather than from a physical OEM BIOS. Running the CA 2023 rotation on a VM can look like an Action Required failure even when the guest OS is perfectly healthy, because the guest has no direct path to a firmware update.

The script detects hypervisor guests from the firmware PK directly:

| Hypervisor | Detection |
|------------|-----------|
| **VMware** | PK signature list signed with owner GUID `a3d5e95b-0a8f-4753-8735-445afb708f62` and an empty certificate payload. |
| **VirtualBox** | PK subject regex match on `VirtualBox`. |

Guests are routed to a neutral **Virtualized** state. The card explains that cert rotation is hypervisor-managed and the guest is out of scope. Hyper-V / QEMU / Xen guests with real OEM-style PK certs fall through to the normal audit; only hypervisors that advertise themselves in the PK are detected.

### Can Windows Update the Firmware Directly?

The script reads the UEFI `db` variable attributes using a low-level system call to determine if the firmware allows authenticated writes from the OS. This is how Windows Update pushes certificates into the BIOS without needing a firmware update.

It checks two things:
1. **UEFI attributes** - Does the firmware allow runtime writes? (`RUNTIME_ACCESS` + `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`)
2. **KEK authority** - Is the 2023 KEK present to sign the payload?

The UEFI attributes come from the `Attributes` property returned by Windows' inbox `Get-SecureBootUEFI -Name db` cmdlet during the script's existing database read. The script does not compile native firmware or token-management code at runtime.

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

**Blocker events** flag issues like BitLocker conflicts (1032), vulnerable bootloaders (1033), or an OEM KEK publication gap (1803 - no PK-signed KEK 2023 update available via Windows Update).

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

#### Five SVN values, one canonical sourcing contract

The card surfaces **five** SVN readings on every device, in the same shape regardless of cmdlet availability:

| Field | Source | Notes |
|---|---|---|
| **Firmware SVN** | Raw DBX (BootMgr GUID, max-by-`[version]`) | What firmware will enforce. Authoritative. |
| **Boot Manager SVN** | `Get-SecureBootSVN` cmdlet (`BootManagerSVN`) | SVN of the on-disk `bootmgfw.efi`. `N/A` without KB5077241. |
| **Staged SVN** | Raw parse of `DBXUpdateSVN.bin` | What the staged file *would* push on next absorb. ASN.1 wrapper stripped before parsing. |
| **CdBoot SVN** | Raw DBX (CdBoot GUID, max-by-`[version]`) | The CD/recovery boot component's SVN. Always raw - cmdlet doesn't surface it. |
| **WdsMgr SVN** | Raw DBX (WdsMgr GUID, max-by-`[version]`) | The WDS network-boot component's SVN. Always raw. |

The two raw-only components (`CdBoot` / `WdsMgr`) are useful as a parity readout when only `BootMgr` moves - and as a quick cross-check against [`SVN_Order.ps1`](https://github.com/user-attachments/files/26099026/SVN_Order.zip) for verifying the [PowerShell#27058](https://github.com/PowerShell/PowerShell/issues/27058) workaround on a device.

#### Two staged `.bin` files, two distinct rollout milestones

| File | Contents | Milestone |
|---|---|---|
| `DBXUpdate2024.bin` | Production CA 2011 revocation **+** BootMgr SVN `2.0` | Stage 3 - revokes the old Windows Production PCA 2011 |
| `DBXUpdateSVN.bin` | BootMgr SVN at the current rollout target | Stage 4 - rolls firmware SVN forward (target may bump over time) |

#### SVN Compliance Floor

Compliance is authoritative from `$script:SVN_COMPLIANCE_FLOORS` (default `8.0` for all three boot components, reviewed April 2026). **Firmware SVN ≥ floor → Compliant**, regardless of what value `DBXUpdateSVN.bin` happens to ship.

This matters because Microsoft sometimes bumps the staged file's SVN ahead of any actual enforcement change (e.g. the file ships `9.0` while Stage 4 still enforces `8.0`). This is per-model, and impossible to automate in a fleet, however the reccommended baseline as of current is 8.0. A device at the prior level is *at the enforcement target*, and must not be flagged as `(SVN Update Not Applied)` or `(Pending SVN Reboot)`. Bump the floor in the script per documented Microsoft milestones; one constant covers every consumer (the DBX classifier's "superseded" route 2, the headline compliance check, and the gate that suppresses the pending-reboot overlays).

#### PowerShell#27058 - cmdlet bug + cmdlet narrative both quarantined

[`Get-SecureBootSVN`](https://learn.microsoft.com/en-us/powershell/module/secureboot/get-securebootsvn?view=windowsserver2025-ps) returns the **DBX-order-last** BootMgr SVN entry instead of the numeric maximum. Symptom: `cmdlet=2.0` on a device the raw DBX clearly puts at `8.0`. The script:

1. **Replicates the cmdlet's parse logic** in `Get-DbxComponentSVNs` (mirrors [`SVN_Order.ps1`](https://github.com/microsoft/secureboot_objects) byte-for-byte: same GUID prefixes, same hex-substring SVN extraction, same `[version]` comparison) but does an explicit max-by-version select instead of letting DBX order decide.
2. **Always uses the raw value** for `Firmware SVN` - the cmdlet's `FirmwareSVN` field is treated as untrusted on every device. When they disagree, a `WARNING` is logged with the `#27058` reference so the bug signature is visible in the audit trail.
3. **Ignores the cmdlet's `ComplianceStatus` string** when the floor is met. The cmdlet computes its narrative ("Not compliant - Firmware does not match boot manager") from the same buggy `FirmwareSVN`, so a device at floor `8.0` would otherwise inherit a false "Not compliant" verdict. Floor met → script renders `Compliant (Firmware SVN 8.0 >= floor 8.0)` and the cmdlet's wording is dropped.
4. **Logs a per-component parity line every run**: `Raw DBX SVN per component (max-by-version): BootMgr=X | CdBoot=Y | WdsMgr=Z`. Identical format on every stage so the audit trail diffs cleanly against `SVN_Order.ps1` verbatim.

> A fix is in flight on Microsoft's end (Secure Boot team confirmed; expected in an upcoming Windows monthly update). The workaround stays in place because the June 2026 enforcement deadline can't wait for that build to roll out fleet-wide.

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

Both the ground truth (is the cert there?) and the manifest (did Windows finish processing it?) must pass. If anything fails, Mitigations 3+4 are blocked with a clear reason.

### BitLocker Safety Boundary

With `$suspendBitlockerForSVN` checked (`$true`, the default), the script enumerates encrypted Operating System and Fixed Data BitLocker volumes immediately before Stage 3/4. It calls `Suspend-BitLocker` with `-RebootCount 2`, refreshes each volume, and verifies that protection is suspended before writing the irreversible `AvailableUpdates` bits.

The same boundary is used for combined Stage 3+4 (`0x280`), Stage 3-only (`0x80`), and Stage 4-only (`0x200`) operations. A shared manifest safety pass runs in both Enforce and Passive/Audit modes, so pending bits written by Microsoft/WU, policy, or another tool receive the same BitLocker protection. Passive/Audit still does not initiate SVN enforcement.

Unsafe premature bits are repaired/cleared before either mode can trigger the Secure Boot task. Legitimate remaining bits honor the BitLocker checkbox. If an unsafe bit cannot be cleared, task execution is blocked and the script reports **do not reboot** regardless of the checkbox state; when suspension is enabled, BitLocker is also prepared as a fallback. A suspension failure with legitimate bits pending produces the same prominent warning. A failure during a new script-initiated operation prevents the Stage 3/4 registry/task trigger from being written.

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
| 14 | `0x4000` | Conditional qualifier (always present, notshown in output) |
| 2+14 | `0x4004` | KEK needs to be updated (combo) |

The script also reads `AvailableUpdatesPolicy` (GPO/MDM-driven, persists across reboots) and `HighConfidenceOptOut`. Unknown/undocumented bits are detected and flagged.

---

## Smart Handling

The script handles a lot of edge cases so you don't have to investigate them manually:

- **Stale events** - A 1801 event when the cert is already in `db` is flagged as stale (no false alarms)
- **OS-writable vs. not** - Correctly differentiates "Windows will handle it" from "you need to update the BIOS"
- **KEK validation** - Won't falsely report OS-writable when the KEK authority cert is missing
- **Trigger intelligence** - Won't re-trigger updates when Event 1800 (reboot needed) or 1799 (in progress) is present; these need time.
- **Delay detection** - `CanAttemptUpdateAfter` explains why an update hasn't happened yet
- **Error decoding** - Servicing error codes are translated to readable messages
- **Reboot correlation** - Confirms reboots happened between Event 1800 and 1799 using boot event cross-checks
- **Three-way KEK logic** - Missing KEK with OS-writable = Action Optional; with Event 1803 (no PK-signed KEK 2023 update available via WU - awaiting OEM publication to Microsoft, or BIOS update) = Action Required; neither = Pending with opt-in guidance
- **OEM-specific guidance** - BIOS update and key reset links for Dell, HP, Lenovo, ASUS, and Microsoft
- **BitLocker safety** - Automatically suspends encrypted OS/fixed-data volumes for 2 reboots at the Stage 3/4 boundary, blocks new triggers on failure, and reports each affected volume upstream
- **SVN safety** - Stage 1+2 prerequisite gate, passive mode safety checks, post-enforcement repair, boot-time cross-reference for reboot-pending detection, three-way SVN miss classification (PendingUpdate / SvnNotApplied / PartialCommit) so "firmware refused after reboot" never hides behind "pending reboot"
- **SVN firmware readout** - Works around [PowerShell#27058](https://github.com/PowerShell/PowerShell/issues/27058) by parsing the DBX bytes directly, picking the max by `[version]` across all three SVN-keyed GUIDs (BootMgr / CdBoot / WdsMgr) via the canonical `Get-DbxComponentSVNs` helper (mirrors [`SVN_Order.ps1`](https://github.com/microsoft/secureboot_objects) byte-for-byte). The cmdlet's `FirmwareSVN` is treated as untrusted on every device - the raw value always wins, with a `WARNING` logged on disagreement so the bug signature is visible. Card surfaces all five SVNs (Firmware / Boot Manager / Staged / CdBoot / WdsMgr) in the same shape regardless of cmdlet availability
- **SVN compliance floor** - `$script:SVN_COMPLIANCE_FLOORS` (default `8.0` for BootMgr / CdBoot / WdsMgr) is the authoritative compliance signal, not the cmdlet's `ComplianceStatus` string. Floor met → `Compliant (Firmware SVN X >= floor Y)`. The floor also feeds the DBX classifier's "superseded" route 2 and gates the `(Pending SVN Reboot)` / `(SVN update pending)` overlays so a higher-numbered staged SVN doesn't generate false-flag callouts on already-compliant devices. Bump per documented Microsoft milestones
- **PK trust detection** - Parses the Platform Key and surfaces PKFail / CVE-2024-8105 (AMI Test PK) as a dedicated red **PK Untrusted** state that overrides "Compliant" - structural cert presence is moot when the chain of trust is broken
- **PK-blocks-KEK signal** - When Event 1795 fires and the 2023 KEK is still missing on a *legitimate* OEM PK, the PK row is re-labeled "does not authorize KEK 2K CA 2023 - BIOS update required" so the real blocker is obvious (distinct from PKFail)
- **Hypervisor-aware** - VMware (via PK owner GUID) and VirtualBox (via PK subject regex) guests are routed to a neutral **Virtualized** state instead of being false-flagged as Action Required
- **Boot media scanning** - Attached USB / optical recovery media are scanned for 2011-signed boot managers; optional deep-scan mode inspects WIM images inside install media
- **DBX cross-check** - Live firmware DBX is compared against every `dbx*.bin` file Windows has staged locally (`C:\Windows\System32\SecureBootUpdates\`) for exact coverage past the "2011 CA revoked" SVN signal. SVN-keyed entries are counted as `superseded` (not missing) via two routes: (1) firmware SVN ≥ that entry's SVN, or (2) firmware SVN ≥ the documented compliance floor for that component. Distinguishes `DBXUpdate2024.bin` (BootMgr SVN `2.0` + 2011 CA revocation) from `DBXUpdateSVN.bin` (BootMgr SVN at the active rollout target). ASN.1 wrapper stripped before parsing both `.bin` files and the staged-SVN readout
- **Automatic fallback** - `Get-SecureBootUEFI -Decoded` when available, raw byte parsing when not. `Get-SecureBootSVN` cmdlet is consulted only for `BootManagerSVN` / `BootManagerPath` (no raw equivalent - cmdlet reads the on-disk boot manager binary); `FirmwareSVN` and `StagedSVN` always come from raw DBX so the contract is identical with or without KB5077241
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
| `Build-CertInventorySection` | Certificate inventory (three-state icons, PK trust / PKFail labels) |
| `Build-PkSecurityAlertSection` | PKFail / CVE-2024-8105 alert (rendered only when `$statusKey = 'PKUntrusted'`; two-`<details>` fix ladder + references) |
| `Build-FactoryDefaultsSection` | Factory defaults (`PKDefault`, `KEKDefault`, `dbDefault`, `dbxDefault`) |
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
- Returns X509 certificate objects either way and preserves the inbox cmdlet's UEFI `Attributes` value for the passive OS-writability check

---

## Sources

- [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) - Secure Boot hardening mitigations
- [CVE-2023-24932 Enterprise Deployment Guidance](https://support.microsoft.com/en-us/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967) - Enterprise deployment steps, combined Mitigation 3+4 (0x280)
- [KB5077241](https://support.microsoft.com/en-us/topic/february-24-2026-kb5077241-os-builds-26200-7922-and-26100-7922-preview-b8cc7bc8-d640-4f18-9437-3ee59298b970) - February 2025 update (Get-SecureBootSVN, -Decoded)
- [SecureBoot UEFI Boot Media](https://support.microsoft.com/en-us/topic/updating-windows-bootable-media-to-use-the-pca2023-signed-boot-manager-d4064779-0e4e-43ac-b2ce-24f434fcfa0f) - Update Boot Media to Pass updated SecureBoot verification
- [KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69) - Secure Boot event IDs
- [KB5084567](https://support.microsoft.com/en-us/topic/sample-secure-boot-e2e-automation-guide-f850b329-9a6e-40d1-823a-0925c965b8a0) - AvailableUpdates bitmask reference
- [garlin/SecureBoot-CA-2023-Updates](https://github.com/garlin-cant-code/SecureBoot-CA-2023-Updates) - SVN parsing, DBX byte reading
- [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) - Microsoft Secure Boot reference objects (DBX revocation list, KEK update map)
- [cjee21/Check-UEFISecureBootVariables](https://github.com/cjee21/Check-UEFISecureBootVariables) - UEFI variable inspection reference
- [Microsoft Official scripts](https://support.microsoft.com/en-us/topic/sample-secure-boot-e2e-automation-guide-f850b329-9a6e-40d1-823a-0925c965b8a0) - Detection and orchestration reference scripts
- [Microsoft Windows Secure Boot key creation & management guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11) - Microsoft's PK/KEK guidance including the Windows OEM Devices PK
- [CVE-2024-8105 (PKFail)](https://nvd.nist.gov/vuln/detail/CVE-2024-8105) - Publicly-leaked AMI Aptio V test PK affecting 200+ device models
- [CERT/CC PKfail](https://github.com/CERTCC/PKfail/) - Temporary-mitigation script that re-signs and enrolls the Microsoft-managed Windows OEM Devices PK

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-NewExample.png" alt="SecureBoot-Card-Example" width="420px" />
<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-LocalExampleLight.png" alt="SecureBoot-LocalCard-Example" width="420px" />
<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/SecureBoot%20Management/images/SecureBoot-LocalExampleDark.png" alt="SecureBoot-LocalCard-Example" width="420px" />

[PowerShell Script](https://github.com/SunshineSam/Scripts/blob/main/NinjaRMM/Windows/SecureBoot%20Management/SecureBoot-Management-CA2023.ps1)
