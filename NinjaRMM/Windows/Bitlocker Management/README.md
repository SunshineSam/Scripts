# 🔐 All Things BitLocker

## 🧠 Purpose

This BitLocker suite **completely solves BitLocker management pain-points**, especially for mixed environments, or environments lacking AAD, Intune, or on-prem AD. It is:

- ✅ **Agnostic** to AD and Azure/Intune
- ✅ **Integrates seamlessly** with hybrid, workgroup, or disconnected environments
- ✅ **Enforces consistency** with encryption and protection states across devices
- ✅ **Tracks all BitLocker details** with custom field support
- ✅ **Automatically** rotates and securely stores recovery keys
- ✅ **Outputs formatted WYSIWYG cards** for visibility and executive reporting
- ✅ **Easily implement** into RMM workflows (e.g., NinjaRMM) with minimal setup

> ⚙️ This is a built from scratch solution to bridge real world gaps in IT environments, compliance needs, and automation.

---

## 📦 Prerequisites

- PowerShell **5.1** or later
- **Administrator** privileges
- NinjaRMM custom fields created for BitLocker status and recovery key

---

## 🔧 BitLocker Management
_Manages encryption state, rotates/stores recovery keys, and publishes a consolidated HTML status card_

### 💻 RMM Input Options

| **Variable**                   | **Type**     | **Description**                                                                    |
|--------------------------------|--------------|------------------------------------------------------------------------------------|
| **$MountPoint**                | *string[]*   | Volume letter(s) to process (e.g., C:, D:). Defaults to system volume.             |
| **$ApplyToAllFixedDisk**       | *switch*     | If set, targets all fixed disks (ignores **$MountPoint**).                         |
| **$BitLockerProtection**       | *dropdown*   | Desired action: Enable, Maintain, Suspend, or Disable. See [`BitLockerProtection`](#bitlockerprotection). |
| **$RecoveryKeyAction**         | *dropdown*   | Recovery key operation: Ensure, Rotate, or Remove. See [`RecoveryKeyAction`](#recoverykeyaction). |
| **$BitlockerEncryptionMethod** | *dropdown*   | Encryption method: Aes128, Aes256, XtsAes128, XtsAes256 (default). See [`BitlockerEncryptionMethod`](#bitlockerencryptionmethod). |
| **$UseTpmProtector**           | *switch*     | Enforce TPM protector. Defaults to true.                                           |
| **$UseUsedSpaceOnly**          | *switch*     | Encrypt only used space when enabling. Defaults to true.                           |
| **$BackupToAD**                | *switch*     | Backup recovery keys to AD/AAD. Defaults to false.                                 |
| **$SaveLogToDevice**           | *switch*     | Save logs to `C:\Logs\BitLockerManagement.log` on the device. Defaults to false.   |

> **Maintain mode**: Keeps all drives in their current encryption state — does not enable, disable, suspend, or resume BitLocker. Only reconciles protectors (TPM, recovery key), generates status cards, and backs up recovery keys. Fully decrypted drives are skipped. Useful for key rotation or protector enforcement without changing drive state.

### 🎯 Parameter Deep-Dive

Each of the three dropdowns has clearly defined behavior and cross-parameter guardrails. The script auto-corrects incompatible combinations before any BitLocker operation runs — see [Cross-Parameter Enforcement](#cross-parameter-enforcement) below.

#### `$BitLockerProtection`

Controls the protection state applied to each target volume.

| Value | What It Does |
|-------|--------------|
| **Enable** | Enables BitLocker from a fully-decrypted state, **or** resumes protection on a suspended volume. Uses `$BitlockerEncryptionMethod` and `$UseUsedSpaceOnly` when starting fresh encryption. Enforces `$UseTpmProtector` and ensures a recovery key per `$RecoveryKeyAction`. Auto-unlock is enabled for non-OS volumes when `$AutoUnlockNonOSVolumes` is true. |
| **Maintain** | **No state changes.** Reconciles protectors (TPM, recovery key), manages auto-unlock, updates the status card, and backs up recovery keys. Fully-decrypted drives are skipped. Use this for key rotation or protector enforcement on already-encrypted fleets without touching the encryption state. |
| **Suspend** | Suspends BitLocker for `$SuspensionRebootCount` reboots (default 1). Ensures TPM and recovery-key protectors exist first. Skips volumes currently encrypting (`EncryptionInProgress`) or already suspended. |
| **Disable** | Fully decrypts the volume via `Disable-BitLocker`. If targeting the OS volume, auto-unlock is disabled on all data drives first (required — auto-unlock depends on the OS volume's key). **Forces** `$RecoveryKeyAction = Remove`. |

> **Enable is idempotent**: running Enable on an already-encrypted volume does not re-encrypt — it just reconciles protectors and refreshes the status card. Safe to schedule on a cron.

#### `$RecoveryKeyAction`

Controls the `RecoveryPassword` protector lifecycle. Always evaluated against the current protector set on each volume.

| Value | What It Does |
|-------|--------------|
| **Ensure** | Guarantees **exactly one** `RecoveryPassword` protector exists. If duplicates are found, the newest is kept and the rest are removed. If none exists, a new one is generated. If exactly one valid key is already present, this is a no-op. |
| **Rotate** | Removes the existing `RecoveryPassword` protector and generates a new one. Requires the volume to be encrypted — **skipped on fully-decrypted volumes** (rotation without encryption is meaningless). The previous key is tracked internally to confirm the rotation actually changed the protector ID before writing to the secure field. |
| **Remove** | Deletes the `RecoveryPassword` protector entirely. **Only permitted when the volume is fully-decrypted AND protection is off.** Blocked when `$PreventKeyPromptOnEveryBoot` is true. Forced automatically when `$BitLockerProtection = Disable`. |

> **Rotate preserves continuity**: the old key stays valid in AD/AAD backup (if `$BackupToAD` is true) until the new key backup succeeds. The script never removes a key without confirming its replacement is live.

#### `$BitlockerEncryptionMethod`

Controls the encryption algorithm **only when starting fresh encryption** (fully-decrypted → encrypting). Ignored on resume, suspend, maintain, and disable paths — you cannot re-encrypt an existing volume with a different algorithm without fully decrypting it first.

| Value | What It Does |
|-------|--------------|
| **Aes128** | Legacy AES-CBC 128-bit. Compatible with pre-Windows 10 v1511 systems and removable media. **Not recommended** for new fixed-disk encryption. |
| **Aes256** | Legacy AES-CBC 256-bit. Same compatibility caveats as Aes128. **Not recommended** for new fixed-disk encryption. |
| **XtsAes128** | XTS-AES 128-bit. Modern mode designed for disk encryption, resistant to ciphertext manipulation. Appropriate for fixed disks where performance is a concern. |
| **XtsAes256** *(default)* | XTS-AES 256-bit. Strongest option, recommended for all modern fixed-disk encryption. |

### 🛠️ Other Optional Management Options

| **Variable**                       | **Type** | **Description**                                                    |
|------------------------------------|----------|--------------------------------------------------------------------|
| **$PreventKeyPromptOnEveryBoot**   | *switch* | Always keep TPM & key protectors to prevent boot-time prompts.     |
|**$AutoUnlockNonOSDrives**          | *switch* | Auto-unlock non-OS drives when enabling. Defaults to true.         |
| **$SuspensionRebootCount**         | *int*    | Number of reboots allowed while suspended. Defaults to 1.          |
| **$AutoReboot**                    | *switch* | Reboot after enablement. Defaults to false.                        |

### 🛡️ Safety Options

| **Variable**                     | **Type** | **Description**                                                      |
|----------------------------------|----------|----------------------------------------------------------------------|
| **$VerifyRecoveryKeyStorage**    | *switch* | Verifies recovery key storage before encryption. Writes a realistic-sized test payload to the secure field, reads it back from the agent cache to confirm permissions and field capacity, then waits 60 seconds for the agent to sync to the NinjaRMM console before proceeding. **Requires** the secure field to have "Read/Write" (Automation) permissions enabled. Defaults value is true.

> **USB Drives**: USB-connected drives are always blacklisted from processing, even if Windows classifies them as "Fixed." This is unconditional and not configurable. USB drives will never be encrypted by this script.

> **Important**: `$VerifyRecoveryKeyStorage` requires the NinjaRMM secure custom field to have **Read/Read** (Automation) permissions enabled. If these permissions are not set and the parameter is `$true`, the script will abort before any encryption occurs with a clear error message. This is intentional, encryption without verified key storage risks data loss.
>
> **Note on NinjaRMM agent caching**: `Ninja-Property-Set` writes to the agent's local cache. `Ninja-Property-Get` reads from that same local cache. The agent checks in to the NinjaRMM console approximately every 60 seconds and flushes any cached changes at that time. The read-back verification confirms the cache write succeeded (permissions, field capacity, no truncation), but there is no agent-side API to confirm the data reached the server. After cache verification passes, the pre-flight waits 60 seconds for the agent to complete a check-in cycle before proceeding. This provides a best-effort sync window and allows live console viewers to visually confirm the test data arrived.

### 🔓 Auto-Unlock

Auto-unlock for non-OS volumes uses `Enable-BitLockerAutoUnlock` to enable. Each attempt starts with a clean slate — disabling any existing auto-unlock entries and removing all orphaned `ExternalKey` protectors so only one (the auto-unlock key) exists on the volume. If the cmdlet fails after 3 attempts, BitLocker is **automatically disabled** on the volume to prevent an inaccessible drive after reboot. AutoUnlock only applies to internal Fixed Drives, not USB Fixed Drives.
>
> The **Status Cards** reports AutoUnlock state for non-OS volumes by confirming autounlock results for each volume.

### 🔐 Custom-Field Options

| **Variable**                      | **Type**   | **Description**                                                                      |
|-----------------------------------|------------|--------------------------------------------------------------------------------------|
| **$BitLockerStatusFieldName**     | *string*   | Custom WYSIWYG field name for the status card(s). Defaults to "BitLockerStatusCard." |
| **$RecoveryKeySecureFieldName**   | *string*   | Custom secure field for recovery key(s). Defaults to "BitLockerRecoveryKey."         |

### 🎨 Card Customization

| **Variable**                 | **Type**   | **Description**                                                         |
|------------------------------|------------|-------------------------------------------------------------------------|
| **$CardTitle**               | *string*   | Card title. Defaults to "Bitlocker Status."                             |
| **$CardIcon**                | *string*   | FontAwesome icon (e.g., fas fa-shield-alt).                             |
| **$CardBackgroundGradient**  | *string*   | Background gradient. "Default" omits styling.                           |
| **$CardBorderRadius**        | *string*   | Border radius (e.g., 10px). Defaults to 10px.                           |
| **$CardSeparationMargin**    | *string*   | Margin between cards (e.g., 0 8px). Defaults to 0 8px.                  |

---

## 🔧 BitLocker Status  
_Read-only reporting for all fixed disks; collects recovery keys and renders a single HTML status card_

### 💻 RMM Input Options

| **Variable**             | **Type**   | **Description**                                                                    |
|--------------------------|------------|------------------------------------------------------------------------------------|
| **$SaveLogToDevice**     | *switch*   | Save logs to `C:\Logs\BitLockerManagement.log` on the device. Defaults to false.   |
| **$UpdateRecoveryKeys**  | *switch*   | Force update of stored recovery keys. Defaults to true.                            |

### 🛡️ Safety Options

| **Variable**                     | **Type**   | **Description**                                                                    |
|----------------------------------|------------|------------------------------------------------------------------------------------|
| **$VerifyRecoveryKeyStorage**    | *switch*   | Runs a pre-flight check before collecting recovery keys — writes a realistic-sized test payload to the secure field, reads it back to confirm permissions and field capacity. If the pre-flight fails, recovery keys are not collected or stored for that run. **Requires** the secure field to have "Read/Write" (Automation) permissions. Defaults to true.

> **USB Drives**: USB-connected drives are always blacklisted from reporting, even if Windows classifies them as "Fixed." This is unconditional and not configurable.

### 🔐 Custom-Field Options

| **Variable**                      | **Type**   | **Description**                                                                      |
|-----------------------------------|------------|--------------------------------------------------------------------------------------|
| **$BitLockerStatusFieldName**     | *string*   | Custom WYSIWYG field name for the status card(s). Defaults to "BitLockerStatusCard." |
| **$RecoveryKeySecureFieldName**   | *string*   | Custom secure field for recovery key(s). Defaults to "BitLockerRecoveryKey."         |

> **IMPORTANT**: Onece more (as stated above), the Secure Field **Requires** Read/Write (Automation) permissions for the VerifyRecoveryKeyStorage paremater to work.

### 🎨 Card Customization

| **Variable**                 | **Type**   | **Description**                                                         |
|------------------------------|------------|-------------------------------------------------------------------------|
| **$CardTitle**               | *string*   | Card title. Defaults to "Bitlocker Status."                             |
| **$CardIcon**                | *string*   | FontAwesome icon (e.g., fas fa-shield-alt).                             |
| **$CardBackgroundGradient**  | *string*   | Background gradient. "Default" omits styling.                           |
| **$CardBorderRadius**        | *string*   | Border radius (e.g., 10px). Defaults to 10px.                           |
| **$CardSeparationMargin**    | *string*   | Margin between cards (e.g., 0 8px). Defaults to 0 8px.                  |

---

## 📜 Script Details

- **Management**
  Enable, maintain, suspend, or disable BitLocker; rotate and store all recovery keys in a single secure field; output HTML status card(s) for all fixed disk.

- **Status**  
  Query BitLocker status on every fixed disk; optionally collect up-to-date recovery key(s); output HTML status card(s) without making changes.

---

## ✅ Use Cases

- Enforce BitLocker compliance across **workgroup**, **hybrid**, or **domain-joined** machines
- Automate **recovery key rotation** and secure storage
- Deliver **single-click visibility** via WYSIWYG cards in NinjaRMM
- Schedule **regular status checks** for auditing or imaging workflows
- Standardize encryption methods and **suspend/re-enable for imaging** or patching
- Provide **real-time visibility** into BitLocker status through WYSIWYG reports
- Eliminate reliance on AAD, Intune, or Group Policy for full BitLocker lifecycle management
- Store critical encryption data securely within your RMM for **auditing or support**

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/Bitlocker%20Management/images/MultiVolumeExample.png" alt="BitLocker Multi-Volume View Example" width="660px" />
