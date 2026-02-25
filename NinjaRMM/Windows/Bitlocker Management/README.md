# 🔐 All Things BitLocker

## 🧠 Purpose

This BitLocker suite **completely solves BitLocker management pain-points**, especially for mixed environments, or environments lacking AAD, Intune, or on-prem AD. It is:

- ✅ **Agnostic** to AD and Azure/Intune
- ✅ Operates seamlessly across hybrid, workgroup, or disconnected environments
- ✅ Enforces consistent encryption and protection state across devices
- ✅ Tracks all BitLocker details with custom field support
- ✅ Automatically rotates and securely stores recovery keys
- ✅ Outputs formatted WYSIWYG cards for visibility and executive reporting
- ✅ Easily integrates into RMM workflows (e.g., NinjaRMM) with minimal setup

> ⚙️ This is a built from scratch solution to bridge real world gaps across IT environments, compliance needs, and automation.

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
| **$BitLockerProtection**       | *dropdown*   | Desired action: Enable, Maintain, Suspend, or Disable.                             |
| **$RecoveryKeyAction**         | *dropdown*   | Recovery key operation: Ensure, Rotate, or Remove.                                 |
| **$BitlockerEncryptionMethod** | *dropdown*   | Encryption method: Aes128, Aes256, XtsAes128, XtsAes256 (default).                 |
| **$UseTpmProtector**           | *switch*     | Enforce TPM protector. Defaults to true.                                           |
| **$UseUsedSpaceOnly**          | *switch*     | Encrypt only used space when enabling. Defaults to true.                           |
| **$BackupToAD**                | *switch*     | Backup recovery keys to AD/AAD. Defaults to false.                                 |
| **$SaveLogToDevice**           | *switch*     | Save logs to `C:\Logs\BitLockerManagement.log` on the device. Defaults to false.   |

> **Maintain mode**: Keeps all drives in their current encryption state — does not enable, disable, suspend, or resume BitLocker. Only reconciles protectors (TPM, recovery key), generates status cards, and backs up recovery keys. Fully decrypted drives are skipped. Useful for key rotation or protector enforcement without changing drive state.

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

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/Bitlocker%20Management/images/MultiDriveExample.png" alt="BitLocker Multi-Drive View Example" width="360px" />
