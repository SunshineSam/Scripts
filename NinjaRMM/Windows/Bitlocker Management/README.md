# 🔐 All Things BitLocker

## 🧠 Purpose

This BitLocker suite **completely solves BitLocker management pain-points**, especially in environments lacking AAD, Intune, or on-prem AD. It is:

- ✅ **Agnostic** to domain, Azure AD, or Intune status  
- ✅ Operates seamlessly across hybrid, workgroup, or disconnected environments  
- ✅ Enforces consistent encryption and protection state across devices  
- ✅ Tracks all BitLocker details with custom field support  
- ✅ Automatically rotates and securely stores recovery keys  
- ✅ Outputs formatted WYSIWYG cards for visibility and executive reporting  
- ✅ Easily integrates into RMM workflows (e.g., NinjaRMM) with minimal setup

> ⚙️ This is a built from scratch solution to bridge real world gaps across IT environments, compliance needs, and automation. This will make you want to enforce Bitlocker!

---

## 📦 Prerequisites

- PowerShell **5.1** or later  
- **Administrator** privileges  
- NinjaRMM custom fields created for BitLocker status and recovery key

---

## 🔧 BitLocker Management WYSIWYG  
_Manages encryption state, rotates/stores recovery keys, and publishes a consolidated HTML status card_

### 💻 RMM Input Options

| **Variable**                   | **Type**     | **Description**                                                                         |
|--------------------------------|--------------|-----------------------------------------------------------------------------------------|
| **$MountPoint**                | *string[]*   | Drive letter(s) to process (e.g., C:, D:). Defaults to system drive.                    |
| **$ApplyToAllFixedDisk**       | *switch*     | If set, targets all fixed disks (ignores **$MountPoint**).                              |
| **$BitLockerProtection**       | *dropdown*   | Desired action: Enable, Suspend, or Disable.                                            |
| **$RecoveryKeyAction**         | *dropdown*   | Recovery key operation: Ensure, Rotate, or Remove.                                      |
| **$BitlockerEncryptionMethod** | *dropdown*   | Encryption method: Aes128, Aes256, XtsAes128, XtsAes256 (default).                      |
| **$UseTpmProtector**           | *switch*     | Enforce TPM protector. Defaults to true.                                                |
| **$UseUsedSpaceOnly**          | *switch*     | Encrypt only used space when enabling. Defaults to true.                                |
| **$BackupToAD**                | *switch*     | Backup recovery keys to AD/AAD. Defaults to false.                                      |
| **$SaveLogToDevice**           | *switch*     | Save logs to `C:\Logs\BitLockerManagement.log` on the device. Defaults to false.        |

### 🛠️ Other Optional Management Options

| **Variable**                       | **Type** | **Description**                                                    |
|------------------------------------|----------|--------------------------------------------------------------------|
| **$PreventKeyPromptOnEveryBoot**   | *switch* | Always keep TPM & key protectors to prevent boot-time prompts.     |
|**$AutoUnlockNonOSDrives**          | *switch* | Auto-unlock non-OS drives when enabling. Defaults to true.         |
| **$SuspensionRebootCount**         | *int*    | Number of reboots allowed while suspended. Defaults to 1.          |
| **$AutoReboot**                    | *switch* | Reboot after enablement. Defaults to false.                        |

### 🔐 Custom-Field Options (WYSIWYG Field Names)

| **Variable**                      | **Type**   | **Description**                                                                |
|-----------------------------------|------------|--------------------------------------------------------------------------------|
| **$BitLockerStatusFieldName**     | *string*   | Custom field name for the HTML status card. Defaults to "BitLockerStatusCard." |
| **$RecoveryKeySecureFieldName**   | *string*   | Secure field for recovery keys. Defaults to "BitLockerRecoveryKey."            |

### 🎨 Card Customization

| **Variable**                 | **Type**   | **Description**                                                         |
|------------------------------|------------|-------------------------------------------------------------------------|
| **$CardTitle**               | *string*   | Card title. Defaults to "Bitlocker Status."                             |
| **$CardIcon**                | *string*   | FontAwesome icon (e.g., fas fa-shield-alt).                             |
| **$CardBackgroundGradient**  | *string*   | Background gradient. "Default" omits styling.                           |
| **$CardBorderRadius**        | *string*   | Border radius (e.g., 10px). Defaults to 10px.                           |
| **$CardSeparationMargin**    | *string*   | Margin between cards (e.g., 0 8px). Defaults to 0 8px.                  |

---

## 🔧 BitLocker Status WYSIWYG  
_Read-only reporting for all fixed disks; collects recovery keys and renders a single HTML status card_ 

### 💻 RMM Input Options

| **Variable**             | **Type**   | **Description**                                                                    |
|--------------------------|------------|------------------------------------------------------------------------------------|
| **$SaveLogToDevice**     | *switch*   | Save logs to `C:\Logs\BitLockerManagement.log` on the device. Defaults to false.   |
| **$UpdateRecoveryKeys**  | *switch*   | Force update of stored recovery keys. Defaults to true.                            |

### 🔐 Custom-Field Options (WYSIWYG Field Names)

| **Variable**                      | **Type**   | **Description**                                                                |
|-----------------------------------|------------|--------------------------------------------------------------------------------|
| **$BitLockerStatusFieldName**     | *string*   | Custom field name for the HTML status card. Defaults to "BitLockerStatusCard." |
| **$RecoveryKeySecureFieldName**   | *string*   | Secure field for recovery keys. Defaults to "BitLockerRecoveryKey."            |


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

- **Management WYSIWYG**  
  Enable, suspend, or disable BitLocker; rotate and store all recovery keys in one secure field; output a consolidated HTML card for NinjaRMM.

- **Status WYSIWYG**  
  Query BitLocker status on every fixed disk; collect recovery keys; output a single HTML card without making changes.

---

## ✅ Use Cases

- Enforce BitLocker compliance across **workgroup**, **hybrid**, or **domain-joined** machines
- Automate **recovery key rotation** and secure storage in RMM
- Deliver **single-click visibility** via WYSIWYG cards in NinjaRMM
- Schedule **regular status checks** for auditing or imaging workflows
- Standardize encryption methods and **suspend/re-enable for imaging** or patching
- Provide **real-time visibility** into BitLocker status through WYSIWYG reports
- Eliminate reliance on AAD, Intune, or Group Policy for full BitLocker lifecycle management
- Store critical encryption data securely within your RMM for **auditing or support**

<img src="https://raw.githubusercontent.com/SunshineSam/Scripts/main/NinjaRMM/Windows/Bitlocker%20Management/images/ExampleView.png" alt="BitLocker Multi-Drive View Example" width="40%" />