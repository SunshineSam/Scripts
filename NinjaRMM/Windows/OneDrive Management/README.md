# ☁️ All Things OneDrive

## 🧠 Purpose

This collection of scripts solves the ongoing pains of **OneDrive visibility and control** in managed environments by offering:

- 📊 **Real-time health visibility** of OneDrive sync and folder redirection (via WYSIWYG card)
- 🧹 **Complete removal utility** for all known OneDrive installs (System, MSI, AppData)
- 🔐 **RMM-native deployment**, designed for use with NinjaRMM Secure Fields and Custom Fields
- 🧰 Clean separation between **reporting**, **sync status tracking**, and **removal logic**

> ℹ️ These scripts give you **control**, **clarity**, and **customization** over how OneDrive behaves and reports - without relying on user interaction.

---

## ⚙️ WYSIWYG Sync Status Script Options

### 📥 RMM Input Options

| **Variable**                    | **Type**   | **Description**                                                                   |
|---------------------------------|------------|-----------------------------------------------------------------------------------|
| **$SaveLogToDevice**            | *checkbox* | If set, saves log to `C:\Logs\OneDrive\OneDriveInfo.log`                          |
| **$OneDriveWYSIWYGCustomField** | *string*   | WYSIWYG custom field for the generated status card (default: `OneDriveStatusCard`)|

### 🎨 Card Customization Options

| **Variable**                | **Default**               | **Description**                                                |
|-----------------------------|---------------------------|----------------------------------------------------------------|
| **$CardTitle**              | `OneDrive Config Details` | Custom HTML card title                                         |
| **$CardIcon**               | `fas fa-cloud`            | FontAwesome icon for the card                                  |
| **$CardBackgroundGradient** | `Default`                 | Background gradient (disabled in NinjaRMM, fallback to none)   |
| **$CardBorderRadius**       | `10px`                    | CSS-style border radius                                        |
| **$CardIconColor**          | `#0364b8`                 | Hex color for icon styling                                     |

---

## 🧾 Script Details

### 🟦 OneDrive Sync Status (WYSIWYG)

- Runs a script block as the **current user** to access per-user sync data.
- Tracks:
  - Sync state (Up-to-date, Not syncing, Problems)
  - Last successful sync timestamp
  - Folder redirection status (Documents, Desktop, etc.)
  - Active **SharePoint Libraries**, if applicable
- Generates a **responsive NinjaRMM WYSIWYG card** showing sync health and folder paths
- Temporary JSON files are created at `C:\temp\` and **auto-cleaned**
- Fully supports scheduled runs for **routine OneDrive monitoring**

> 🔎 This is ideal for proactively monitoring sync failures and SharePoint library issues in real-time — directly inside NinjaRMM.

---

### 🗑️ OneDrive Removal Utility

Script to fully **remove**, **disable**, or **clean up** OneDrive using parameterized switches.

#### 🔧 Uninstall Toggles

| **Variable**              | **Type**    | **Description**                                                  |
|---------------------------|-------------|------------------------------------------------------------------|
| **$SystemUninstall**      | *checkbox*  | Removes OneDrive from `System32` / `SysWOW64`                    |
| **$PreInstalledUninstall**| *checkbox*  | Removes OEM/MSI installs from `Program Files`                    |
| **$UserProfileUninstall** | *checkbox*  | Removes per-user `AppData` installs                              |

#### 🚫 Cleanup & Disablement Options

| **Variable**                     | **Type**    | **Description**                                                 |
|----------------------------------|-------------|-----------------------------------------------------------------|
| **$ApplyGPO**                    | *checkbox*  | Sets registry GPO to disable OneDrive system-wide               |
| **$RemoveFromExplorerSidebar**   | *checkbox*  | Removes OneDrive from File Explorer sidebar                     |
| **$RemoveScheduledRun**          | *checkbox*  | Deletes scheduled tasks tied to OneDrive startup                |
| **$RemoveRunHook**               | *checkbox*  | Deletes `NTUSER.DAT` entry to block OneDrive for new users      |
| **$RestartExplorer**             | *checkbox*  | Restarts Explorer.exe to clean up UI elements                   |

> 🧼 This script allows **selective removal**, deep cleanups, and **hard disablement** with zero user prompts. Ideal for locked-down environments, kiosk mode, or VDI setups.

---

## ✅ Use Cases

- Gain real-time OneDrive sync insight for **fleet health monitoring**
- Remove OneDrive or monitor OneDrive agnostically
- Standardize OneDrive management **without end user involvement**
- Integrate into **scheduled RMM jobs** for proactive maintenance

> 🎯 Whether you're monitoring or eliminating OneDrive - you now have **precision-level control** and **reliable reporting**, all through RMM.

---