# 🗂️ All Things Explorer

## 🧭 Purpose

This suite of scripts lets you **centrally manage** user and machine **Explorer settings**, **Search Highlights policy**, and **network drive mappings**-all via RMM. You'll be able to:

- 🔒 Enforce file-extension visibility, compact mode, and post-upgrade Start layout  
- 🚫 Enable or disable Windows Search Highlights via Group Policy registry  
- 🔄 Seamlessly remap network drives from one UNC prefix to another, with fallback logic  
- 📋 Apply changes machine-wide and per-user (or under SYSTEM for all profiles)  
- 📑 Maintain **full logs** for auditing and troubleshooting  

> 🎯 Whether you're standardizing UX, tightening policy, or migrating file shares-this toolkit gives you **precision-level control** across your estate.

---

## 📦 Prerequisites

- **PowerShell 5.1** or later  
- **Administrator** privileges for machine-wide and SYSTEM-context actions  
- RMM environment with ability to pass parameters via **environment variables** if desired

---

## ⚙️ RMM Input Options

### 1️⃣ Explorer Advanced Options

| **Variable**             | **Type**     | **Description**                                                                                 |
|--------------------------|--------------|-------------------------------------------------------------------------------------------------|
| **HideFileExtension**    | *dropdown*   | `Enable` = **hide** file extensions;<br>`Disable` = **show** file extensions                    |
| **UseCompactMode**       | *dropdown*   | `Enable` = **compact view** in Explorer;<br>`Disable` = standard spacing                        |
| **StartShowOnUpgrade**   | *dropdown*   | `Enable` = **show** Start layout after an upgrade;<br>`Disable` = hide it                       |
| **RestartExplorer**      | *checkbox*   | If set, **restarts** Explorer after applying per-user settings                                  |

### 2️⃣ Windows Search Highlights Policy

| **Variable**               | **Type**     | **Description**                                                           |
|----------------------------|--------------|---------------------------------------------------------------------------|
| **EnableDynamicContent**   | *checkbox*   | `$true` = **enable** Search Highlights (remove override); `$false` = **disable** them (set policy DWORD = 0) |
| **ForceRestartExplorer**   | *checkbox*   | If set, **restarts** Explorer and the Windows Search service (WSearch)   |

### 3️⃣ Network Drive Remapping

| **Variable**            | **Type**     | **Description**                                                                                   |
|-------------------------|--------------|---------------------------------------------------------------------------------------------------|
| **OldUNCPrefix**        | *string*     | The old UNC prefix for existing network drives (e.g. `\\Server1`)                                 |
| **NewUNCPrefix**        | *string*     | The new UNC prefix for remapped drives (e.g. `\\Server2`)                                         |
| **ForceNewMapping**     | *checkbox*   | If set, proceeds even if temporary mapping of the old UNC fails                                   |

---

## 📜 Script Details

### 🔧 1. Explorer Advanced Options

Applies **machine-wide** and **per-user** registry toggles under:
- `HKLM:\...\Explorer\Advanced`
- `HKCU:\...\Explorer\Advanced` (or loaded hives for SYSTEM context)

**Actions**:
- Hides/shows file extensions (`HideFileExt`)
- Enables/disables compact mode (`UseCompactMode`)
- Shows/hides Start after upgrade (`StartShowOnUpgrade`)
- Optionally restarts Explorer for immediate effect

---

### 🔎 2. Windows Search Highlights Policy

- Targets the policy key: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search
EnableDynamicContentInWSB`
- **Disable**: sets DWORD = 0
- **Enable**: removes the override property
- Runs `gpupdate /force`
- Optionally restarts Explorer & WSearch service

---

### 🛜 3. Network Drive Remapping

Scans **mapped drives** (`DriveType=4`), and for each that matches `$OldUNCPrefix`:

1. Determines actual base UNC and relative path
2. Allocates a **temporary drive letter** for safe parsing
3. Unmaps the original drive and maps the new UNC to the **same** letter
4. Cleans up the temporary mapping or reverts on failure
5. Supports a **ForceNewMapping** fallback

---

## ✅ Use Cases

- Standardize **Explorer behavior** and enforce a **consistent UI** across desktops
- Disable all **Search Highlights** on kiosks, VDI, or privacy-sensitive machines
- **Remap** user network drives during print-server or file-server migrations
- Automate **policy rollout** and **connections** without manual input or scripting per machine

---

> 🎯 Whether you're shaping Explorer UX, toggling Search Highlights, or migrating network shares-this suite gives you **hands-free, audit-ready control**.