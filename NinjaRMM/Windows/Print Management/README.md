# 🖨️ All Things Print Management

## 🧠 Purpose

This print management suite streamlines and automates **local printer ACL configuration**, **system print queue restoration**, and **network printer migration**. Whether you're **delegating access**, **securing queues**, or **repointing shared printers**, this solution offers:

- ✅ **Granular ACL control** over who can print, manage printers, or manage documents
- ✅ **Full reprovisioning** of built-in printers like *Fax* and *Microsoft Print to PDF*
- ✅ **UNC migration utility** for moving users from one print server to another
- ✅ **Robust logging** for audits, support, and visibility
- ✅ **Zero-dependency remediation** using built-in drivers
- ✅ Seamless integration with **RMM tools** (like NinjaRMM)

> 🎯 Designed for environments where **printer control**, **access enforcement**, and **automated recovery** matter.

---

## 📦 Prerequisites

### 🛂 Printer Permissions Script

#### 💻 RMM Input Options

| **Variable**                   | **Type**   | **Description**                                                                |
|--------------------------------|------------|--------------------------------------------------------------------------------|
| **$PrinterName**               | *string*   | Exact name of the local printer                                                |
| **$PrinterPrincipal**          | *string*   | Group or user (e.g., `BUILTIN\Everyone`, `DOMAIN\Users`)                       |
| **$PrintPermission**           | *dropdown* | `"Allow"` or `"Deny"` access to **Print**                                      |
| **$ManagePrinterPermission**   | *dropdown* | `"Allow"` or `"Deny"` access to **Manage this Printer**                        |
| **$ManageDocumentsPermission** | *dropdown* | `"Allow"` or `"Deny"` access to **Manage Documents**                           |
| **$RemovePrincipal**           | *checkbox* | If set, removes all ACEs for the principal and exits immediately               |
| **$SaveLogToDevice**           | *checkbox* | Saves log to `C:\Logs\Print Management\Permissions.log` (default: `true`)      |

---

## 📜 Script Details

### 🔐 Printer ACL Management

Adds, updates, or removes ACLs (Access Control Lists) for printers with **fine-grained access control**. Ideal for delegated print management or environment-specific restrictions.

**Key Features**:
- Preserves all existing ACEs unrelated to target
- Applies Windows security logic (e.g., **Deny overrides Allow**)
- Normalizes invalid combinations (e.g., Deny Print → Deny everything)
- Computes access masks for:
  - 🖨️ **Print** = `READ_CONTROL + PRINTER_ACCESS_USE`
  - 🛠️ **Manage Printer** = `STANDARD_RIGHTS_REQUIRED + ADMINISTER + USE`
  - 📄 **Manage Documents** = `STANDARD_RIGHTS_REQUIRED + JOB_ADMIN + JOB_READ`
- Logs all actions for audit/debug
- Requires **Administrator privileges**

---

### 🛠️ Printer Reprovision Script

#### 💻 RMM Input Options

| **Variable**        | **Type**   | **Description**                                                           |
|---------------------|------------|---------------------------------------------------------------------------|
| **$PrinterType**    | *dropdown* | `"Fax"` or `"Microsoft Print to PDF"` <br> *(passed via env:printerType)* |

---

### 🔁 Built-in Printer Reprovisioning

This utility **remediates missing or broken Windows printers**, such as **Fax** and **Print to PDF**, without external downloads or drivers.

**Key Actions**:
- Stops the **Print Spooler**
- Removes existing printer + port
- Uses built-in drivers:
  - `msfax.inf` for **Fax**
  - `prnms009.inf` for **Microsoft Print to PDF**
- Enables **Print to PDF** feature if disabled
- Recreates required ports (e.g., `FAX:`)
- Adds printer via `PrintUIEntry`
- Verifies printer installation

> 🧼 Useful for **automated recovery** across managed devices
> ✅ Runs **offline** using Windows-native components

---

### 🔄 UNC Printer Migration Script

#### 💻 RMM Input Options

| **Variable**             | **Type**   | **Description**                                                              |
|--------------------------|------------|------------------------------------------------------------------------------|
| **$OldUNCPath**          | *string*   | The old print server UNC path (e.g., `\\Server1`)                            |
| **$NewUNCPath**          | *string*   | The new print server UNC path (e.g., `\\Server2`)                            |
| **$CopyPreferences**     | *checkbox* | If set, attempts to copy printer preferences from old to new                 |

---

### 🔁 Shared Printer Migration (Old UNC → New UNC)

This script migrates mapped printers from one print server to another for the **current user**, using UNC path substitution. Designed for **zero-interruption transitions** during server cutovers.

**Key Features**:
- Identifies all mapped network printers beginning with the old UNC
- Automatically:
  - Adds replacement connection from the new UNC path
  - Copies duplexing/tray settings (when supported)
  - Preserves **default printer** setting
  - Removes the original printer entry
- Includes a timeout and fallback if the new connection fails
- Fully non-intrusive - works silently under user context

> 🧩 Ideal for **print server migrations**, **domain transitions**, or **printer standardization efforts**.

---

> 🎯 Whether you're controlling access, migrating print servers, or restoring built-in printers - this growing suite gives you **granular policy enforcement**, **user-side redirection**, and **hands-free recovery** across your entire environment.