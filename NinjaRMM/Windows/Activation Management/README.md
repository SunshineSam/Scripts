# 💻 Windows Activation

## 🧠 Purpose

This script automates **Windows activation** by intelligently applying the device’s embedded **OEM BIOS product key** when needed.
It eliminates the guesswork in managing activation states across fleets and helps ensure **license compliance** with minimal intervention.

> 🔐 Designed for IT environments where reprovissioning occurs, maintaining reliable activation.

---

## ⚙️ Parameters

### 🔧 Required / Optional Inputs

| **Variable**         | **Type**   | **Description**                                                                 |
|----------------------|------------|---------------------------------------------------------------------------------|
| **`$ForceBIOSKey`**  | *switch*   | Forces reactivation using the BIOS-embedded product key, regardless of status   |
| **`$SaveLogToDevice`** | *switch* | If set, logs activation steps to `C:\Logs\Product Activation\Activation.log`    |

---

## 🧾 Script Behavior

The script activates Windows using the embedded **BIOS OEM key** if **any** of the following conditions apply:

- The current key is one of the **generic defaults** (commonly seen in volume-licensed or OEM misconfigs)
- Windows is **not activated**
- The **`$ForceBIOSKey`** flag is set explicitly

---

### 📦 Generic Keys Checked

These well-known generic keys are used to determine if replacement is required:

| **Key (partial)** | **Edition**              |
|-------------------|--------------------------|
| `3V66T`           | Windows 10/11 Pro        |
| `8HVX7`           | Windows 10/11 Home       |
| `2YT43`           | Windows 10/11 Enterprise |
| `NW6C2`           | Windows 10/11 Education  |

---

## 🔄 Actions Performed

1. **Retrieves** the current Windows activation status and partial product key
2. **Validates** if the key is generic or the system is unactivated
3. If needed, it performs:
   - ✅ `slmgr.vbs /ipk` ➜ Installs the embedded OEM key from BIOS
   - ✅ `slmgr.vbs /ato` ➜ Activates Windows via standard online method

---

> 🎯 Whether used for post-imaging cleanup, misconfigured OEM installs, or compliance enforcement - this script ensures **Windows is properly licensed** and **securely activated**.