# 🔑 Set Logon Account (LogonUI)

## 🧠 Purpose

This script **pins a specific account to the Windows sign-in screen**, so the next person at the device lands on the right user tile with the right sign-in method already selected. The benefits are:

- ✅ **Works for both local and domain accounts**, with validation against the device's joined domain
- ✅ **Selects the sign-in method** for the tile (Password, Windows Hello Face/PIN, Smart Card, FIDO key, or Cloud)
- ✅ **Clears stale LogonUI state** first, so old users and old provider mappings can't compete with the new default
- ✅ **Resolves the SID and display name** for you, so the only input is the user name
- ✅ **Refreshes LogonUI.exe** automatically when run as SYSTEM, so the change shows up without a reboot
- ✅ **Won't make changes while someone is signed in**, since LogonUI ignores the pinned user while a session exists

> ⚙️ Useful for shared, kiosk, or freshly imaged devices where you want the sign-in screen to point at a specific account instead of whoever last signed in.

---

## 📦 Prerequisites

- PowerShell **5.1** or later
- **Administrator** privileges (run as **SYSTEM** from NinjaRMM so LogonUI can be refreshed)
- The target account must **already exist** on the device (local) or in the joined domain
- **No users signed in** to the device, including locked or disconnected sessions

---

## 🔧 Set Logon Account
_Sets the "last logged on user" and sign-in provider that LogonUI shows by default_

### 💻 RMM Input Options

| **Variable**           | **Type**     | **Description**                                                                                          |
|------------------------|--------------|----------------------------------------------------------------------------------------------------------|
| **$LogonUser**         | *string*     | **Required.** Account to pin: `User` (local) or `DOMAIN\User` (domain). See [`LogonUser`](#logonuser).    |
| **$AuthMethod**        | *dropdown*   | Sign-in method for the tile. Defaults to `Password`. See [`AuthMethod`](#authmethod).                    |
| **$SaveLogToDevice**   | *checkbox*   | Save logs to `C:\Logs\LogonUI\LogonUIUser.log` on the device. Defaults to true.                          |

> ⚙️ All parameters can also be set with **environment variables**: `logonUser`, `loginAuthMethod`, and `saveLogToDevice`.

### 🎯 Parameter Deep-Dive

#### `$LogonUser`

The script decides whether the account is local or domain from how the name is written.

| Input Format | Treated As | What It Does |
|--------------|------------|--------------|
| **User** | Local account | Resolves the SID as `COMPUTERNAME\User` and writes `.\User` to LogonUI, which matches how Windows shows local accounts. |
| **DOMAIN\User** | Domain account | Only allowed when the device is joined to that domain. The domain can be the NetBIOS name or the FQDN (e.g. `Domain` or `Domain.local`). |
| **DOMAIN\User** on a non-domain device | Rejected | Exits with an error. A domain user can't be pinned on a workgroup device. |
| **user@domain** (UPN) | Rejected | Not supported. Use `DOMAIN\User` instead. |

> **Display name**: The tile's display name comes from the account's **Full Name** when one is set. Otherwise the plain user name is used (never `.\User`).

#### `$AuthMethod`

Chooses which credential provider the tile opens with. The matching GUID is written to both `LastLoggedOnProvider` and the account's `UserTile` entry.

| Value | Provider GUID | What It Does |
|-------|---------------|--------------|
| **Password** *(default)* | `{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}` | Standard password sign-in. |
| **Windows Hello Face** | `{8AF662BF-65A0-4D0A-A540-A338A999D36F}` | Windows Hello facial recognition. |
| **Windows Hello PIN** | `{2135F72A-90B5-4ED3-A7F1-8BB705AC276A}` | Windows Hello PIN. |
| **Smart Card** | `{8FD7E19C-3BF7-489B-A72C-846AB3678C96}` | Smart card sign-in. |
| **FidoKey** | `{F8A1793B-7873-4046-B2A7-1F318747F427}` | FIDO2 security key. |
| **Cloud** | `{C5D7540A-CD51-453B-B22B-05305BA03F07}` | Cloud Experience provider (Microsoft / Entra accounts). |

> **Note**: The chosen method has to actually be set up for that account (e.g. a PIN must be enrolled for **Windows Hello PIN**). If it isn't, Windows falls back to whatever providers the account does have.

### 🗂️ Registry Values

All values live under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`.

| **Value**                      | **Set To**                                 |
|--------------------------------|--------------------------------------------|
| **LastLoggedOnUser**           | `DOMAIN\User` or `.\User`                  |
| **LastLoggedOnSAMUser**        | `DOMAIN\User` or `.\User`                  |
| **LastLoggedOnDisplayName**    | Full Name, or the plain user name          |
| **LastLoggedOnUserSID**        | Account SID                                |
| **SelectedUserSID**            | Account SID                                |
| **LastLoggedOnProvider**       | Provider GUID for `$AuthMethod`            |
| **`UserTile\<SID>`**           | Provider GUID for `$AuthMethod`            |

> **UserTile is kept to a single entry**: Windows only honors one SID mapping, so every other SID under `UserTile` is removed before the new one is written.

---

## 🔍 How It Works

1. **Pre-flight Checks**
   - Exits if not running as Administrator or if `$LogonUser` is empty.
   - Maps `$AuthMethod` to its provider GUID.

2. **Signed-In Account Check**
   - Looks for any signed-in account (active, locked, or disconnected/RDP) by checking who owns `explorer.exe` and who is on the console.
   - If anyone is found, it logs a **WARNING** listing each account and exits with code `1`. **Nothing is changed.**

3. **LogonUI Refresh (before)**
   - When running as SYSTEM, ends any running `LogonUI.exe` and lets Windows restart it.

4. **Identity Resolution**
   - Works out whether the account is local or domain, checks the domain against the device's joined domain, and resolves the SID and display name.
   - If the SID can't be resolved, the script exits with code `1` before touching the registry.

5. **Clear Existing State**
   - Removes the existing `LastLoggedOn*`, `SelectedUserSID`, and `LastLoggedOnProvider` values, and clears every `UserTile` SID mapping.

6. **Write New State**
   - Writes each registry value through `RegistryShouldBe`, which retries up to 5 times and checks the value after each write.
   - Writes the single `UserTile\<SID>` mapping.

7. **LogonUI Refresh (after)**
   - When running as SYSTEM, restarts `LogonUI.exe` again so the sign-in screen shows the new default right away.

> **Not running as SYSTEM?** The registry changes still apply, but LogonUI isn't restarted. The new default appears the next time the sign-in screen loads.

---

## ⚠️ Things To Know

- **Sign out, don't lock.** A locked or disconnected session still counts as signed in, and the script will exit without changes. Have the user fully sign out (or reboot) and run it again.
- **User hives aren't touched.** The script only edits the machine-wide LogonUI key and never loads or changes `NTUSER.DAT`.
- **This sets a default.** It picks which tile is selected; it doesn't stop anyone from choosing another account or sign-in method.
- **The next sign-in takes over.** When someone signs in, Windows records them as the last user as usual. Run the script again (e.g. on a schedule) to re-pin.

---

## ✅ Use Cases

- Point **shared or kiosk devices** at a dedicated account every time
- **Hand off a freshly imaged device** with the new owner already on the sign-in screen
- Default users to **Windows Hello PIN / Face** or a **FIDO key** instead of a password
- Get rid of a **tech's or admin's account** showing as the last user after on-site work
- Standardize the sign-in screen across **workgroup** and **domain-joined** devices

> 🎯 Take the guesswork out of the sign-in screen by pinning the right account and sign-in method on every device.
