# 📬 Mange Windows Content Delivery Manager

## 🧠 Purpose

This script gives you **enterprise-grade control** over Windows content-delivery, Spotlight, Tips & Suggestions across **all user profiles**, including the Default hive. It lets you **enable or disable** dozens of registry-backed UI experiences in one pass:

- ✋ Eliminate unwanted **Welcome Experience** tips
- 🚫 Block **Lock screen facts**, ads & Spotlight
- 🏁 Turn off **Start menu** app suggestions
- ⚙️ Suppress **Settings** app recommendations
- 📦 Control **silent app installs** and **OEM preloads**
- 📲 Manage **OneDrive**, **Windows Ink**, **Sharing**, **Timeline**, **People**, **Feature Management** & more
- 👤 Apply uniform settings to **existing** and **new** user profiles

> 🔐 Perfect for privacy-focused, kiosk-mode, or corporate-managed desktops where **consistent UX policy** is mandatory.

---

## ⚙️ RMM Input Options

| **Variable**                       | **Type**       | **Description**                                                                                 |
|------------------------------------|----------------|-------------------------------------------------------------------------------------------------|
| **WelcomeContent**                 | *dropdown*     | `"Enabled"` or `"Disabled"` for **Welcome Experience**                                          |
| **LockScreenContent**              | *dropdown*     | `"Enabled"` or `"Disabled"` for **Lock Screen** facts/ads/Spotlight                             |
| **StartContent**                   | *dropdown*     | `"Enabled"` or `"Disabled"` for **Start menu** suggestions                                      |
| **SettingsContent**                | *dropdown*     | `"Enabled"` or `"Disabled"` for **Settings** app tips                                           |
| **InstallContent**                 | *dropdown*     | `"Enabled"` or `"Disabled"` for **SilentInstalledApps**                                         |
| **PreInstalledAppsContent**        | *dropdown*     | `"Enabled"` or `"Disabled"` for **OEM & preinstalled apps**                                     |
| **SuggestionsContent**             | *dropdown*     | `"Enabled"` or `"Disabled"` for **generic Windows tips & suggested apps**                       |
| **SyncProvidersContent**           | *dropdown*     | `"Enabled"` or `"Disabled"` for **OneDrive sync provider** notifications                        |
| **WindowsInkContent**              | *dropdown*     | `"Enabled"` or `"Disabled"` for **Windows Ink** suggestions                                     |
| **SharingContent**                 | *dropdown*     | `"Enabled"` or `"Disabled"` for **sharing service** suggestions                                 |
| **FeatureManagementContent**       | *dropdown*     | `"Enabled"` or `"Disabled"` for **feature management** settings                                 |
| **AppsContent**                    | *dropdown*     | `"Enabled"` or `"Disabled"` for **specific app suggestions** (e.g., BingWeather, Candy Crush)   |
| **PeopleContent**                  | *dropdown*     | `"Enabled"` or `"Disabled"` for **MyPeople** suggested apps                                     |
| **TimelineContent**                | *dropdown*     | `"Enabled"` or `"Disabled"` for **Timeline** suggestions (Task View)                            |
| **SpotlightContent**               | *dropdown*     | `"Enabled"` or `"Disabled"` for additional **Spotlight** controls                               |
| **BackgroundAccessContent**        | *dropdown*     | `"Enabled"` or `"Disabled"` for **CDM background activity**                                     |
| **UserProfileEngagementContent**   | *dropdown*     | `"Enabled"` or `"Disabled"` for **Get even more out of Windows** pop-ups                        |
| **IncludeDefaultHive**             | *checkbox*     | Apply settings also to the **Default user hive**                                                |
| **CDMState**                       | *dropdown*     | **"Allow"** or **"Block"** all Content-Delivery features (overrides individual toggles)         |
| **SaveLogToDevice**                | *checkbox*     | Save logs to `C:\Logs\CDM\CDM.log` (default: `true`)                                            |

> ⚙️ All parameters can also be set via **environment variables** (e.g. `welcomeContent`, `cdmState`, `includeDefaultHive`, etc.).

---

## 🔧 How It Works

1. **Elevation Check**  
   Verifies Administrator privileges; exits if not elevated.

2. **Hive Discovery**  
   Enumerates all **user SIDs** under `HKLM:\...\ProfileList` and (optionally) the **Default** user hive.

3. **Hive Loading**  
   Loads each `NTUSER.DAT` into `HKEY_USERS\<SID>` for direct registry edits.

4. **Registry Mapping**  
   Defines **groups** of registry values (Welcome, LockScreen, Start, etc) and their paths under:
   - `...\ContentDeliveryManager`  
   - `...\Explorer\Advanced`  
   - `...\PenWorkspace`  
   - `...\BackgroundAccessApplications`  
   - `...\UserProfileEngagement`

5. **Master Switch (CDMState)**  
   - **Block**: Forces **CDM related** groups to "Disabled"
   - **Allow**: Forces **CDM related** groups to "Enabled"
   - **Not set**: Honors only explicitly passed parameters

6. **Individual Toggles**  
   Applies any parameter-level enable/disable values
   via a robust `RegistryShouldBe` function with retry logic.

7. **Cleanup**  
   Unloads all loaded hives and writes a completion log entry.

---

## ✅ Use Cases

- Enforce a **"clean" Windows experience** with no unwanted tips, ads, or suggestions
- Standardize UI behavior across **every** user and **new** profiles
- Harden **kiosk**, **VDI**, or **shared workstation** environments
- Simplify **IT policy rollout** for Windows 10/11 content and feature toggles
- Audit and troubleshoot via **comprehensive logging**

---

> 🎯 Achieve **consistent, scalable control** over Windows UI suggestions and content-delivery across your entire organization.