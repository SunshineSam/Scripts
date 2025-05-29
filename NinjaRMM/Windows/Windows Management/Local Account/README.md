# 👤 Local Account Creation & LAPS

## 🧭 Purpose

This script creates or updates a local administrator account with a **strong randomized password**, securely stores that password into a **NinjaRMM secure field**, and enforces best practices like **password expiration**, **admin group control**, and **automatic credential rotation**.

> 🔐 This is a drop-in local admin lifecycle solution for RMM managed environments - supporting full automation, rotation, and secure credential syncing.

---

## ⚙️ RMM Input Options

| **Variable**                   | **Type**     | **Description**                                                                |
|--------------------------------|--------------|--------------------------------------------------------------------------------|
| **AdminUsername**              | *string*     | Username of the local account to create or manage (default: `"Admin"`)         |
| **PasswordSecureFieldName**    | *string*     | Secure custom field for storing password (default: `"LocalAdminPassword"`)     |
| **OverridePassword**           | *checkbox*   | If set, forcibly resets the password for existing accounts                     |
| **PasswordNeverExpires**       | *checkbox*   | Marks the password and account to never expire                                 |
| **AddToAdministrators**        | *checkbox*   | Adds/removes the account from the local Administrators group                   |

---

## 🧠 How It Works

1. **Parameter Resolution & Validation**
   - Resolves inputs from direct parameters or `env:` values.
   - Checks elevation and exits if not run as Administrator.

2. **Account Creation**
   - If the account does **not exist**:
     - Generates a secure password (14–18 chars, 4–6 non-alphanumeric).
     - Converts to `SecureString`, creates account with options.
     - Immediately stores plaintext password into Ninja secure field.
     - Clears memory of all sensitive content.
     - Handles Administrators group membership.

3. **Account Update**
   - If the account **exists**:
     - Resets password **only** if `OverridePassword` is set.
     - Updates NinjaRMM secure field if password changed.
     - Applies `PasswordNeverExpires` setting if passed.
     - Adjusts admin group membership based on checkbox.
     - Clears memory of sensitive variables securely.

4. **Security Handling**
   - Passwords are **never left in memory longer than needed**.
   - `SecureString` and plain values are **nulled and cleared** immediately.
   - No password is written or logged outside of Ninja Secure Field.
   - **Elevation is required** — script will not run otherwise.

---

## 🔐 Secure Field Behavior

- The **Ninja Secure Field** is only updated if:
  - A new account is created, **or**
  - An existing account has its password forcibly reset.
- If `OverridePassword` is **not** set, and the account exists, the current password remains unchanged, and **no field update is made**.

---

## ✅ Use Cases

- Enforce consistent, secure **admin account deployment**.
- Enable per-device local admin access **without sharing credentials**.
- Auto-rotate local passwords and push them to RMM **securely**.
- Comply with least privilege by dynamically removing from Administrators if needed.
- Run post-deployment or as **scheduled account rotation** job.

> 🎯 Whether you're deploying a new device or rotating credentials quarterly - this script gives you **full local admin lifecycle control** within NinjaRMM.