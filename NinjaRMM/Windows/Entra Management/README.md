# 🧭 Autopilot Hardware ID

## 🧠 Purpose

This script solves the challenge of collecting and securely storing **Windows Autopilot hardware hashes** across fleets - **without requiring Intune** or complex onboarding tools.

- ✅ Gathers the Autopilot **hardware hash** directly via CIM
- ✅ Stores the result securely in **NinjaRMM custom fields**
- ✅ Designed for use in **automated, zero-touch provisioning pipelines**
- ✅ Optional **local logging** for transparency and auditing
- ✅ Operates silently, reliably, and without user interaction

> 🔐 Perfect for hardware pre-enrollment workflows where devices must be registered in Autopilot **before** being handed off.

---

## ⚙️ RMM Input Options

| **Variable**                    | **Type**    | **Description**                                                                            |
|---------------------------------|-------------|--------------------------------------------------------------------------------------------|
| **$AutoPilotSecureCustomField** | *string*    | Name of the **secure** custom field to store the Autopilot hash (default: `AutopilotHWID`) |
| **$SaveLogToDevice**            | *checkbox*  | If checked, logs are saved locally on the device                                           |

---

## 🔧 How It Works

1. **🔍 Parameter Handling**
   - Accepts `$AutoPilotSecureCustomField` to define the secure field name (optional).
   - Checks for `env:AutopilotHWIDPropertyName` and uses it if available.
   - Exits with an error if no valid property name is found.

2. **💻 CIM Query**
   - Queries the `root/cimv2/mdm/dmmap` namespace for the `MDM_DevDetail_Ext01` class.
   - Extracts the `DeviceHardwareData` property — the full Autopilot hardware hash.

3. **❗ Error Handling**
   - If CIM query fails or returns no data, the script logs and exits with a clear error.
   - If `Ninja-Property-Set` is missing (outside RMM), the property update is skipped safely.

4. **🔐 Secure Field Update**
   - Injects the hash into the defined **secure custom field** via `Ninja-Property-Set`.
   - Note: THe secure field will need a large character limit

5. **📝 Logging (Optional)**
   - If `$SaveLogToDevice` is enabled, stores a local timestamped log of success/failure.
   - Log path is standard but can be modified directly in the script.

---

## ✅ Use Cases

- Automate **Autopilot hardware registration** across environments
- Build a **pre-staging process** for Windows device provisioning
- Provide vendors or technicians with a **hash dump pipeline** for future use
- Avoid manual gathering steps with a **secure, trackable, RMM-native** process

> 📦 Utilize with future automation to for **Autopilot registration** if the secure field is read/write.

---