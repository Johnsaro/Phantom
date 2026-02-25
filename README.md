# PhantomPeel — Driver & Spoofer Forensics Tool

PhantomPeel is a specialized forensics utility designed to detect traces of Windows kernel drivers and spoofer artifacts (specifically targeting **infsoft / Infinite Spoofer**).

## ⚠️ Prerequisites

- **Operating System**: Windows 10/11 (64-bit).
- **Python Version**: Python 3.8 or higher.
- **Permissions**: **Must be run as Administrator** to access the Windows Registry and System32 directories.

## 🚀 How to Run

1. **Open PowerShell or CMD as Administrator.**
2. **Navigate to the script directory**:
   ```powershell
   cd "C:\Users\saroj\OneDrive\Documents\projects\PhantomPeel"
   ```
3. **Execute the script**:
   ```powershell
   python phantom_peel.py
   ```

## 🛠️ Main Features

| Feature | Description |
| :--- | :--- |
| **Driver Sweep** | Scans the Windows Registry for all kernel/FS drivers. Flags drivers in non-standard locations or those created since Jan 2025. |
| **Artifact Hunt** | Searches for random-named folders, recent `.sys` drops, and known launcher filenames. Now specifically targets your identified spoofer folder. |
| **Deep Forensics** | Analyzes MUICache, ShimCache, and Prefetch for execution traces. Now includes a check for the `HideMachine` registry bypass. |
| **Security Posture** | Reports on **Secure Boot** status and **Test Signing** mode, which are often manipulated by spoofers. |
| **Network Fingerprint** | Validates your MAC address against the **OUI (Organizationally Unique Identifier)** to detect randomly generated spoofed addresses. |
| **HWID Integrity** | Displays and tracks your hardware serials (Disk, Motherboard, GPU, BIOS, RAM, MAC) against a "SAFE" baseline. |
| **Forensic Clean** | **[Option 6]** Aggressively targets and removes persistence (Run keys, Tasks) and execution traces to restore system integrity. |
| **Export Report** | Generates a detailed JSON report in your `Downloads` folder for further analysis. |

## 📊 Understanding the Output

- **Red Flags [!]**: High-probability artifacts or unsigned kernel drivers.
- **Yellow Flags [!]**: Suspicious items (e.g., files created since your spoofer installation in early 2025).
- **Green [+]**: Clean scans or valid digital signatures.

## 📁 Output Location
When you select **Option [5] Export Report**, the tool will save a JSON file named `phantompeel_report_YYYYMMDD_HHMMSS.json` to:
`C:\Users\<User>\Downloads`

## 🛡️ Best Practices: Baselining

Hardware spoofers generally fall into two categories:
1. **Temporary Spoof:** Clears on reboot. These are safer to detect using a baseline.
2. **Permanent Spoof:** Modifies firmware or registry persistently. These require manual verification against physical stickers or purchase receipts.

**CRITICAL:** Only use **Option [4] Lock Identity** when you are 100% certain your system is "clean." 
- **Recommended Flow:** Reboot your PC -> Do NOT run any launchers or spoofers -> Run PhantomPeel -> Verify IDs match your physical hardware -> **Option [4] Lock Identity**.
- If you lock your identity while a spoofer is active, the tool will treat those "fake" IDs as your SAFE baseline, rendering the integrity check useless.
