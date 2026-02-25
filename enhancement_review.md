# Enhancement Review: PhantomPeel Forensic Tool

## 1. Current State Assessment

**PhantomPeel v1.1** is a robust baseline for detecting common spoofer artifacts. It excels at:
- **Registry-based Driver Enumeration:** Efficiently identifies kernel drivers and checks for non-standard paths.
- **Entropy Analysis:** Detects random-named folders often used by spoofers to hide payloads.
- **Forensic Cleaning:** Provides a targeted "nuke" option for common persistence mechanisms (Run keys, Tasks).
- **System Integrity Baseline:** Uses a local JSON file to track hardware changes over time.

### ⚠️ Current Weaknesses
1. **Shallow Registry Analysis:** Only looks at active services, not historical hardware records in `Enum` keys.
2. **Generic HWID Queries:** Relies on standard WMI calls which are easily intercepted by modern "kernel-mode" spoofers.
3. **No Network Fingerprinting:** Does not validate if the MAC address matches a legitimate manufacturer (OUI).
4. **Missing Security Posture Check:** Does not report on TPM or Secure Boot status, which are often disabled to run spoofers.
5. **Limited Artifact List:** Targeting is primarily focused on `infsoft`, while many modern spoofers use different naming conventions.

---

## 2. Modern Spoofer Detection Trends (2024-2025)

Modern anti-cheats (Vanguard, Ricochet) have moved beyond simple serial checks. To match them, PhantomPeel should incorporate:

### A. Registry Deep-Dive (The "Paper Trail")
Spoofers often change the "current" serial but fail to clean the historical records in:
- `HKLM\SYSTEM\CurrentControlSet\Enum\PCI`
- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI`
**Action:** Cross-reference current IDs with these historical entries. If a "new" disk appears without a corresponding history, it's a red flag.

### B. Network OUI Validation
A randomly generated MAC address (e.g., `00:1A:2B:3C:4D:5E`) might not belong to any known manufacturer.
**Action:** Check the first 3 bytes against a database of OUIs.

### C. The "HideMachine" Detection
A common "lazy" spoofing technique involves setting a registry key to hide WMI details.
**Action:** Check `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Restrictions\HideMachine`.

### D. Hardware-Backed Security
Most spoofers require **Secure Boot** to be OFF or **Test Signing** to be ON.
**Action:** Detect and report these states.

---

## 3. Proposed Enhancements (Roadmap)

### Phase 1: Security Posture (Immediate)
- [x] Add Secure Boot status check. (Implemented v1.1)
- [ ] Add TPM availability check.
- [x] Add "Test Signing" mode detection (`bcdedit` query). (Implemented v1.1)

### Phase 2: Deep Fingerprinting
- [x] **MAC OUI Check:** Flag MAC addresses that don't belong to real vendors. (Implemented v1.1)
- [ ] **Registry History Scan:** Scan `Enum` keys for old hardware IDs.
- [ ] **Monitor Serial Query:** Retrieve EDID data to find the monitor's true serial.

### Phase 3: Advanced Cleaning
- [ ] **USN Journal Analysis:** (Advanced) Check the Update Sequence Number journal for traces of deleted spoofer files.
- [ ] **Event Log Clearing Detection:** Check if Event Logs were recently cleared (a common "cleaner" tactic).

---

## 4. High-Tier Anti-Cheat Analysis (2025-2026)

Target games: *COD (Ricochet)*, *Delta Force (ACE)*, *Apex/PUBG (EAC/BE)*, *Arc Raiders (EAC+Proprietary)*.

### A. Tencent ACE (Anti-Cheat Expert)
ACE is extremely aggressive, particularly in *Delta Force*. It uses **VT-d (Directed I/O)** to detect DMA hardware and leaves multiple persistent services:
- **Services:** `ACE-BASE`, `ACE-GAME`. These must be sc-deleted and re-checked after reboot.
- **Shadow Registry:** ACE scans `Enum\PCI` history. If your current GPU serial doesn't match the historical PCI installation date/record, you are flagged.

### B. Ricochet (Call of Duty)
Focuses on **Root of Trust (TPM 2.0)**.
- **Remote Attestation:** Verifies TPM status directly with servers. Spoofing the TPM often breaks the "handshake," leading to instant shadow bans.
- **Timing Attacks:** Measures IO response times. Any micro-delay from a spoofer driver (hooking `DeviceIoControl`) is detected.

### C. Embark (Arc Raiders)
Combines EAC with **Cerebro AI** for behavioral analysis.
- **Behavioral Fingerprinting:** Even with a perfect HWID spoof, if your mouse movement entropy (Anybrain) matches a banned player, the system will link and ban the new identity.

---

## 5. Conclusion
The implementation of Option 6 (Forensic Clean) was a major step forward. To stay relevant against 2026 high-tier anti-cheats, PhantomPeel must evolve from an "Artifact Hunter" into a "System Integrity Validator" that looks for inconsistencies in hardware-rooted security (TPM/UEFI) and historical registry trails.
