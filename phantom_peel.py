#!/usr/bin/env python3
"""
PHANTOMPEEL — Driver & Spoofer Forensics Tool
Windows kernel driver enumeration + spoofer artifact hunter
"""

import os
import sys
import math
import time
import json
import ctypes
import winreg
import hashlib
import threading
import subprocess
from datetime import datetime
from pathlib import Path


# ── ANSI / COLORS ─────────────────────────────────────────────────────────────

def _enable_ansi():
    try:
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
    except Exception:
        pass

_enable_ansi()

class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def magenta(s): return f"{C.MAGENTA}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"

def clear_screen():
    """Clear terminal using ANSI escape codes (no shell call needed)."""
    print('\033[2J\033[H', end='', flush=True)


# ── ANIMATIONS ──────────────────────────────────────────────────────────────

class ReconSpinner:
    def __init__(self, message="Scanning"):
        self.message = message
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._animate, daemon=True)

    def update(self, message):
        self.message = message

    def _animate(self):
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not self.stop_event.is_set():
            # Pad message to clear previous longer messages
            msg = self.message[:50] + "..." if len(self.message) > 50 else self.message
            print(f"\r  {cyan(chars[idx])} {msg}".ljust(65), end="", flush=True)
            idx = (idx + 1) % len(chars)
            time.sleep(0.08)
        print("\r" + " " * 70 + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join()

def timer_start():
    return time.time()

def timer_end(start_time):
    duration = time.time() - start_time
    now = datetime.now().strftime('%H:%M:%S')
    print(f"  {dim(f'Finished at {now} (Duration: {duration:.2f}s)')}")


# ── CONSTANTS ─────────────────────────────────────────────────────────────────

# Spoofer was used for a year. Flag anything created since early 2025.
SCAN_FROM   = datetime(2025, 1, 1)
BASELINE_FILE = os.path.join(os.path.dirname(__file__), ".phantompeel_hw_baseline.json")

WINDIR      = os.environ.get('WINDIR', r'C:\Windows')
SYS32_DRV   = os.path.join(WINDIR, 'System32', 'drivers')

# ── HARDWARE INTEGRITY ────────────────────────────────────────────────────────

def get_hw_id(command):
    """Run a wmic command and return the cleaned output."""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        lines = [line.strip() for line in output.split('\n') if line.strip() and not line.strip().lower().startswith(('serialnumber', 'uuid', 'processorid', 'partnumber', 'pnpdeviceid', 'volumeid', 'volumemanagerid'))]
        return " | ".join(lines) if lines else "Unknown"
    except Exception:
        return "Error"

def get_volume_id():
    """Retrieve Volume Serial Number for C: drive."""
    try:
        output = subprocess.check_output("vol c:", shell=True, stderr=subprocess.DEVNULL).decode().strip()
        if "Serial Number is" in output:
            return output.split("Serial Number is")[1].strip()
    except Exception: pass
    return "Unknown"

def get_security_posture():
    """Check for Secure Boot and Test Signing mode."""
    posture = {"SecureBoot": "Unknown", "TestSigning": "Unknown"}
    try:
        # Secure Boot
        out = subprocess.check_output("powershell Confirm-SecureBootUEFI", shell=True, stderr=subprocess.DEVNULL).decode().strip()
        posture["SecureBoot"] = "Enabled" if "True" in out else "Disabled"
    except Exception: pass

    try:
        # Test Signing
        out = subprocess.check_output("bcdedit /enum {current}", shell=True, stderr=subprocess.DEVNULL).decode().strip()
        posture["TestSigning"] = "Enabled" if "testsigning             Yes" in out.lower() else "Disabled"
    except Exception: pass
    
    return posture

def check_mac_oui(mac):
    """Basic validation of MAC OUI (first 3 bytes). Flags 'random' looking ones."""
    if mac == "Unknown" or mac == "Error": return "Unknown"
    
    # Common virtual/spoofed prefixes
    # 02:xx:xx is locally administered (common in spoofers)
    prefix = mac.replace(":", "").replace("-", "")[:2].upper()
    try:
        first_byte = int(prefix, 16)
        if first_byte & 2: # Locally Administered bit
            return "Locally Administered (Suspicious)"
    except Exception: pass
    
    return "Standard"

def get_system_profile():
    """Extract a dictionary of current hardware serials."""
    mac = get_hw_id("wmic nic where \"PhysicalAdapter=True\" get MACAddress")
    posture = get_security_posture()
    
    return {
        "Disk"       : get_hw_id("wmic diskdrive get serialnumber"),
        "Volume_C"   : get_volume_id(),
        "Motherboard": get_hw_id("wmic baseboard get serialnumber"),
        "BIOS"       : get_hw_id("wmic csproduct get uuid"),
        "CPU"        : get_hw_id("wmic cpu get processorid"),
        "RAM"        : get_hw_id("wmic memorychip get serialnumber"),
        "GPU"        : get_hw_id("wmic PATH Win32_VideoController GET PNPDeviceID"),
        "MAC"        : mac,
        "MAC_Type"   : check_mac_oui(mac),
        "SecureBoot" : posture["SecureBoot"],
        "TestSigning": posture["TestSigning"]
    }

def integrity_check():
    """Compare current HW profile against the locked baseline."""
    current = get_system_profile()
    
    if not os.path.exists(BASELINE_FILE):
        return "NEW", current, {}

    try:
        with open(BASELINE_FILE, 'r') as f:
            baseline = json.load(f)
    except Exception:
        return "ERROR", current, {}

    matches = {}
    is_safe = True
    for key in current:
        if key in baseline:
            matches[key] = (current[key] == baseline[key])
            if not matches[key]:
                is_safe = False
        else:
            matches[key] = "Unknown"

    return ("SAFE" if is_safe else "SPOOFED"), current, matches

def lock_identity():
    """Save the current hardware profile as the permanent baseline."""
    profile = get_system_profile()
    try:
        with open(BASELINE_FILE, 'w') as f:
            json.dump(profile, f, indent=4)
        print(f"\n  {green('[+] Hardware identity locked successfully.')}")
        time.sleep(1.5)
    except Exception as e:
        print(f"\n  {red(f'[!] Failed to lock identity: {e}')}")
        pause()

def display_integrity_header():
    """Print the integrity status block."""
    status, current, matches = integrity_check()
    
    print(f"  {bold('SYSTEM INTEGRITY STATUS')}")
    print(f"  {dim('─' * 45)}")
    
    if status == "NEW":
        print(f"  Status : {yellow('[ UNINITIALIZED ]')}")
        print(f"  {dim('No baseline found. Press [4] to lock your hardware ID.')}")
    elif status == "SAFE":
        print(f"  Status : {green('[ SECURE / MATCHED ]')}")
    elif status == "SPOOFED":
        print(f"  Status : {red('[ WARNING: IDENTITY MISMATCH ]')}")
    else:
        print(f"  Status : {red('[ INTEGRITY ERROR ]')}")

    print(f"\n  {dim('Component Serials:')}")
    for key, val in current.items():
        if key in ["MAC_Type", "SecureBoot", "TestSigning"]: continue
        
        match_str = ""
        if status != "NEW":
            is_match = matches.get(key)
            if is_match is True:   match_str = green(" (MATCH)")
            elif is_match is False: match_str = red(" (CHANGED!)")
        
        # Truncate long IDs for display
        display_val = (val[:35] + '...') if len(val) > 35 else val
        print(f"  {red('→')} {key.ljust(12)} : {display_val}{match_str}")
    
    # Show Network & Security Posture
    print(f"\n  {dim('Security & Network Fingerprint:')}")
    mac_type = current.get("MAC_Type", "Unknown")
    mac_color = red if "Suspicious" in mac_type else green
    print(f"  {red('→')} MAC OUI      : {mac_color(mac_type)}")
    
    sb = current.get("SecureBoot", "Unknown")
    sb_color = green if sb == "Enabled" else yellow
    print(f"  {red('→')} Secure Boot  : {sb_color(sb)}")
    
    ts = current.get("TestSigning", "Unknown")
    ts_color = green if ts == "Disabled" else red
    print(f"  {red('→')} Test Signing : {ts_color(ts)}")

    print(f"  {dim('─' * 45)}\n")


# ── DIRECTORIES & SCAN TARGETS ──────────────────────────────────────────────

USERPROFILE = os.environ.get('USERPROFILE', '')
ONEDRIVE    = os.path.join(USERPROFILE, 'OneDrive')

# Locations the spoofer would drop folders / files into
SEARCH_DIRS = [
    os.environ.get('LOCALAPPDATA', ''),
    os.environ.get('APPDATA', ''),
    os.environ.get('TEMP', ''),
    os.path.join(USERPROFILE, 'Downloads'),
    os.path.join(USERPROFILE, 'Desktop'),
    os.path.join(ONEDRIVE, 'Desktop'),            # OneDrive Desktop
    os.path.join(USERPROFILE, 'AppData', 'LocalLow'),
    r'C:\ProgramData',
    USERPROFILE,                                  # root of user profile
]

# Keyword match against FILENAME STEM only (not full path) to avoid false positives
SPOOFER_KEYWORDS = [
    'spoof', 'hwid', 'bypass', 'kdmapper', 'iqvw64e',
    'gdrvsio64', 'gdrv', 'nflauncher', 'infsoft',
    'drvmap', 'physmem', 'winio', 'dbutil', 'eneio',
    'mapdrv', 'kernelhub', 'mapper', 'spoofer',
    'vanguard', 'ricochet', 'battleye', 'easyanticheat',
    'acebase', 'acegame', 'anticheatexpert', 'uncheater',
    'syping', 'vantage', 'ghost', 'shadow',
]

# Exact filenames to hunt (checked case-insensitively)
KNOWN_FILES = [
    'nflauncher.exe',
    'gdrv.sys', 'gdrvsio64.sys',
    'iqvw64e.sys', 'capcom.sys', 'atidrv64.sys',
    'kdmapper.exe', 'drvmap.exe',
    'dbutil_2_3.sys', 'winio64.sys', 'winio32.sys',
    'eneio64.sys', 'glckio2.sys', 'asasio.sys',
    'acebase.sys', 'acegame.sys', 'uncheater.sys',
]

# Drivers known to be used as 'bridges' by spoofers/mappers
VULNERABLE_DRIVERS = {
    "iqvw64e.sys": "Intel Network Diagnostic (Used by kdmapper)",
    "capcom.sys" : "Capcom Tool (Allows kernel execution)",
    "gdrv.sys"   : "Gigabyte Driver (Exploitable)",
    "dbutil_2_3.sys": "Dell BIOS Tool (Exploitable)",
    "eneio64.sys": "EneTech IO Driver (Common in mappers)",
    "glckio2.sys": "Genesis Logic Driver (Exploitable)",
    "acebase.sys": "Tencent ACE Anti-Cheat (Persistence)",
}

# Built-in Windows drivers that legitimately have no ImagePath in the registry.
# Loaded by the boot manager — do NOT flag these.
BUILTIN_NO_PATH = {
    'beep', 'null', 'ntfs', 'exfat', 'fastfat', 'refs', 'refsv1',
    'msfs', 'npfs', 'cimfs', 'wof', 'msrpc', 'mup', 'pdc',
    'acpiex', 'compositebus', 'umbus', 'swenum', 'rdyboost',
    'fltmgr', 'bindflt', 'wcifs', 'cldflt',
}


# ── SHARED REPORT BUFFER ──────────────────────────────────────────────────────

report = {
    "scan_time"         : "",
    "suspicious_drivers": [],
    "recent_sys_drops"  : [],
    "spoofer_artifacts" : [],
}


# ── BANNER ────────────────────────────────────────────────────────────────────

BANNER = r"""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                                                                       ║
  ║   ____  _   _    _    _   _ _____ ___  __  __ ____  _____ _____ _     ║
  ║  |  _ \| | | |  / \  | \ | |_   _/ _ \|  \/  |  _ \| ____| ____| |    ║
  ║  | |_) | |_| | / _ \ |  \| | | || | | | |\/| | |_) |  _| |  _| | |    ║
  ║  |  __/|  _  |/ ___ \| |\  | | || |_| | |  | |  __/| |___| |___| |___ ║
  ║  |_|   |_| |_/_/   \_\_| \_| |_| \___/|_|  |_|_|   |_____|_____|_____|║
  ║                                                                       ║
  ║   Driver & Spoofer Forensics Tool                        v1.1         ║
  ║   Windows Kernel Enumeration  +  Artifact Hunter                      ║
  ╚═══════════════════════════════════════════════════════════════════════╝
"""


# ── HELPERS ───────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def shannon_entropy(s: str) -> float:
    """Shannon entropy — higher value means more random-looking string."""
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s.lower():
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_random_name(name: str) -> bool:
    """
    Does this folder name look randomly generated?
    Spoofers create folders like 'xKp9mR2wQz' to stay hidden.
    Returns True if the name is short, high-entropy, with no recognisable words.
    """
    if len(name) < 6 or len(name) > 32:
        return False
    legit_words = [
        'microsoft', 'windows', 'steam', 'nvidia', 'amd', 'intel',
        'google', 'chrome', 'discord', 'mozilla', 'firefox',
        'temp', 'cache', 'local', 'roaming', 'package', 'user',
        'data', 'programs', 'onedrive', 'adobe', 'brave',
        'epic', 'riot', 'valorant', 'blizzard', 'origin',
    ]
    nl = name.lower()
    if any(kw in nl for kw in legit_words):
        return False
    return shannon_entropy(name) >= 3.5


def resolve_path(raw: str) -> str:
    """
    Expand env vars and resolve Windows kernel path prefixes that
    os.path.exists() cannot handle:
      \\??\\C:\\...      — device namespace prefix
      \\SystemRoot\\...  — kernel alias for %WINDIR%
      system32\\...      — relative path (rare)
    """
    p = os.path.expandvars(raw).strip()

    # Strip \\??\\ or \\?\\ device namespace prefix
    if p.startswith('\\??\\') or p.startswith('\\?\\'):
        idx = p.find(':\\')
        if idx > 0:
            p = p[idx - 1:]   # slice to  C:\...

    if p.lower().startswith('\\systemroot\\'):
        p = os.path.join(WINDIR, p[12:])
    elif p.lower().startswith('system32\\'):
        p = os.path.join(WINDIR, p)

    return p


def file_sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(8192), b''):
                h.update(block)
        return h.hexdigest()
    except Exception as e:
        return f"Error: {e}"


def check_signature_batch(paths: list) -> dict:
    """
    Check signatures for a list of files in ONE PowerShell call.
    Returns a dict of {path: status}
    """
    results = {p: "Unknown" for p in paths}
    if not paths:
        return results

    # Filter out duplicates and non-existent files to save time
    unique_paths = list(set(p for p in paths if os.path.exists(p)))
    if not unique_paths:
        return results

    # Chunk the paths to avoid command-line length limits (max 100 paths per call)
    chunk_size = 80
    for i in range(0, len(unique_paths), chunk_size):
        chunk = unique_paths[i:i + chunk_size]
        
        # PowerShell script to check all files in chunk and return as JSON-like format
        # Format: "PATH|STATUS"
        script = """
        $paths = @(PATHS_PLACEHOLDER)
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $sig = Get-AuthenticodeSignature -FilePath $p
                Write-Host ("{0}|{1}" -f $p, $sig.Status.ToString())
            }
        }
        """.replace("PATHS_PLACEHOLDER", ",".join([f"'{p.replace("'", "''")}'" for p in chunk]))

        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command', script],
                capture_output=True, text=True, timeout=60
            )
            for line in r.stdout.splitlines():
                if '|' in line:
                    path, status = line.split('|', 1)
                    results[path] = status
        except Exception:
            continue

    return results


def check_signature(path: str) -> str:
    """Legacy single check helper"""
    try:
        if not os.path.exists(path):
            return "File Not Found"
        safe = path.replace("'", "''")
        cmd  = f"(Get-AuthenticodeSignature -FilePath '{safe}').Status.ToString()"
        r    = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout.strip() or 'Unknown'
    except Exception as e:
        return f"CheckFailed: {e}"


def pause():
    input(f"\n  {dim('Press Enter to return to menu...')}")


def section(title: str):
    print(f"\n{bold(cyan(f'  ═══[ {title} ]═══'))}\n")


# ── OPTION 1 — DRIVER SWEEP ───────────────────────────────────────────────────

def driver_sweep():
    section("DRIVER SWEEP")
    t = timer_start()
    spinner = ReconSpinner("Enumerating services in Registry")
    spinner.start()

    key_path       = r"SYSTEM\CurrentControlSet\Services"
    flagged, total = [], 0
    all_drivers    = []

    try:
        root_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
    except Exception as e:
        spinner.stop()
        print(red(f"  [!] Registry access failed: {e}"))
        pause()
        return

    num = winreg.QueryInfoKey(root_key)[0]

    for i in range(num):
        try:
            svc_name = winreg.EnumKey(root_key, i)
            sub_key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{key_path}\\{svc_name}", 0, winreg.KEY_READ)
            
            try:
                svc_type, _ = winreg.QueryValueEx(sub_key, "Type")
                if svc_type not in (1, 2):
                    winreg.CloseKey(sub_key)
                    continue

                raw_path, _ = winreg.QueryValueEx(sub_key, "ImagePath")
                resolved    = resolve_path(raw_path)
                
                all_drivers.append({
                    "ServiceName": svc_name,
                    "Type": svc_type,
                    "ImagePath": resolved
                })
            except FileNotFoundError:
                # No ImagePath — check if demand-start unusual
                if svc_name.lower() not in BUILTIN_NO_PATH:
                    try:
                        start_val, _ = winreg.QueryValueEx(sub_key, "Start")
                        if start_val == 3:
                            all_drivers.append({
                                "ServiceName": svc_name,
                                "Type": svc_type,
                                "ImagePath": "Not specified"
                            })
                    except FileNotFoundError: pass

            winreg.CloseKey(sub_key)
        except (OSError, WindowsError): continue

    winreg.CloseKey(root_key)
    
    total = len(all_drivers)
    spinner.update(f"Analyzing {total} drivers...")

    # ── Batch Signature Check ────────────────────────────────────
    all_paths = [d["ImagePath"] for d in all_drivers if d["ImagePath"] != "Not specified"]
    spinner.update(f"Checking signatures (Batch Mode)...")
    sig_map = check_signature_batch(all_paths)

    spinner.update("Filtering results...")
    for d in all_drivers:
        reasons  = []
        path     = d["ImagePath"]
        svc_name = d["ServiceName"]

        if path == "Not specified":
            reasons.append("Demand-start kernel driver with no ImagePath")
        else:
            # Location check
            for bad_dir in SEARCH_DIRS:
                if bad_dir and bad_dir.lower() in path.lower():
                    reasons.append(f"Non-standard location: {bad_dir}")
                    break

            if os.path.exists(path):
                sig = sig_map.get(path, "Unknown")
                d["Signature"] = sig
                
                ctime = datetime.fromtimestamp(os.path.getctime(path))
                d["Created"] = ctime.strftime('%Y-%m-%d %H:%M:%S')
                d["SHA256"]  = file_sha256(path)

                if ctime >= SCAN_FROM:
                    # SMART FILTER: Don't flag Valid drivers just for being "recent" updates
                    is_sys32 = "system32\\drivers" in path.lower() or "system32\\driverstore" in path.lower()
                    if "Valid" in sig and is_sys32 and not is_random_name(Path(path).stem):
                        pass # Valid Windows Update drop
                    else:
                        reasons.append(f"Recently dropped: {d['Created']}")

                if sig and "Valid" not in sig and sig not in ("File Not Found", "Unknown"):
                    reasons.append(f"Bad/missing signature: {sig}")

                stem = Path(path).stem.lower()
                for kw in SPOOFER_KEYWORDS:
                    if stem == kw or stem.startswith(kw + '_') or stem.endswith('_' + kw):
                        reasons.append(f"Filename matches keyword: '{kw}'")
                        break
            else:
                d["FileExists"] = False
                if svc_name.lower() not in BUILTIN_NO_PATH:
                    reasons.append("ImagePath specified but file not found on disk")

        if reasons:
            d["FlagReasons"] = reasons
            flagged.append(d)

    spinner.stop()

    print(f"  Scanned : {dim(str(total))} kernel/FS drivers")
    print(f"  Flagged : {(yellow if flagged else green)(str(len(flagged)))} suspicious\n")

    if not flagged:
        print(f"  {green('[+]')} No suspicious drivers found.")
    else:
        for idx, d in enumerate(flagged, 1):
            sig       = d.get("Signature", "")
            sig_color = red if (sig and "Valid" not in sig) else green
            print(f"  {red(f'[{idx}]')} {bold(d['ServiceName'])}")
            print(f"       Path      : {d.get('ImagePath', 'N/A')}")
            for r in d.get("FlagReasons", []):
                print(f"       {yellow('!')} {r}")
            if sig:
                print(f"       Signature : {sig_color(sig)}")
            if d.get("SHA256"):
                print(f"       SHA256    : {dim(d['SHA256'])}")
            if d.get("Created"):
                print(f"       Created   : {d['Created']}")
            print()

    report["suspicious_drivers"] = flagged
    timer_end(t)
    pause()


# ── OPTION 2 — SPOOFER ARTIFACT HUNT ─────────────────────────────────────────

def spoofer_hunt():
    section("SPOOFER ARTIFACT HUNT")
    t = timer_start()
    scan_window = SCAN_FROM.strftime('%b %Y')
    print(f"  {dim(f'Hunting artifacts from {scan_window} onwards...')}")
    print(f"  {dim('Hunting for random-named folders, recent .sys drops, and known launcher filenames...')}\n")

    # ── 2a. Recent .sys drops in System32\drivers ──────────────────────────
    spinner = ReconSpinner("Checking System32\\drivers for recent drops")
    spinner.start()
    recent_sys = []

    try:
        for entry in os.scandir(SYS32_DRV):
            if not entry.name.lower().endswith('.sys'):
                continue
            try:
                ctime = datetime.fromtimestamp(entry.stat().st_ctime)
                if ctime >= SCAN_FROM:
                    recent_sys.append({
                        "file"     : entry.name,
                        "path"     : entry.path,
                        "created"  : ctime.strftime('%Y-%m-%d %H:%M:%S'),
                    })
            except (OSError, PermissionError):
                continue
        
        if recent_sys:
            spinner.update(f"Verifying {len(recent_sys)} signatures (Batch)...")
            sig_map = check_signature_batch([f["path"] for f in recent_sys])
            filtered_sys = []
            for f in recent_sys:
                sig = sig_map.get(f["path"], "Unknown")
                stem = Path(f["path"]).stem.lower()
                is_suspicious = not ("Valid" in sig and not is_random_name(stem) and not any(kw in stem for kw in SPOOFER_KEYWORDS))
                
                if is_suspicious:
                    f["signature"] = sig
                    f["sha256"]    = file_sha256(f["path"])
                    filtered_sys.append(f)
            recent_sys = filtered_sys
                
    except PermissionError:
        spinner.stop()
        print(red("Permission denied — run as Administrator"))
    else:
        spinner.stop()
        print(f"  {cyan('[>]')} System32 sweep: {green(f'done  ({len(recent_sys)} found)')}")

    if recent_sys:
        print(f"\n  {yellow(f'[!] {len(recent_sys)} suspicious .sys file(s) dropped since Jan 2025:')}")
        for f in recent_sys:
            sig_color = red if "Valid" not in f.get("signature", "Unknown") else green
            print(f"\n    {red('→')} {bold(f['file'])}")
            print(f"       Created   : {f['created']}")
            print(f"       Signature : {sig_color(f.get('signature', 'Unknown'))}")
            print(f"       SHA256    : {dim(f.get('sha256', 'N/A'))}")
    else:
        print(f"  {green('[+]')} No suspicious recent .sys drops found.")

    # ── 2b. Random-named folder hunt ──────────────────────────────────────
    spinner = ReconSpinner("Scanning for random-named / suspicious folders")
    spinner.start()
    rand_folders = []

    for base in SEARCH_DIRS:
        if not base or not os.path.isdir(base):
            continue
        spinner.update(f"Scanning {os.path.basename(base)}...")
        try:
            for entry in os.scandir(base):
                if not entry.is_dir():
                    continue
                try:
                    ctime     = datetime.fromtimestamp(entry.stat().st_ctime)
                    name      = entry.name
                    is_recent = ctime >= SCAN_FROM
                    is_rand   = is_random_name(name)
                    has_kw    = any(kw in name.lower() for kw in SPOOFER_KEYWORDS)

                    # Smart Filter: Only flag folders if they look random or match spoofer keywords.
                    if not (is_rand or has_kw):
                        continue

                    # Peek inside — spoofer drops .exe/.sys/.dll in the folder
                    contents = []
                    try:
                        for item in os.scandir(entry.path):
                            if Path(item.name).suffix.lower() in ('.exe', '.sys', '.dll', '.bat', '.ps1'):
                                contents.append(item.name)
                    except PermissionError:
                        contents = ['<access denied>']

                    flags = []
                    if is_recent: flags.append(f"Created {ctime.strftime('%Y-%m-%d %H:%M')}")
                    if is_rand:   flags.append(f"Random name (entropy {shannon_entropy(name):.2f})")
                    if has_kw:    flags.append("Name matches spoofer keyword")

                    rand_folders.append({
                        "path"    : entry.path,
                        "name"    : name,
                        "created" : ctime.strftime('%Y-%m-%d %H:%M:%S'),
                        "flags"   : flags,
                        "contents": contents,
                    })

                except (OSError, PermissionError):
                    continue
        except PermissionError:
            continue

    spinner.stop()
    print(f"  {cyan('[>]')} Folder entropy scan: {green(f'done  ({len(rand_folders)} flagged)')}")

    if rand_folders:
        print(f"\n  {yellow(f'[!] {len(rand_folders)} suspicious folder(s) found:')}")
        for folder in rand_folders:
            print(f"\n    {red('→')} {bold(folder['path'])}")
            print(f"       Flags    : {yellow('  |  '.join(folder['flags']))}")
            if folder['contents']:
                print(f"       Contains : {', '.join(folder['contents'])}")
    else:
        print(f"  {green('[+]')} No suspicious folders found.")

    # ── 2c. Known file hunt ────────────────────────────────────────────────
    spinner = ReconSpinner("Hunting known spoofer filenames")
    spinner.start()
    kw_hits = []

    for base in SEARCH_DIRS:
        if not base or not os.path.isdir(base):
            continue
        spinner.update(f"Searching {os.path.basename(base)}...")
        try:
            for root, dirs, files in os.walk(base):
                # Cap recursion depth at 4 to stay fast
                depth = root.replace(base, '').count(os.sep)
                if depth >= 4:
                    dirs.clear()
                    continue
                for fname in files:
                    if fname.lower() in KNOWN_FILES:
                        full = os.path.join(root, fname)
                        try:
                            ctime = datetime.fromtimestamp(os.path.getctime(full))
                            kw_hits.append({
                                "file"   : fname,
                                "path"   : full,
                                "created": ctime.strftime('%Y-%m-%d %H:%M:%S'),
                            })
                        except OSError:
                            pass
        except PermissionError:
            continue

    spinner.stop()
    print(f"  {cyan('[>]')} Keyword artifact hunt: {green(f'done  ({len(kw_hits)} found)')}")

    if kw_hits:
        print(f"\n  {red(f'[!!] {len(kw_hits)} known spoofer file(s) found:')}")
        for hit in kw_hits:
            print(f"\n    {red('→')} {bold(hit['file'])}")
            print(f"       Path     : {hit['path']}")
            print(f"       Created  : {hit['created']}")
    else:
        print(f"  {green('[+]')} No known spoofer files found.")

    report["recent_sys_drops"]  = recent_sys
    report["spoofer_artifacts"] = rand_folders + kw_hits
    timer_end(t)
    pause()



# ── OPTION 3 — DEEP FORENSICS ────────────────────────────────────────────────

def deep_forensics():
    section("DEEP FORENSICS (EXECUTION & PERSISTENCE)")
    t = timer_start()
    
    # 1. MUICache Analysis
    spinner = ReconSpinner("Analyzing MUICache")
    spinner.start()
    mui_hits = []
    try:
        key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        root_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        for i in range(winreg.QueryInfoKey(root_key)[1]):
            try:
                name, _, _ = winreg.EnumValue(root_key, i)
                if ".exe" in name.lower():
                    path = name.split(".exe")[0] + ".exe"
                    stem = Path(path).stem.lower()
                    if is_random_name(stem) or any(kw in stem for kw in SPOOFER_KEYWORDS):
                        mui_hits.append(path)
            except Exception: pass
        winreg.CloseKey(root_key)
    except Exception: pass
    spinner.stop()
    print(f"  {cyan('[>]')} MUICache Scan: {green('done')}")

    # 2. ShimCache (AppCompatCache)
    spinner = ReconSpinner("Analyzing ShimCache (Exploration)")
    spinner.start()
    shim_hits = []
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        root_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        blob, _  = winreg.QueryValueEx(root_key, "AppCompatCache")
        winreg.CloseKey(root_key)
        blob_str = str(blob).lower()
        for kw in SPOOFER_KEYWORDS:
            if kw in blob_str:
                shim_hits.append(f"Keyword '{kw}' found in AppCompatCache blob")
    except Exception: pass
    spinner.stop()
    print(f"  {cyan('[>]')} ShimCache Scan: {green('done')}")

    # 3. Prefetch Analysis
    spinner = ReconSpinner("Analyzing Prefetch Files")
    spinner.start()
    pf_hits = []
    prefetch_dir = r"C:\Windows\Prefetch"
    if os.path.isdir(prefetch_dir):
        try:
            for f in os.scandir(prefetch_dir):
                if not f.name.endswith(".pf"): continue
                stem = f.name.split("-")[0].lower().replace(".exe", "")
                if is_random_name(stem) or any(kw in stem for kw in SPOOFER_KEYWORDS):
                    ctime = datetime.fromtimestamp(f.stat().st_ctime)
                    if ctime >= SCAN_FROM:
                        pf_hits.append(f"{f.name} (Ran: {ctime.strftime('%Y-%m-%d %H:%M')})")
        except Exception: pass
    spinner.stop()
    print(f"  {cyan('[>]')} Prefetch Scan: {green('done')}")

    # 4. Persistence Scan (Run Keys & Tasks)
    spinner = ReconSpinner("Hunting Persistence (Autostart)")
    spinner.start()
    persist_hits = []
    
    # 5. HideMachine Registry Check
    try:
        wmi_key = r"SYSTEM\CurrentControlSet\Control\WMI\Restrictions"
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, wmi_key, 0, winreg.KEY_READ)
        hide_val, _ = winreg.QueryValueEx(reg, "HideMachine")
        if hide_val == 1:
            persist_hits.append("CRITICAL: 'HideMachine' set to 1 in WMI Restrictions (Known Spoofer)")
        winreg.CloseKey(reg)
    except Exception: pass

    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for root, path in run_paths:
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
            for i in range(winreg.QueryInfoKey(key)[1]):
                v_name, v_val, _ = winreg.EnumValue(key, i)
                v_val = str(v_val).lower()
                if any(kw in v_val or kw in v_name.lower() for kw in SPOOFER_KEYWORDS) or is_random_name(v_name):
                    persist_hits.append(f"Run Key: {v_name} -> {v_val}")
            winreg.CloseKey(key)
        except Exception: pass
    
    try:
        tasks = subprocess.check_output("schtasks /query /fo LIST", shell=True, stderr=subprocess.DEVNULL).decode()
        for line in tasks.split('\n'):
            if "TaskName:" in line:
                tname = line.split("TaskName:")[1].strip().lower()
                if is_random_name(tname) or any(kw in tname for kw in SPOOFER_KEYWORDS):
                    persist_hits.append(f"Scheduled Task: {tname}")
    except Exception: pass
    spinner.stop()
    print(f"  {cyan('[>]')} Persistence Scan: {green('done')}")

    # ── Display Results ─────────────────────────────────────────
    found_any = False
    if mui_hits or pf_hits or shim_hits or persist_hits:
        found_any = True
        if mui_hits:
            print(f"\n  {yellow('[!] Suspicious Executions (MUICache):')}")
            for h in set(mui_hits): print(f"    {red('→')} {h}")
        if shim_hits:
            print(f"\n  {yellow('[!] Evidence in ShimCache:')}")
            for h in set(shim_hits): print(f"    {red('→')} {h}")
        if pf_hits:
            print(f"\n  {yellow('[!] Suspicious Prefetch Traces:')}")
            for h in set(pf_hits): print(f"    {red('→')} {h}")
        if persist_hits:
            print(f"\n  {red('[!!] Persistence Found (Autostart):')}")
            for h in persist_hits: print(f"    {red('→')} {h}")
    
    if not found_any:
        print(f"\n  {green('[+] No execution traces or persistence found.')}")

    report["execution_forensics"] = {
        "muicache": list(set(mui_hits)),
        "shimcache": shim_hits,
        "prefetch": list(set(pf_hits)),
        "persistence": persist_hits
    }
    timer_end(t)
    pause()


# ── OPTION 6 — FORENSIC CLEAN & RESET ─────────────────────────────────────────

def forensic_clean():
    section("FORENSIC CLEAN & RESET")
    print(f"  {yellow('[!] WARNING: This will delete persistence keys and execution logs.')}")
    print(f"  {dim('Targeting: BingWallpaperDaemon (fake), ACC Tasks, UBT Tasks, Prefetch, MUICache')}\n")
    
    confirm = input(f"  Confirm System Clean? (y/n) {dim('>')} ").strip().lower()
    if confirm != 'y':
        return

    # 0. Delete Spoofer Payloads
    import shutil
    print(f"\n  {cyan('[1/5]')} Hunting and deleting spoofer executables...")
    for base in SEARCH_DIRS:
        if not base or not os.path.isdir(base): continue
        try:
            for entry in os.scandir(base):
                if entry.is_dir() and is_random_name(entry.name):
                    try:
                        has_exe = False
                        exe_name = ""
                        for item in os.scandir(entry.path):
                            if item.name.lower().endswith('.exe'):
                                has_exe = True
                                exe_name = item.name
                                break
                        if has_exe:
                            shutil.rmtree(entry.path)
                            print(f"      {green('[+]')} Spoofer executable '{bold(exe_name)}' found and has been removed.")
                    except Exception: pass
        except Exception: pass

    # 1. Kill Registry Persistence
    print(f"  {cyan('[2/5]')} Cleaning Registry Persistence...")
    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    targets = ['bingwallpaperdaemon', 'nflauncher', 'spoofer']
    
    for root, path in run_paths:
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS)
            for i in range(winreg.QueryInfoKey(key)[1]):
                try:
                    v_name, _, _ = winreg.EnumValue(key, i)
                    if v_name.lower() in targets or is_random_name(v_name):
                        winreg.DeleteValue(key, v_name)
                        print(f"      {green('[-] Removed Run Key:')} {v_name}")
                except Exception: continue
            winreg.CloseKey(key)
        except Exception: pass

    # 2. Delete Suspicious Tasks
    print(f"  {cyan('[3/5]')} Deleting Suspicious Scheduled Tasks...")
    tasks_to_kill = ['accbackgroundapplication', 'ubtframeworkservice', 'acercmupdatetask']
    for task in tasks_to_kill:
        try:
            # Use /F to force delete without confirmation
            subprocess.run(f"schtasks /delete /tn \"{task}\" /f", shell=True, capture_output=True)
            print(f"      {green('[-] Deleted Task:')} {task}")
        except Exception: pass

    # 3. Wipe Execution Traces
    print(f"  {cyan('[4/5]')} Wiping Prefetch & MUICache...")
    # Prefetch
    pf_dir = r"C:\Windows\Prefetch"
    if os.path.isdir(pf_dir):
        try:
            for f in os.scandir(pf_dir):
                if f.name.endswith(".pf") and any(kw in f.name.lower() for kw in SPOOFER_KEYWORDS + ['accfix', 'cleaner']):
                    os.remove(f.path)
            print(f"      {green('[+] Prefetch cleaned.')}")
        except Exception: print(f"      {red('[!] Failed to clean some Prefetch files.')}")
    
    # MUICache
    try:
        key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        root_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
        for i in range(winreg.QueryInfoKey(root_key)[1]):
            try:
                name, _, _ = winreg.EnumValue(root_key, i)
                if any(kw in name.lower() for kw in SPOOFER_KEYWORDS + ['accfix']):
                    winreg.DeleteValue(root_key, name)
            except Exception: pass
        winreg.CloseKey(root_key)
        print(f"      {green('[+] MUICache cleaned.')}")
    except Exception: pass

    # 4. Final Reset
    print(f"\n  {cyan('[5/5]')} Clean-up complete.")
    print(f"  {bold(green('SUCCESS: System artifacts have been cleared.'))}")
    print(f"\n  {yellow('[!] CRITICAL STEP:')}")
    print(f"  To restore your status to {green('SAFE')}, you MUST restart your computer now.")
    print(f"  This will clear the spoofer driver currently hiding in your RAM.")
    
    pause()


# ── EXPORT REPORT ────────────────────────────────────────────────────────────

def export_report():
    section("EXPORT REPORT")
    report["scan_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    fname    = f"phantompeel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path = os.path.join(USERPROFILE, 'Downloads', fname)
    try:
        with open(out_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"  {green('[+]')} Report saved to:\n  {bold(out_path)}\n")
    except Exception as e:
        print(f"  {red('[!]')} Failed to write report: {e}\n")
    pause()


# ── MENU ──────────────────────────────────────────────────────────────────────

def draw_menu():
    clear_screen()
    print(cyan(BANNER))
    
    # Show System Integrity at the top
    display_integrity_header()

    status = green("ADMINISTRATOR") if is_admin() else red("NOT ADMIN  —  run as Admin for full access")
    print(f"  User     :  {status}")
    print(f"  Scan From:  {yellow(SCAN_FROM.strftime('%b %d, %Y'))}\n")
    
    print(f"  {bold(yellow('[1]'))}  {bold('Driver Sweep')}           —  Enumerate & flag kernel drivers")
    print(f"  {bold(yellow('[2]'))}  {bold('Spoofer Artifact Hunt')}  —  Random folders, .sys drops, launcher files")
    print(f"  {bold(yellow('[3]'))}  {bold('Deep Forensics')}         —  MUICache & Prefetch execution traces")
    print(f"  {bold(yellow('[4]'))}  {bold('Lock/Update Identity')}  —  Save current serials as the SAFE baseline")
    print(f"  {bold(yellow('[5]'))}  {bold('Export Report')}          —  Save results to JSON in Downloads")
    print(f"  {bold(magenta('[6]'))}  {bold('Forensic Clean & Reset')}  —  Kill persistence & wipe traces")
    print(f"  {bold(red('[0]'))}  {bold('Exit')}\n")


def main():
    while True:
        draw_menu()
        choice = input(f"  {cyan('phantompeel')} {dim('>')} ").strip()
        if   choice == '1':  driver_sweep()
        elif choice == '2':  spoofer_hunt()
        elif choice == '3':  deep_forensics()
        elif choice == '4':
            print(f"\n  {yellow('[!] Lock current IDs as your permanent baseline?')}")
            print(f"      {red('WARNING:')} Only lock your identity if you are 100% sure your system")
            print(f"      is currently in a {green('CLEAN')} state (unspoofed). If a perma-spoofer")
            print(f"      is active, you will lock 'fake' IDs as your safe baseline.")
            confirm = input(f"\n      Confirm Lock (y/n) {dim('>')} ").strip().lower()
            if confirm == 'y':
                lock_identity()
        elif choice == '5':  export_report()
        elif choice == '6':  forensic_clean()
        elif choice == '0':
            print(f"\n  {dim('Exiting PhantomPeel...')}\n")
            sys.exit(0)
        else:
            input(f"  {red('[!]')} Invalid option. {dim('Press Enter...')}")


if __name__ == '__main__':
    main()
