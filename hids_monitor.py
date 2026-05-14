# hids_monitor.py
# Host-based IDS: monitors files, processes, and login events

import os
import hashlib
import psutil
import json
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler

hids_alerts = []

# ── File Integrity Monitor ───────────────────────────────────
WATCH_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    "C:\\Windows\\System32"   # optional — may be slow
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".py", ".sh", ".dll"
]

def add_alert(category, severity, message, details=""):
    hids_alerts.insert(0, {
        "time"    : datetime.now().strftime("%H:%M:%S"),
        "category": category,
        "severity": severity,   # HIGH / MEDIUM / LOW
        "message" : message,
        "details" : details
    })

class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        ext  = os.path.splitext(path)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            add_alert(
                category = "File Integrity",
                severity = "HIGH",
                message  = f"Suspicious file created: {os.path.basename(path)}",
                details  = f"Path: {path} | Extension: {ext}"
            )
        else:
            add_alert(
                category = "File Integrity",
                severity = "LOW",
                message  = f"New file created: {os.path.basename(path)}",
                details  = f"Path: {path}"
            )

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        ext  = os.path.splitext(path)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            add_alert(
                category = "File Integrity",
                severity = "MEDIUM",
                message  = f"Executable modified: {os.path.basename(path)}",
                details  = f"Path: {path}"
            )

    def on_deleted(self, event):
        if event.is_directory:
            return
        add_alert(
            category = "File Integrity",
            severity = "LOW",
            message  = f"File deleted: {os.path.basename(event.src_path)}",
            details  = f"Path: {event.src_path}"
        )

_observer = None

def start_file_monitor(watch_dirs=None):
    global _observer
    if _observer and _observer.is_alive():
        return
    dirs = watch_dirs or WATCH_DIRS
    _observer = Observer()
    handler   = FileChangeHandler()
    for d in dirs:
        if os.path.exists(d):
            try:
                _observer.schedule(handler, d, recursive=True)
            except Exception:
                pass
    _observer.start()

def stop_file_monitor():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()

# ── Process Monitor ──────────────────────────────────────────
SUSPICIOUS_PROCESSES = [
    "mimikatz", "netcat", "nc.exe", "nmap", "wireshark",
    "metasploit", "msfconsole", "cobaltstrike", "psexec",
    "wce.exe", "fgdump", "procdump", "lazagne"
]

HIGH_CPU_THRESHOLD    = 90.0   # %
HIGH_MEMORY_THRESHOLD = 80.0   # %

_known_pids = set()

def scan_processes():
    current_pids = set()
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                      'memory_percent', 'username']):
        try:
            info = proc.info
            pid  = info['pid']
            name = (info['name'] or "").lower()
            current_pids.add(pid)

            # New process appeared
            if pid not in _known_pids:
                _known_pids.add(pid)
                for sus in SUSPICIOUS_PROCESSES:
                    if sus in name:
                        add_alert(
                            category = "Process Monitor",
                            severity = "HIGH",
                            message  = f"Suspicious process detected: {info['name']}",
                            details  = f"PID: {pid} | User: {info.get('username','?')}"
                        )

            # High resource usage
            cpu = info.get('cpu_percent') or 0
            mem = info.get('memory_percent') or 0
            if cpu > HIGH_CPU_THRESHOLD:
                add_alert(
                    category = "Process Monitor",
                    severity = "MEDIUM",
                    message  = f"High CPU usage: {info['name']} ({cpu:.1f}%)",
                    details  = f"PID: {pid}"
                )
            if mem > HIGH_MEMORY_THRESHOLD:
                add_alert(
                    category = "Process Monitor",
                    severity = "MEDIUM",
                    message  = f"High memory usage: {info['name']} ({mem:.1f}%)",
                    details  = f"PID: {pid}"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Detect processes that disappeared suddenly
    disappeared = _known_pids - current_pids
    for pid in disappeared:
        _known_pids.discard(pid)

def start_process_monitor(interval=10):
    def run():
        while True:
            scan_processes()
            threading.Event().wait(interval)
    t = threading.Thread(target=run, daemon=True)
    t.start()

# ── Login / Auth Monitor (Windows Event Log) ─────────────────
def check_login_events():
    try:
        import subprocess
        result = subprocess.run(
            ['wevtutil', 'qe', 'Security',
             '/q:*[System[EventID=4625]]',   # Failed logins
             '/c:10', '/rd:true', '/f:text'],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout and "Event[" in result.stdout:
            count = result.stdout.count("Event[")
            if count > 0:
                add_alert(
                    category = "Login Monitor",
                    severity = "HIGH" if count >= 5 else "MEDIUM",
                    message  = f"{count} failed login attempt(s) detected",
                    details  = "Windows Security Event ID 4625"
                )
    except Exception:
        pass

def start_login_monitor(interval=30):
    def run():
        while True:
            check_login_events()
            threading.Event().wait(interval)
    t = threading.Thread(target=run, daemon=True)
    t.start()

# ── Start everything ─────────────────────────────────────────
def start_hids():
    start_file_monitor()
    start_process_monitor()
    start_login_monitor()

def get_hids_alerts():
    return hids_alerts.copy()