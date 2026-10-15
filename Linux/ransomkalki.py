#!/usr/bin/env python3
"""
RansomKalki - Anti-Ransomware + System Cleaner Engine for Linux
Dependency-free (Python 3 standard library only)
Copyright © RansomKalki

Usage:
  python3 ransomkalki.py start|stop|status|monit|logs|scan|approve|deny|install|help
"""

import os
import sys
import json
import time
import signal
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import re

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
ALERT_DIR = DATA_DIR / "alerts"
CONFIG_FILE = ROOT / "config" / "engine.json"
STATUS_FILE = DATA_DIR / "status.json"
PID_FILE = DATA_DIR / "ransomkalki.pid"
LOG_FILE = LOG_DIR / "engine.log"
INTEL_FILE = DATA_DIR / "threat_intel.txt"
QUARANTINE_DIR = DATA_DIR / "quarantine"

for d in (DATA_DIR, LOG_DIR, ALERT_DIR, QUARANTINE_DIR, ROOT / "config"):
    d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("ransomkalki")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "PollIntervalIdleSec": 60,
    "PollIntervalAlertSec": 15,
    "ApprovalTimeoutImpact": 600,
    "ApprovalTimeoutNormal": 3600,
    "HighMemoryMB": 700,
    "HighThreadCount": 90,
    "AdminEmail": "admin@company.com",
    "EnableEmail": False,
    # Auto-Approval settings (safe defaults: human approval for destructive actions)
    "AutoApproveEnabled": False,          # master switch
    "AutoApproveScoreThreshold": 80,
    "AutoApproveOnTimeout": True,         # timeout → act if still pending
    "RequireApprovalForImpact": True,     # encryption/impact needs human unless explicitly allowed
    "AutoApproveRemovals": False,         # kill/quarantine auto only if True + master
    "AutoApproveEncryptionStop": False,   # impact mitigation auto only if True + master
    # Central multi-tenant console
    "ConsoleEnabled": False,
    "ConsoleUrl": "",                     # e.g. http://console-host:9000
    "TenantId": "default",
    "AgentId": "",                        # auto-generated on first enroll
    "EnrollmentToken": "",
    "HostnameOverride": "",
    "AgentEnabled": True,                 # console can disable endpoint unit
    "AllowlistProcesses": [],             # exception process names (no action)
    "AllowlistPaths": [],                 # exception path prefixes
}

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                user = json.load(f)
                cfg.update(user)
        except Exception:
            pass
    else:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
    return cfg

def save_config(cfg):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Central console client (optional — fails soft if console is down)
# ---------------------------------------------------------------------------
def _console_base(cfg):
    return (cfg.get("ConsoleUrl") or "").rstrip("/")


def _http_json(method, url, payload=None, token="", timeout=5):
    import urllib.request
    data = None
    headers = {"Content-Type": "application/json", "User-Agent": "RansomKalki-Agent"}
    if token:
        headers["X-Enrollment-Token"] = token
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def _machine_fingerprint():
    """Stable unique id from OS machine-id (fallback: host+kernel)."""
    import hashlib
    candidates = ["/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"]
    raw = ""
    for p in candidates:
        try:
            if os.path.isfile(p):
                raw = open(p, "r", errors="ignore").read().strip()
                if raw:
                    break
        except Exception:
            pass
    if not raw:
        try:
            raw = f"{os.uname().nodename}|{os.uname().sysname}|{os.uname().machine}"
        except Exception:
            raw = str(os.getpid())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def ensure_agent_id(cfg):
    """Auto-define unique AgentId / hostname from machine identity."""
    changed = False
    if not cfg.get("AgentId"):
        cfg["AgentId"] = f"lin-{_machine_fingerprint()}"
        changed = True
    if not cfg.get("HostnameOverride"):
        try:
            cfg["HostnameOverride"] = os.uname().nodename
            changed = True
        except Exception:
            pass
    if not cfg.get("TenantId"):
        cfg["TenantId"] = "default"
        changed = True
    if changed:
        save_config(cfg)
    return cfg


def console_enroll(cfg):
    base = _console_base(cfg)
    if not base:
        return cfg
    cfg = ensure_agent_id(cfg)
    host = cfg.get("HostnameOverride") or os.uname().nodename
    try:
        _http_json("POST", base + "/api/enroll", {
            "TenantId": cfg.get("TenantId") or "default",
            "AgentId": cfg["AgentId"],
            "Hostname": host,
            "Platform": "Linux",
            "Version": "1.5.0",
        }, token=cfg.get("EnrollmentToken") or "")
        log.info("Enrolled with console %s as %s", base, cfg["AgentId"])
    except Exception as e:
        log.warning("Console enroll failed: %s", e)
    return cfg


def process_console_commands(cfg, commands):
    if not commands:
        return cfg
    for cmd in commands:
        ctype = cmd.get("Type")
        if ctype == "ResolveAlert":
            aid = cmd.get("AlertId")
            decision = cmd.get("Decision") or "Approved"
            finding = cmd.get("Finding") or {}
            if resolve_approval(aid, decision):
                if decision == "Approved":
                    try:
                        action_kill_quarantine(finding)
                    except Exception as e:
                        log.error("Remote approve action failed: %s", e)
                log.warning("Console remote %s for alert %s", decision, aid)
        elif ctype == "ApplyPolicy":
            policy = cmd.get("Policy") or {}
            for k, v in policy.items():
                if k in DEFAULT_CONFIG or k in (
                    "AgentEnabled", "AllowlistProcesses", "AllowlistPaths",
                    "AutoApproveEnabled", "AutoApproveRemovals",
                    "AutoApproveEncryptionStop", "RequireApprovalForImpact",
                    "AutoApproveOnTimeout", "AutoApproveScoreThreshold",
                ):
                    cfg[k] = v
            save_config(cfg)
            log.info("Console policy applied: %s", policy)
        elif ctype == "SetEnabled":
            cfg["AgentEnabled"] = bool(cmd.get("Enabled", True))
            save_config(cfg)
            log.warning("Console set AgentEnabled=%s", cfg["AgentEnabled"])
        elif ctype == "SetExceptions":
            if "AllowlistProcesses" in cmd:
                cfg["AllowlistProcesses"] = list(cmd.get("AllowlistProcesses") or [])
            if "AllowlistPaths" in cmd:
                cfg["AllowlistPaths"] = list(cmd.get("AllowlistPaths") or [])
            save_config(cfg)
            log.info("Console exceptions updated")
    return cfg


def build_console_status(cfg, status):
    """Enrich status for central console fleet view."""
    st = dict(status or {})
    pending = st.get("PendingAlerts") or 0
    findings = st.get("FindingsCount") or 0
    issues = []
    if not cfg.get("AgentEnabled", True):
        issues.append("disabled")
    if pending:
        issues.append("pending_approvals")
    if findings:
        issues.append("active_findings")
    if st.get("Mode") == "Alert":
        issues.append("alert_mode")
    st["Issues"] = issues
    st["HasIssue"] = len(issues) > 0 and "disabled" not in issues or (pending > 0 or findings > 0)
    st["Config"] = {
        "AutoApproveEnabled": cfg.get("AutoApproveEnabled", False),
        "AutoApproveRemovals": cfg.get("AutoApproveRemovals", False),
        "AutoApproveEncryptionStop": cfg.get("AutoApproveEncryptionStop", False),
        "RequireApprovalForImpact": cfg.get("RequireApprovalForImpact", True),
        "AgentEnabled": cfg.get("AgentEnabled", True),
        "AllowlistProcesses": cfg.get("AllowlistProcesses") or [],
        "AllowlistPaths": cfg.get("AllowlistPaths") or [],
    }
    return st


def console_heartbeat(cfg, status):
    """Send heartbeat; apply any returned commands. Fails soft."""
    if not cfg.get("ConsoleEnabled"):
        return cfg
    base = _console_base(cfg)
    if not base:
        return cfg
    cfg = ensure_agent_id(cfg)
    host = cfg.get("HostnameOverride") or os.uname().nodename
    try:
        resp = _http_json("POST", base + "/api/heartbeat", {
            "TenantId": cfg.get("TenantId") or "default",
            "AgentId": cfg["AgentId"],
            "Hostname": host,
            "Platform": "Linux",
            "Version": "1.5.0",
            "Status": build_console_status(cfg, status),
        }, token=cfg.get("EnrollmentToken") or "")
        cfg = process_console_commands(cfg, resp.get("commands") or [])
    except Exception as e:
        log.debug("Console heartbeat failed: %s", e)
    return cfg


def console_upload_alert(cfg, alert_id, finding, expires_at=""):
    if not cfg.get("ConsoleEnabled"):
        return
    base = _console_base(cfg)
    if not base or not cfg.get("AgentId"):
        return
    host = cfg.get("HostnameOverride") or os.uname().nodename
    try:
        _http_json("POST", base + "/api/alert", {
            "TenantId": cfg.get("TenantId") or "default",
            "AgentId": cfg["AgentId"],
            "AlertId": alert_id,
            "Hostname": host,
            "Platform": "Linux",
            "Finding": finding,
            "ExpiresAt": expires_at,
        }, token=cfg.get("EnrollmentToken") or "")
    except Exception as e:
        log.debug("Console alert upload failed: %s", e)

# ---------------------------------------------------------------------------
# Threat Intel
# ---------------------------------------------------------------------------
BUILTIN_PROCESS = [
    "xmrig", "minerd", "cpuminer", "nicehash", "ethminer", "phoenixminer",
    "nbminer", "gminer", "t-rex", "lolminer", "miner", "coinminer",
    "cryptominer", "hashrate", "searchprotect", "conduit", "genieo"
]
BUILTIN_PATHS = ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/*/Downloads/"]

def load_intel():
    intel = {"ProcessNames": list(BUILTIN_PROCESS), "PathPatterns": list(BUILTIN_PATHS)}
    if INTEL_FILE.exists():
        section = ""
        with open(INTEL_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].upper()
                    continue
                if section == "PROCESS_NAMES":
                    intel["ProcessNames"].append(line)
                elif section == "PATH_PATTERNS":
                    intel["PathPatterns"].append(line)
    return intel

# ---------------------------------------------------------------------------
# Collector (Linux)
# ---------------------------------------------------------------------------
def collect():
    # Memory
    meminfo = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        total = meminfo.get("MemTotal", 1)
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used_pct = round((total - avail) / total * 100, 1)
    except Exception:
        used_pct = 0.0

    # Processes
    procs = []
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            pid = int(pid_dir.name)
            with open(pid_dir / "comm") as f:
                name = f.read().strip()
            with open(pid_dir / "status") as f:
                status = f.read()
            rss = 0
            threads = 0
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])  # kB
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
            cmdline = ""
            try:
                with open(pid_dir / "cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            except Exception:
                pass
            exe = ""
            try:
                exe = os.readlink(pid_dir / "exe")
            except Exception:
                pass
            procs.append({
                "pid": pid,
                "name": name,
                "memory_mb": round(rss / 1024, 1),
                "threads": threads,
                "exe": exe,
                "cmdline": cmdline[:200]
            })
        except Exception:
            continue

    # Lightweight real network snapshot from /proc (no sleep)
    ext_count, unique_ips, remotes = 0, 0, []
    try:
        net = capture_connections_snapshot()
        ext_count = net["external_conns"]
        unique_ips = net["unique_ips"]
        remotes = net["remotes"]
    except Exception:
        pass

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "memory_used_pct": used_pct,
        "processes": procs,
        "net_external_conns": ext_count,
        "net_unique_ips": unique_ips,
        "net_remotes": remotes,
    }

# ---------------------------------------------------------------------------
# Real Network Flow Capture (Linux – /proc only, no libpcap)
# ---------------------------------------------------------------------------
def _is_private_ip(ip):
    if not ip:
        return True
    if ip.startswith(("127.", "10.", "192.168.", "::1", "fe80:", "fc00:", "fd")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    if ip in ("0.0.0.0", "::", "*"):
        return True
    return False

def _hex_ip(hexstr):
    """Convert /proc/net/tcp hex IP (little-endian) to dotted quad."""
    try:
        if len(hexstr) == 8:
            b = bytes.fromhex(hexstr)
            return ".".join(str(b[i]) for i in (3, 2, 1, 0))
    except Exception:
        pass
    return hexstr

def get_interface_bytes():
    sent = recv = 0
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                name = name.strip()
                if name == "lo":
                    continue
                parts = rest.split()
                if len(parts) >= 16:
                    recv += int(parts[0])
                    sent += int(parts[8])
    except Exception:
        pass
    return sent, recv

def capture_connections_snapshot():
    """Parse /proc/net/tcp for established external connections."""
    external = []
    try:
        with open("/proc/net/tcp") as f:
            next(f)  # header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                # state 01 = ESTABLISHED
                if parts[3] != "01":
                    continue
                remote = parts[2]
                rip_hex, rport_hex = remote.split(":")
                rip = _hex_ip(rip_hex)
                rport = int(rport_hex, 16)
                if not _is_private_ip(rip):
                    external.append({"ip": rip, "port": rport})
    except Exception:
        pass
    unique = list({e["ip"] for e in external})
    return {
        "external_conns": len(external),
        "unique_ips": len(unique),
        "remotes": unique[:15],
        "connections": external,
    }

def invoke_network_capture(sample_seconds=5):
    sent1, recv1 = get_interface_bytes()
    t0 = time.time()
    snap = capture_connections_snapshot()
    time.sleep(sample_seconds)
    sent2, recv2 = get_interface_bytes()
    elapsed = max(0.001, time.time() - t0)
    sent_delta = max(0, sent2 - sent1)
    recv_delta = max(0, recv2 - recv1)
    mb_out = round((sent_delta / 1048576) * (60.0 / elapsed), 2)
    mb_in = round((recv_delta / 1048576) * (60.0 / elapsed), 2)

    reasons = []
    suspicious = False
    if mb_out >= 300:
        suspicious = True
        reasons.append(f"High outbound volume {mb_out} MB/min")
    if snap["unique_ips"] >= 25:
        suspicious = True
        reasons.append(f"Many unique external IPs ({snap['unique_ips']})")
    if snap["external_conns"] >= 80:
        suspicious = True
        reasons.append(f"High external connection count ({snap['external_conns']})")

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sample_sec": sample_seconds,
        "net_mb_per_min": mb_out,
        "net_mb_in_per_min": mb_in,
        "net_external_conns": snap["external_conns"],
        "net_unique_ips": snap["unique_ips"],
        "net_remotes": snap["remotes"],
        "net_suspicious": suspicious,
        "net_reasons": " | ".join(reasons),
        "bytes_sent_delta": sent_delta,
        "bytes_recv_delta": recv_delta,
    }

def run_network_capture(seconds=120, sample_seconds=5):
    print()
    print("=== RansomKalki Real Network Capture (Linux) ===")
    print(f"  Duration : {seconds}s  |  Sample window : {sample_seconds}s")
    print("  Source   : /proc/net/dev + /proc/net/tcp (no libpcap)")
    print("  Dashboard: python3 ransomkalki.py dashboard")
    print("  Press Ctrl+C to stop.")
    print()

    end = time.time() + seconds
    tick = 0
    try:
        while time.time() < end:
            tick += 1
            cap = invoke_network_capture(sample_seconds)
            status = {
                "Engine": "Running",
                "Pid": os.getpid(),
                "LastCycle": cap["timestamp"],
                "MemoryUsedPct": collect().get("memory_used_pct", 0),
                "FindingsCount": 1 if cap["net_suspicious"] else 0,
                "PendingAlerts": len(get_pending()),
                "Mode": "Alert" if cap["net_suspicious"] else "Idle",
                "AutoApprove": True,
                "Version": "1.3.0-capture",
                "Platform": "Linux",
                "SimActive": False,
                "CaptureActive": True,
                "SimPattern": cap["net_reasons"] or "Live capture – normal",
                "SimMode": "live-capture",
                "NetMBPerMin": cap["net_mb_per_min"],
                "NetMBInPerMin": cap["net_mb_in_per_min"],
                "NetExternalConns": cap["net_external_conns"],
                "NetUniqueIPs": cap["net_unique_ips"],
                "NetRemotes": cap["net_remotes"],
                "NetSuspicious": cap["net_suspicious"],
                "SimTick": tick,
                "SimRemainingSec": max(0, int(end - time.time())),
            }
            save_status(status)

            if cap["net_suspicious"] and cap["net_mb_per_min"] >= 300:
                alert_id = "cap" + os.urandom(4).hex()
                path = ALERT_DIR / f"{alert_id}.json"
                if not path.exists():
                    finding = {
                        "id": 1, "type": "Network", "name": "HighOutboundVolume",
                        "pid": 0, "exe": "", "memory_mb": 0, "score": 80,
                        "severity": "High", "reasons": cap["net_reasons"],
                        "timestamp": cap["timestamp"],
                    }
                    with open(path, "w") as f:
                        json.dump({
                            "AlertId": alert_id, "Finding": finding,
                            "SubmittedAt": cap["timestamp"], "TimeoutSec": 600,
                            "Status": "Pending",
                            "ExpiresAt": (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z",
                            "Capture": True,
                        }, f, indent=2)
                    log.warning(f"CAPTURE ALERT {alert_id}: {cap['net_reasons']}")

            flag = "!" if cap["net_suspicious"] else " "
            print(f"  [{datetime.now().strftime('%H:%M:%S')}]{flag} out={cap['net_mb_per_min']:>8} MB/min  "
                  f"in={cap['net_mb_in_per_min']:>7} MB/min  ext_conns={cap['net_external_conns']:>4}  "
                  f"unique_ips={cap['net_unique_ips']:>3}  {cap['net_reasons'] or 'ok'}")
            if cap["net_remotes"]:
                print(f"           → {', '.join(cap['net_remotes'][:5])}")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    st = load_status() or {}
    st["CaptureActive"] = False
    st["Mode"] = "Idle"
    st["SimPattern"] = "Capture ended"
    save_status(st)
    print("\nCapture complete.")

def run_full_packet_capture(seconds=60, bpf_filter=""):
    """Full packet capture using tcpdump if available (writes PCAP)."""
    capture_dir = DATA_DIR / "captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = capture_dir / f"ransomkalki_{stamp}.pcap"
    summary_path = capture_dir / f"ransomkalki_{stamp}.summary.txt"

    print()
    print("=== RansomKalki FULL Packet Capture (Linux) ===")
    print(f"  Duration : {seconds}s")
    print(f"  Output   : {capture_dir}")
    print()

    tcpdump = None
    try:
        r = subprocess.run(["which", "tcpdump"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            tcpdump = r.stdout.strip()
    except Exception:
        pass

    if not tcpdump:
        print("  tcpdump not found. Install with: sudo apt install tcpdump  (or equivalent)")
        print("  Falling back to flow-level capture (/proc only)...")
        print()
        run_network_capture(seconds, 5)
        return

    if os.geteuid() != 0:
        print("  WARNING: full packet capture usually requires root (sudo).")
        print("  Attempting anyway...")
        print()

    cmd = [tcpdump, "-i", "any", "-w", str(pcap_path), "-n"]
    if bpf_filter:
        cmd.extend(bpf_filter.split())
        print(f"  Filter   : {bpf_filter}")
    print(f"  Command  : {' '.join(cmd)}")
    print(f"  [1/3] Starting tcpdump for {seconds}s...")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"  Failed to start tcpdump: {e}")
        print("  Falling back to flow-level capture...")
        run_network_capture(seconds, 5)
        return

    end = time.time() + seconds
    try:
        while time.time() < end:
            if proc.poll() is not None:
                err = ""
                try:
                    err = proc.stderr.read().decode("utf-8", "replace")[:200]
                except Exception:
                    pass
                print(f"  tcpdump exited early: {err}")
                break
            remaining = max(0, int(end - time.time()))
            snap = capture_connections_snapshot()
            status = {
                "Engine": "Running", "Pid": os.getpid(),
                "LastCycle": datetime.utcnow().isoformat() + "Z",
                "Mode": "Alert", "Version": "1.4.0-pcap", "Platform": "Linux",
                "CaptureActive": True, "PcapActive": True,
                "SimPattern": "FULL packet capture in progress",
                "SimMode": "pcap", "SimRemainingSec": remaining,
                "NetExternalConns": snap["external_conns"],
                "NetUniqueIPs": snap["unique_ips"],
                "NetRemotes": snap["remotes"],
                "PcapFile": str(pcap_path),
            }
            save_status(status)
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] full pcap active  remaining={remaining}s  file={pcap_path.name}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n  Stopping early...")

    print("  [2/3] Stopping tcpdump...")
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    size_mb = round(pcap_path.stat().st_size / 1048576, 2) if pcap_path.exists() else 0
    summary = (
        f"RansomKalki Full Packet Capture Summary\n"
        f"=====================================\n"
        f"Started   : {stamp}\n"
        f"Duration  : {seconds}s\n"
        f"PCAP file : {pcap_path} ({size_mb} MB)\n"
        f"Filter    : {bpf_filter or '(none – all traffic)'}\n"
        f"Host      : {os.uname().nodename}\n"
        f"Tool      : {tcpdump}\n"
    )
    summary_path.write_text(summary)
    print()
    print("  [3/3] Capture complete.")
    print(f"  PCAP : {pcap_path} ({size_mb} MB)")
    print(f"  Log  : {summary_path}")
    print()
    log.info(f"Full packet capture saved: {pcap_path}")

    st = load_status() or {}
    st["PcapActive"] = False
    st["CaptureActive"] = False
    st["Mode"] = "Idle"
    st["SimPattern"] = f"PCAP complete: {pcap_path.name}"
    st["PcapFile"] = str(pcap_path)
    save_status(st)

# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
CRITICAL = {"systemd", "kthreadd", "ksoftirqd", "migration", "rcu_", "init", "bash", "sshd", "python3", "ransomkalki"}

def detect(snapshot, intel, config):
    findings = []
    fid = 0
    for p in snapshot["processes"]:
        if any(p["name"].startswith(c) for c in CRITICAL):
            continue
        score = 0
        reasons = []
        for bad in intel["ProcessNames"]:
            if bad.lower() in p["name"].lower():
                score += 40
                reasons.append(f"Name matches threat intel: {bad}")
                break
        for pat in intel["PathPatterns"]:
            if pat.replace("*", "") in (p["exe"] or ""):
                score += 25
                reasons.append("Suspicious path")
                break
        if p["memory_mb"] > config["HighMemoryMB"]:
            score += 15
            reasons.append(f"High memory ({p['memory_mb']} MB)")
        if p["threads"] > config["HighThreadCount"]:
            score += 15
            reasons.append(f"High threads ({p['threads']})")
        if score >= 40:
            fid += 1
            findings.append({
                "id": fid,
                "type": "Process",
                "name": p["name"],
                "pid": p["pid"],
                "exe": p["exe"],
                "memory_mb": p["memory_mb"],
                "score": score,
                "reasons": " | ".join(reasons),
                "severity": "High" if score >= 70 else "Medium",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
    if snapshot["memory_used_pct"] >= 90:
        fid += 1
        findings.append({
            "id": fid, "type": "System", "name": "HighMemoryPressure",
            "pid": 0, "exe": "", "memory_mb": 0, "score": 50,
            "reasons": f"Memory {snapshot['memory_used_pct']}%", "severity": "High",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    return findings

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def action_kill_quarantine(finding, config=None):
    try:
        cfg = config or load_config()
        if not cfg.get("AgentEnabled", True):
            log.info("Agent disabled — skip action for %s", finding.get("name"))
            return False
        name = (finding.get("name") or "").lower()
        exe = (finding.get("exe") or "").lower()
        for n in (cfg.get("AllowlistProcesses") or []):
            if n and n.lower() in name:
                log.info("Allowlisted process exception: %s", name)
                return False
        for p in (cfg.get("AllowlistPaths") or []):
            if p and p.lower() in exe:
                log.info("Allowlisted path exception: %s", exe)
                return False
        pid = finding.get("pid", 0)
        if pid > 0:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.4)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            log.warning(f"Killed PID {pid} ({finding.get('name')})")
        exe = finding.get("exe") or ""
        if exe and os.path.isfile(exe) and not exe.startswith(("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib")):
            dest = QUARANTINE_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{Path(exe).name}"
            try:
                os.rename(exe, dest)
                log.warning(f"Quarantined {exe} → {dest}")
            except Exception as e:
                log.error(f"Quarantine failed: {e}")
        return True
    except Exception as e:
        log.error(f"Action failed: {e}")
        return False

# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------
def submit_approval(finding, timeout_sec, config=None):
    alert_id = os.urandom(6).hex()
    expires = (datetime.utcnow() + timedelta(seconds=timeout_sec)).isoformat() + "Z"
    package = {
        "AlertId": alert_id,
        "Finding": finding,
        "SubmittedAt": datetime.utcnow().isoformat() + "Z",
        "TimeoutSec": timeout_sec,
        "Status": "Pending",
        "ExpiresAt": expires,
    }
    with open(ALERT_DIR / f"{alert_id}.json", "w") as f:
        json.dump(package, f, indent=2)
    log.warning(f"Alert {alert_id} submitted for approval ({finding.get('name')})")
    if config:
        console_upload_alert(config, alert_id, finding, expires)
    return alert_id

def get_pending():
    pending = []
    for f in ALERT_DIR.glob("*.json"):
        try:
            with open(f) as fh:
                a = json.load(fh)
            if a.get("Status") == "Pending":
                pending.append(a)
        except Exception:
            pass
    return pending

def resolve_approval(alert_id, decision):
    path = ALERT_DIR / f"{alert_id}.json"
    if not path.exists():
        return False
    with open(path) as f:
        a = json.load(f)
    a["Status"] = decision
    a["ResolvedAt"] = datetime.utcnow().isoformat() + "Z"
    with open(path, "w") as f:
        json.dump(a, f, indent=2)
    log.info(f"Alert {alert_id} → {decision}")
    return True

# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------
def save_status(data):
    with open(STATUS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_status():
    if STATUS_FILE.exists():
        try:
            with open(STATUS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def is_running():
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def run_engine(config):
    if is_running():
        print("RansomKalki is already running.")
        return
    PID_FILE.write_text(str(os.getpid()))
    log.info(f"RansomKalki engine started (PID {os.getpid()})")
    intel = load_intel()
    alert_mode = False
    if config.get("ConsoleEnabled") and config.get("ConsoleUrl"):
        config = console_enroll(config)

    def handle_signal(signum, frame):
        log.info("Shutdown signal received")
        if PID_FILE.exists():
            PID_FILE.unlink()
        sys.exit(0)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while True:
        try:
            # Reload config so console-pushed policy takes effect
            config = load_config()
            agent_on = config.get("AgentEnabled", True)

            # Timeout auto-actions (if enabled and agent enabled)
            for p in get_pending():
                exp = datetime.fromisoformat(p["ExpiresAt"].replace("Z", ""))
                if datetime.utcnow() > exp:
                    if config.get("AutoApproveOnTimeout", True):
                        log.warning(f"Timeout AUTO-ACTION for {p['AlertId']}")
                        action_kill_quarantine(p["Finding"])
                        resolve_approval(p["AlertId"], "Timeout-Auto")
                    else:
                        log.warning(f"Timeout expired (auto-action disabled) for {p['AlertId']}")
                        resolve_approval(p["AlertId"], "Timeout-Expired")

            snap = collect()
            findings = detect(snap, intel, config)

            status = {
                "Engine": "Running",
                "Pid": os.getpid(),
                "LastCycle": datetime.utcnow().isoformat() + "Z",
                "MemoryUsedPct": snap["memory_used_pct"],
                "FindingsCount": len(findings),
                "PendingAlerts": len(get_pending()),
                "Mode": "Alert" if alert_mode else "Idle",
                "AutoApprove": config.get("AutoApproveEnabled", False),
                "Version": "1.5.0",
                "Platform": "Linux",
                "CaptureActive": True,
                "NetExternalConns": snap.get("net_external_conns", 0),
                "NetUniqueIPs": snap.get("net_unique_ips", 0),
                "NetRemotes": snap.get("net_remotes", []),
                "SimPattern": "Live capture (connection table)",
                "AgentId": config.get("AgentId") or "",
                "TenantId": config.get("TenantId") or "default",
            }
            save_status(status)
            config = console_heartbeat(config, status)

            if findings and agent_on:
                alert_mode = True
                for f in findings:
                    if f["score"] < 60:
                        continue
                    reasons = (f.get("reasons") or "").lower()
                    ftype = (f.get("type") or "").lower()
                    is_impact = any(k in reasons for k in ("encrypt", "shadow", "vss", "backup", "corruption", "ransom"))
                    is_removal = ftype in ("process", "malware", "spyware", "miner", "network") or any(
                        k in reasons for k in ("quarantine", "kill", "remove")
                    )
                    should_auto = False
                    if config.get("AutoApproveEnabled") and f["score"] >= config.get("AutoApproveScoreThreshold", 80):
                        if is_impact:
                            if (not config.get("RequireApprovalForImpact", True)) and config.get("AutoApproveEncryptionStop", False):
                                should_auto = True
                            else:
                                should_auto = False
                        elif is_removal:
                            should_auto = bool(config.get("AutoApproveRemovals", False))
                        else:
                            should_auto = True

                    if should_auto:
                        log.warning(f"AUTO-APPROVED (score {f['score']}): {f.get('name')}")
                        action_kill_quarantine(f)
                        aid = submit_approval(f, 1, config)
                        resolve_approval(aid, "Auto-Approved")
                    else:
                        timeout = config["ApprovalTimeoutImpact"] if (f["severity"] == "High" or is_impact) else config["ApprovalTimeoutNormal"]
                        submit_approval(f, timeout, config)
            else:
                alert_mode = False

            sleep = config["PollIntervalAlertSec"] if alert_mode else config["PollIntervalIdleSec"]
            time.sleep(sleep)
        except Exception as e:
            log.error(f"Cycle error: {e}")
            time.sleep(30)

# ---------------------------------------------------------------------------
# pm2-style console
# ---------------------------------------------------------------------------
def cmd_status():
    running = is_running()
    status = load_status()
    pending = get_pending()
    print()
    print("┌──────────────────────────────────────────────────────────────────────────────┐")
    print("│                     RANSOMKALKI SECURITY ENGINE STATUS                          │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")
    print()
    if not running:
        print("  Status    : STOPPED")
        print("  Use:  python3 ransomkalki.py start")
        print()
        return
    print(f"  Status    : ONLINE")
    print(f"  PID       : {status.get('Pid')}")
    print(f"  Mode      : {status.get('Mode')}")
    print(f"  Last Cycle: {status.get('LastCycle')}")
    print(f"  Memory    : {status.get('MemoryUsedPct')}% used")
    print(f"  Findings  : {status.get('FindingsCount')}")
    print(f"  Pending   : {len(pending)} approval(s)")
    print(f"  AutoApprove: {status.get('AutoApprove')}  (threshold from config)")
    print(f"  Platform  : Linux | Version {status.get('Version')}")
    print()
    if pending:
        print("  ┌─ PENDING APPROVALS ─────────────────────────────────────────────────────┐")
        for p in pending:
            print(f"  │ ID: {p['AlertId']}  |  {p['Finding'].get('name')}  |  Score: {p['Finding'].get('score')}")
        print("  └─────────────────────────────────────────────────────────────────────────┘")
        print("  Approve : python3 ransomkalki.py approve <AlertId>")
        print("  Deny    : python3 ransomkalki.py deny <AlertId>")
    print()

def cmd_monit():
    print("RansomKalki Live Monitor - Ctrl+C to exit\n")
    try:
        while True:
            os.system("clear" if os.name != "nt" else "cls")
            cmd_status()
            print(f"Updated: {datetime.now().strftime('%H:%M:%S')}  |  Refreshing every 5s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")

def cmd_logs(n=40):
    if LOG_FILE.exists():
        lines = LOG_FILE.read_text().splitlines()
        for line in lines[-n:]:
            print(line)
    else:
        print("No log file yet.")

# ---------------------------------------------------------------------------
# Real-time GUI Dashboard (stdlib http.server)
# ---------------------------------------------------------------------------
class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence request logs

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            html_file = ROOT / "dashboard.html"
            if not html_file.exists():
                html_file = ROOT.parent / "dashboard.html"
            if html_file.exists():
                self._html(html_file.read_text(encoding="utf-8"))
            else:
                self._html("<h1>dashboard.html not found</h1>")
        elif path == "/api/status":
            st = load_status() or {"Engine": "Stopped", "Platform": "Linux"}
            cfg = load_config()
            st["AutoApprove"] = cfg.get("AutoApproveEnabled", False)
            st["AutoApproveEnabled"] = cfg.get("AutoApproveEnabled", False)
            st["AutoApproveRemovals"] = cfg.get("AutoApproveRemovals", False)
            st["AutoApproveEncryptionStop"] = cfg.get("AutoApproveEncryptionStop", False)
            st["RequireApprovalForImpact"] = cfg.get("RequireApprovalForImpact", True)
            st["AutoApproveOnTimeout"] = cfg.get("AutoApproveOnTimeout", True)
            self._json(st)
        elif path == "/api/config":
            self._json(load_config())
        elif path == "/api/alerts":
            self._json(get_pending())
        elif path == "/api/logs":
            lines = []
            if LOG_FILE.exists():
                lines = LOG_FILE.read_text(errors="replace").splitlines()[-50:]
            self._json({"lines": lines})
        else:
            self.send_error(404)

    def do_POST(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        alert_id = (qs.get("id") or [""])[0]
        if path == "/api/config":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                patch = json.loads(raw)
            except Exception:
                patch = {}
            cfg = load_config()
            for k in ("AutoApproveEnabled", "AutoApproveRemovals", "AutoApproveEncryptionStop",
                      "RequireApprovalForImpact", "AutoApproveOnTimeout", "AutoApproveScoreThreshold"):
                if k in patch:
                    cfg[k] = patch[k]
            save_config(cfg)
            log.info(
                "Config updated via dashboard: AutoApproveEnabled=%s Removals=%s EncryptionStop=%s",
                cfg.get("AutoApproveEnabled"), cfg.get("AutoApproveRemovals"), cfg.get("AutoApproveEncryptionStop"),
            )
            self._json(cfg)
            return
        if path == "/api/approve" and alert_id:
            if resolve_approval(alert_id, "Approved"):
                try:
                    with open(ALERT_DIR / f"{alert_id}.json") as f:
                        a = json.load(f)
                    action_kill_quarantine(a.get("Finding") or {})
                except Exception:
                    pass
            self._json({"ok": True})
        elif path == "/api/deny" and alert_id:
            resolve_approval(alert_id, "Denied")
            self._json({"ok": True})
        else:
            self.send_error(404)

def start_dashboard(port=8787):
    server = HTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"\n  RansomKalki Dashboard running at  http://localhost:{port}/")
    print("  Press Ctrl+C to stop.\n")
    try:
        # Try to open browser
        import webbrowser
        webbrowser.open(f"http://localhost:{port}/")
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()

# ---------------------------------------------------------------------------
# Real-time Network Traffic Simulation
# ---------------------------------------------------------------------------
def run_network_simulation(mode="mixed", seconds=120):
    import random
    print()
    print("=== RansomKalki Real-Time Network Traffic Simulation ===")
    print(f"  Mode     : {mode}")
    print(f"  Duration : {seconds}s")
    print("  Dashboard: run 'python3 ransomkalki.py dashboard' in another terminal")
    print("  Press Ctrl+C to stop early.")
    print()

    c2_hosts = ["185.234.72.11", "91.219.237.44", "45.142.120.88", "103.27.202.15"]
    cloud_hosts = ["s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "transfer.sh", "mega.nz"]
    legit_hosts = ["192.168.1.10", "10.0.0.5", "172.16.0.20", "8.8.8.8", "1.1.1.1"]

    end = time.time() + seconds
    tick = 0
    try:
        while time.time() < end:
            tick += 1
            now = datetime.utcnow()

            if mode == "baseline":
                mb = round(5 + random.random() * 25, 2)
                conns = random.randint(2, 12)
                ips = random.randint(2, 8)
                suspicious = False
                pattern = "Normal office traffic"
                remotes = random.sample(legit_hosts, min(3, len(legit_hosts)))
            elif mode == "exfil":
                mb = round(400 + random.random() * 900, 2)
                conns = random.randint(15, 60)
                ips = random.randint(3, 10)
                suspicious = True
                pattern = "High-volume outbound (possible exfil)"
                remotes = random.sample(cloud_hosts, min(3, len(cloud_hosts)))
            elif mode == "c2":
                mb = round(0.5 + random.random() * 8, 2)
                conns = random.randint(1, 6)
                ips = 1
                suspicious = True
                pattern = "Periodic low-volume beaconing (possible C2)"
                remotes = [random.choice(c2_hosts)]
            elif mode == "ransomware":
                mb = round(50 + random.random() * 200, 2)
                conns = random.randint(8, 30)
                ips = random.randint(4, 12)
                suspicious = True
                pattern = "Ransomware prep: staging + C2 + backup probe"
                remotes = random.sample(c2_hosts + cloud_hosts, 4)
            else:  # mixed
                roll = random.randint(0, 99)
                if roll < 50:
                    mb = round(8 + random.random() * 40, 2)
                    conns = random.randint(3, 15)
                    ips = random.randint(3, 10)
                    suspicious = False
                    pattern = "Mixed: baseline"
                    remotes = random.sample(legit_hosts, 3)
                elif roll < 75:
                    mb = round(350 + random.random() * 600, 2)
                    conns = random.randint(20, 50)
                    ips = random.randint(4, 9)
                    suspicious = True
                    pattern = "Mixed: exfil burst"
                    remotes = random.sample(cloud_hosts, 2)
                else:
                    mb = round(1 + random.random() * 5, 2)
                    conns = random.randint(1, 4)
                    ips = 1
                    suspicious = True
                    pattern = "Mixed: C2 beacon"
                    remotes = [random.choice(c2_hosts)]

            status = {
                "Engine": "Running",
                "Pid": os.getpid(),
                "LastCycle": now.isoformat() + "Z",
                "MemoryUsedPct": round(35 + random.random() * 25, 1),
                "FindingsCount": random.randint(1, 4) if suspicious else 0,
                "PendingAlerts": random.randint(0, 2) if suspicious else 0,
                "Mode": "Alert" if suspicious else "Idle",
                "AutoApprove": True,
                "Version": "1.2.0-sim",
                "Platform": "Linux",
                "SimActive": True,
                "SimMode": mode,
                "SimPattern": pattern,
                "NetMBPerMin": mb,
                "NetExternalConns": conns,
                "NetUniqueIPs": ips,
                "NetRemotes": remotes,
                "NetSuspicious": suspicious,
                "SimTick": tick,
                "SimRemainingSec": max(0, int(end - time.time())),
            }
            save_status(status)

            if suspicious and mb >= 300:
                alert_id = "sim" + os.urandom(4).hex()
                alert_path = ALERT_DIR / f"{alert_id}.json"
                if not alert_path.exists():
                    finding = {
                        "id": 1, "type": "Network", "name": "SimulatedExfil",
                        "pid": 0, "exe": "", "memory_mb": 0, "score": 85,
                        "severity": "High",
                        "reasons": f"Simulated high outbound {mb} MB/min to {', '.join(remotes)}",
                        "timestamp": now.isoformat() + "Z",
                    }
                    package = {
                        "AlertId": alert_id,
                        "Finding": finding,
                        "SubmittedAt": now.isoformat() + "Z",
                        "TimeoutSec": 600,
                        "Status": "Pending",
                        "ExpiresAt": (now + timedelta(minutes=10)).isoformat() + "Z",
                        "Simulated": True,
                    }
                    with open(alert_path, "w") as f:
                        json.dump(package, f, indent=2)
                    log.warning(f"SIM ALERT {alert_id}: {pattern} ({mb} MB/min)")

            flag = "!" if suspicious else " "
            print(f"  [{now.strftime('%H:%M:%S')}]{flag} {pattern:<40} {mb:>8} MB/min  conns={conns}  ips={ips}")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")

    st = load_status() or {}
    st["SimActive"] = False
    st["Mode"] = "Idle"
    st["SimPattern"] = "Simulation ended"
    save_status(st)
    print("\nSimulation complete.")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    config = load_config()
    args = sys.argv[1:]
    cmd = args[0] if args else "help"
    arg1 = args[1] if len(args) > 1 else ""

    if cmd == "start":
        print("Starting RansomKalki engine (Ctrl+C to stop)...")
        run_engine(config)
    elif cmd == "stop":
        if is_running():
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            if PID_FILE.exists():
                PID_FILE.unlink()
            print("RansomKalki stopped.")
        else:
            print("RansomKalki is not running.")
    elif cmd == "status":
        cmd_status()
    elif cmd == "monit":
        cmd_monit()
    elif cmd == "logs":
        cmd_logs()
    elif cmd == "scan":
        intel = load_intel()
        snap = collect()
        findings = detect(snap, intel, config)
        if not findings:
            print("No suspicious items found.")
        else:
            for f in findings:
                print(f"[{f['id']}] {f['severity']:6} {f['name']:20} score={f['score']}  {f['reasons']}")
    elif cmd == "approve":
        if not arg1:
            print("Usage: python3 ransomkalki.py approve <AlertId>")
            return
        if resolve_approval(arg1, "Approved"):
            # load and act
            with open(ALERT_DIR / f"{arg1}.json") as f:
                a = json.load(f)
            action_kill_quarantine(a["Finding"])
            print(f"Approved and action executed for {arg1}")
        else:
            print("Alert not found.")
    elif cmd == "deny":
        if not arg1:
            print("Usage: python3 ransomkalki.py deny <AlertId>")
            return
        if resolve_approval(arg1, "Denied"):
            print(f"Denied {arg1}")
        else:
            print("Alert not found.")
    elif cmd == "dashboard":
        port = 8787
        if arg1.isdigit():
            port = int(arg1)
        start_dashboard(port)
    elif cmd == "simulate":
        mode = arg1 if arg1 in ("baseline", "exfil", "c2", "ransomware", "mixed") else "mixed"
        duration = 120
        if len(args) > 2 and args[2].isdigit():
            duration = int(args[2])
        run_network_simulation(mode, duration)
    elif cmd == "capture":
        # capture [seconds] [sample]  OR  capture full [seconds] [filter...]
        if arg1 == "full" or arg1 == "pcap":
            duration = 60
            bpf = ""
            if len(args) > 2 and args[2].isdigit():
                duration = int(args[2])
                bpf = " ".join(args[3:]) if len(args) > 3 else ""
            elif len(args) > 2:
                bpf = " ".join(args[2:])
            run_full_packet_capture(duration, bpf)
        else:
            duration = int(arg1) if arg1.isdigit() else 120
            sample = 5
            if len(args) > 2 and args[2].isdigit():
                sample = int(args[2])
            run_network_capture(duration, sample)
    elif cmd == "pcap":
        duration = int(arg1) if arg1.isdigit() else 60
        bpf = " ".join(args[2:]) if len(args) > 2 else ""
        run_full_packet_capture(duration, bpf)
    elif cmd in ("auto-on", "auto-off"):
        cfg = load_config()
        on = cmd == "auto-on"
        cfg["AutoApproveEnabled"] = on
        cfg["AutoApproveRemovals"] = on
        save_config(cfg)
        print(f"Auto-approve master={on} removals/kill={on} (RequireApprovalForImpact remains {cfg.get('RequireApprovalForImpact', True)})")
        print(f"Config: {CONFIG_FILE}")
    elif cmd == "install":
        print("=== RansomKalki Auto-Installation (Linux) ===\n")
        # Ensure dirs + default config
        for d in (DATA_DIR, LOG_DIR, ALERT_DIR, QUARANTINE_DIR, ROOT / "config"):
            d.mkdir(parents=True, exist_ok=True)
        load_config()  # writes default engine.json if missing
        print(f"  [+] Directories and config ready")

        unit_path = Path("/etc/systemd/system/ransomkalki.service")
        unit = f"""[Unit]
Description=RansomKalki Anti-Ransomware + System Cleaner Engine
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {Path(__file__).resolve()} start
Restart=on-failure
RestartSec=5
Nice=10
WorkingDirectory={ROOT}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        if os.geteuid() == 0:
            unit_path.write_text(unit)
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", "ransomkalki"], check=False)
            subprocess.run(["systemctl", "restart", "ransomkalki"], check=False)
            print(f"  [+] Systemd unit written to {unit_path}")
            print("  [+] Service enabled and started")
            print("\nInstallation complete. Check status with:")
            print("  python3 ransomkalki.py status")
            print("  systemctl status ransomkalki")
        else:
            print("  [!] Not running as root — cannot write systemd unit automatically.")
            print("  Run with sudo for full auto-install, or manually:")
            print(f"\n  sudo tee {unit_path} << 'EOF'\n{unit}EOF")
            print("  sudo systemctl daemon-reload && sudo systemctl enable --now ransomkalki")
            print(f"\n  Config file (edit AutoApprove* settings): {CONFIG_FILE}")
    else:
        print("""
RansomKalki - Anti-Ransomware + System Cleaner (Linux)
Copyright © RansomKalki

Usage:  python3 ransomkalki.py <command> [args]

Commands:
  start           Start the engine (foreground)
  stop            Stop the engine
  status          Show current status (pm2-style)
  monit           Live status monitor
  logs            Show recent logs
  scan            One-shot scan
  approve <id>    Approve pending alert + execute
  deny <id>       Deny pending alert
  install         Auto-install as systemd service (use sudo)
  auto-on         Enable auto-approve kill/removals
  auto-off        Disable auto-approve kill/removals
  dashboard [port]  Open real-time GUI dashboard (default port 8787)
  simulate [mode] [seconds]
                  Synthetic network traffic simulation
                  Modes: baseline | exfil | c2 | ransomware | mixed
  capture [seconds] [sample_sec]
                  REAL network flow capture (/proc/net/dev + /proc/net/tcp)
  capture full [seconds] [bpf filter...]
                  FULL packet capture via tcpdump → PCAP file
  pcap [seconds] [bpf filter...]
                  Alias for capture full
  help            This help

Auto-Approval (config/engine.json):
  AutoApproveEnabled        = true/false
  AutoApproveScoreThreshold = 80   (score >= this → act immediately)
  AutoApproveOnTimeout      = true (timeout → act)
  RequireApprovalForImpact  = true (force human for encryption-class)

Examples:
  python3 ransomkalki.py dashboard
  python3 ransomkalki.py capture 60
  python3 ransomkalki.py pcap 30
  sudo python3 ransomkalki.py pcap 60 port 443
  python3 ransomkalki.py simulate exfil 60
""")

if __name__ == "__main__":
    main()
