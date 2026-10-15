# Sniffton

**Anti-Ransomware + System Cleaner Engine**  
Copyright © Sniffton · Version 1.4

---

## Who should use this software?

Sniffton is built for people and teams who need **practical ransomware defense and system hygiene** without buying a full enterprise EDR stack or installing heavy third-party agents.

| Audience | Typical use |
|----------|-------------|
| **IT administrators** (SMB / mid-market) | Continuous monitoring on Windows servers and workstations, scheduled scans, approval workflow for risky actions |
| **Security operations / SOC analysts** | Early detection of shadow-copy deletion, high outbound volume, suspicious processes; PCAP for incident evidence |
| **MSP / managed service providers** | Lightweight agent-style deployment across client machines with a consistent status console and auto-install |
| **System builders / power users** | Single-machine protection on Windows or Linux with a live dashboard and optional simulation for training |
| **Developers & red/blue teams** | Test detection logic with synthetic traffic; capture real flows and full packets during exercises |
| **Compliance / risk owners** | Demonstrate monitoring, approval timeouts, quarantine, and forensic-style logging |

### What it is for

- **Early detection** of ransomware-style behaviour (high memory/disk abuse, recovery-inhibition, staging, exfiltration patterns)
- **Prevention posture** through process/path heuristics, threat-intel lists, and auto-quarantine of high-confidence threats
- **Controlled response** with admin approval + timeout auto-action (including impact-class events)
- **Visibility** via a pm2-style CLI and a real-time web dashboard
- **Evidence collection** via flow capture and full packet capture (PCAP/ETL)
- **Demo and training** via built-in network traffic simulation

### What it is not

- Not a replacement for enterprise EDR/XDR (CrowdStrike, SentinelOne, Defender for Endpoint, etc.)
- Not a full AV signature engine
- Not a network TAP or hardware packet broker
- Full L7 deep packet inspection still depends on OS tools (`pktmon` / `tcpdump`) and offline analysis (e.g. Wireshark)

---

## Table of contents

1. [Platform support](#1-platform-support)
2. [Architecture overview](#2-architecture-overview)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Command reference](#5-command-reference)
6. [Modules and features](#6-modules-and-features)
7. [Dashboard guide](#7-dashboard-guide)
8. [Network capture](#8-network-capture)
9. [Simulation (demo / training)](#9-simulation-demo--training)
10. [Approval workflow](#10-approval-workflow)
11. [Logs, data, and quarantine](#11-logs-data-and-quarantine)
12. [Operational recommendations](#12-operational-recommendations)
13. [Troubleshooting](#13-troubleshooting)
14. [License](#14-license)

---

## 1. Platform support

| Platform | Primary implementation | Runtime requirements |
|----------|------------------------|----------------------|
| **Windows** 10 / 11 / Server | `Windows/Sniffton.ps1` | PowerShell 5.1+, Administrator |
| **Linux** | `Linux/sniffton.py` | Python 3.6+ (stdlib only), root recommended for PCAP |
| **Unix / POSIX** | `Unix/sniffton.sh` | POSIX `sh`; lightweight sensor only |

**Design rules:**

- No pip / NuGet / external language packages required for core operation
- Full PCAP uses **OS-native tools only**: Windows `pktmon`, Linux `tcpdump`
- Flow capture works with zero extra software

---

## 2. Architecture overview

```
                    ┌─────────────────────────┐
                    │   CLI / Dashboard UI     │
                    │  status · monit · web    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Sniffton Engine     │
                    │  collect → detect →     │
                    │  approve → act → log    │
                    └────────────┬────────────┘
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   ┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
   │  Sensors    │      │  Network     │      │  Response       │
   │  process    │      │  flow/PCAP   │      │  quarantine     │
   │  memory     │      │  simulate    │      │  kill / disable │
   │  persistence│      │              │      │  alerts         │
   └─────────────┘      └──────────────┘      └─────────────────┘
```

**Main loops:**

1. **Idle cycle** – low-frequency collect + detect (default ~60s)
2. **Alert cycle** – higher frequency when findings exist (default ~15s)
3. **Approval path** – high-score items wait for admin or auto-act on timeout / threshold
4. **Capture / simulate** – optional foreground jobs that feed the same status file the dashboard reads

---

## 3. Installation

### 3.1 Windows

1. Copy the `Sniffton` folder to a fixed location, e.g. `C:\ProgramData\Sniffton` or `C:\Tools\Sniffton`.
2. Open **PowerShell as Administrator**.
3. Allow script execution for this session if needed:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

4. Install (creates folders, default config, Scheduled Task, starts engine):

```powershell
cd C:\Tools\Sniffton\Windows
.\Sniffton.ps1 install
```

5. Verify:

```powershell
.\Sniffton.ps1 status
.\Sniffton.ps1 dashboard
```

**What `install` does:**

- Creates `Data`, `Logs`, `Data\alerts`, `Data\Quarantine`, `Config`
- Writes default `Config\engine.json` if missing
- Registers Scheduled Task **SnifftonEngine** (SYSTEM, at startup, restart on failure)
- Starts the task immediately when possible

**Uninstall:**

```powershell
.\Sniffton.ps1 uninstall
.\Sniffton.ps1 stop
```

### 3.2 Linux

1. Copy the project tree (at least `Linux/` and shared `dashboard.html` if used).
2. Prefer root for service install and full PCAP:

```bash
cd /opt/sniffton/Linux   # example path
sudo python3 sniffton.py install
```

3. If not root, `install` prints a systemd unit you can install manually:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sniffton
```

4. Verify:

```bash
python3 sniffton.py status
python3 sniffton.py dashboard
```

### 3.3 Unix (POSIX)

Lightweight sensor only:

```bash
cd Sniffton/Unix
chmod +x sniffton.sh
./sniffton.sh start
./sniffton.sh status
```

For full features on Unix-like systems, use the **Linux Python** build when `python3` is available.

---

## 4. Configuration

### 4.1 Config file locations

| Platform | Path |
|----------|------|
| Windows | `Windows\Config\engine.json` |
| Linux | `Linux/config/engine.json` |

Created automatically on first run / install with defaults.

### 4.2 Settings reference

| Key | Default | Meaning |
|-----|---------|---------|
| `PollIntervalIdleSec` | `60` | Seconds between cycles when system looks clean |
| `PollIntervalAlertSec` | `15` | Seconds between cycles when findings/alerts exist |
| `ApprovalTimeoutImpact` | `600` | Seconds to wait for admin on high/impact findings (10 min) |
| `ApprovalTimeoutNormal` | `3600` | Seconds for medium findings (60 min) |
| `HighMemoryMB` | `700` | Process RSS above this contributes to score |
| `HighThreadCount` | `90` | High thread count contributes to score |
| `AdminEmail` | `admin@company.com` | Reserved for email notifications |
| `EnableEmail` | `false` | Enable outbound email when implemented/configured |
| `QuarantineDir` | *(under Data)* | Where quarantined binaries are moved |
| `AutoApproveEnabled` | `true` | Master switch for automatic actions |
| `AutoApproveScoreThreshold` | `80` | Score ≥ this → act immediately (if not impact-forced) |
| `AutoApproveOnTimeout` | `true` | When approval window expires → act |
| `RequireApprovalForImpact` | `true` | Force human path for encryption / recovery-inhibition class events |

### 4.3 Example `engine.json`

```json
{
  "PollIntervalIdleSec": 60,
  "PollIntervalAlertSec": 15,
  "ApprovalTimeoutImpact": 600,
  "ApprovalTimeoutNormal": 3600,
  "HighMemoryMB": 700,
  "HighThreadCount": 90,
  "AdminEmail": "soc@yourdomain.com",
  "EnableEmail": false,
  "AutoApproveEnabled": true,
  "AutoApproveScoreThreshold": 80,
  "AutoApproveOnTimeout": true,
  "RequireApprovalForImpact": true
}
```

### 4.4 Threat intelligence file

Optional local list: `Data/threat_intel.txt` (Windows) or `data/threat_intel.txt` (Linux).

Format:

```text
# Sniffton Threat Intelligence
[PROCESS_NAMES]
xmrig
minerd
coinminer

[PATH_PATTERNS]
\Temp\
\AppData\Local\Temp\

[FILE_NAMES]
miner.exe
```

Built-in miner/spyware name lists are always loaded; this file extends them.

---

## 5. Command reference

### 5.1 Windows (`Sniffton.ps1`)

Run from `Windows\` as Administrator:

| Command | Description |
|---------|-------------|
| `.\Sniffton.ps1 install` | Auto-install folders, config, Scheduled Task, start engine |
| `.\Sniffton.ps1 uninstall` | Remove Scheduled Task |
| `.\Sniffton.ps1 start` | Run engine in foreground |
| `.\Sniffton.ps1 stop` | Stop running engine |
| `.\Sniffton.ps1 status` | One-shot status (pm2-style) |
| `.\Sniffton.ps1 monit` | Live console status (5s refresh) |
| `.\Sniffton.ps1 logs` | Tail engine log |
| `.\Sniffton.ps1 scan` | One-shot detect and print findings |
| `.\Sniffton.ps1 approve -Id <id>` | Approve pending alert and execute action |
| `.\Sniffton.ps1 deny -Id <id>` | Deny pending alert |
| `.\Sniffton.ps1 dashboard [-Port 8787]` | Open real-time web dashboard |
| `.\Sniffton.ps1 simulate -SimMode mixed -DurationSec 120` | Synthetic traffic for demos |
| `.\Sniffton.ps1 capture -DurationSec 120 -SampleSec 5` | Real flow-level capture |
| `.\Sniffton.ps1 pcap -DurationSec 60` | Full packet capture (pktmon) |
| `.\Sniffton.ps1 capture -Full -DurationSec 60 -Filter "TCP Port 443"` | Full PCAP with filter |
| `.\Sniffton.ps1 help` | Help text |

### 5.2 Linux (`sniffton.py`)

```bash
python3 sniffton.py <command> [args]
```

| Command | Description |
|---------|-------------|
| `install` | systemd unit + dirs + config (use `sudo` for full auto) |
| `start` / `stop` | Foreground engine / stop by PID file |
| `status` / `monit` / `logs` | Status console |
| `scan` | One-shot scan |
| `approve <id>` / `deny <id>` | Approval actions |
| `dashboard [port]` | Web dashboard (default 8787) |
| `simulate [mode] [seconds]` | Synthetic traffic |
| `capture [seconds] [sample]` | Flow capture |
| `pcap [seconds] [bpf...]` | Full PCAP via tcpdump |
| `capture full [seconds] [bpf...]` | Same as `pcap` |

### 5.3 Unix (`sniffton.sh`)

| Command | Description |
|---------|-------------|
| `./sniffton.sh start` | Lightweight monitoring loop |
| `./sniffton.sh stop` | Stop |
| `./sniffton.sh status` | Status |
| `./sniffton.sh logs` | Log tail |

---

## 6. Modules and features

### 6.1 Collector

Gathers:

- Memory usage
- Process list (name, path, RSS, threads)
- Disk pressure indicators (Windows)
- Point-in-time external TCP connection summary

### 6.2 Detector

Scores processes and system signals using:

- Threat-intel process/path patterns
- High memory / high thread counts
- Unusual install locations (Temp, AppData, Public, etc.)
- System-wide memory/disk pressure

Typical score contributions (illustrative):

| Signal | Approx. points |
|--------|----------------|
| Name matches threat intel | +40 |
| Suspicious path | +25 |
| Unusual location | +10 |
| High memory | +15 |
| High threads | +15 |

Items with score ≥ 60 enter the response path; ≥ `AutoApproveScoreThreshold` may auto-act.

### 6.3 Threat intelligence

- Built-in lists (miners, common PUPs, suspicious updater names)
- Optional `threat_intel.txt` extension
- No cloud account required for core detection

### 6.4 Approval gateway

- Writes JSON alert packages under `Data/alerts`
- CLI and dashboard can Approve / Deny
- Timeout and score-based auto-approval controlled by config

### 6.5 Action engine

On approve or auto-approve:

- Stop process (non-critical only)
- Quarantine executable when path is outside protected system directories
- Record outcome in log

**Never** targets a hard-coded critical process list (e.g. `csrss`, `lsass`, `systemd`, etc.).

### 6.6 Self-protection and safety

- Critical process denylist
- Preference to avoid System32 / WinSxS / core Unix paths
- Fail-safe logging when an action is refused

### 6.7 Status and dashboard

- `status.json` is the shared state file
- CLI `status` / `monit` and web dashboard all read the same data
- Capture and simulation jobs write into the same schema

---

## 7. Dashboard guide

### 7.1 Starting the dashboard

```powershell
# Windows
.\Sniffton.ps1 dashboard
.\Sniffton.ps1 dashboard -Port 8790
```

```bash
# Linux
python3 sniffton.py dashboard
python3 sniffton.py dashboard 8790
```

Browser opens at `http://localhost:8787/` (localhost only).

### 7.2 Layout

| Area | What it means |
|------|----------------|
| **Header badge ONLINE / OFFLINE** | Whether a recent status file shows the engine (or capture/sim job) as running |
| **Engine** | `Running` / stopped; subtext shows Mode `Idle` or `Alert` |
| **Memory Used** | Host RAM usage percentage from last sample |
| **Findings** | Number of detector hits in the last cycle |
| **Pending Approvals** | Count of alerts waiting for Yes/No (or timeout) |
| **Auto-Approve** | `ON` / `OFF` from config / status |
| **Platform / Version** | Windows or Linux and engine version string |
| **Outbound Traffic (MB/min)** | From live capture or simulation; **turns red at ≥ 300** |
| **External Conns** | Established TCP sessions to non-private IPs |
| **Unique Remote IPs** | Distinct external destinations |
| **Traffic Pattern** | Human-readable label (`Live capture`, `exfil burst`, `FULL packet capture`, etc.) |
| **Simulation banner** | Purple bar when simulation or full PCAP is running; shows targets / time left |
| **Pending Approvals table** | Each alert with Score, Severity, Reasons, Expiry, **Approve** / **Deny** buttons |
| **Recent Engine Log** | Last lines of the engine log file |

### 7.3 How to interpret common situations

| You see | Likely meaning | Suggested action |
|---------|----------------|------------------|
| ONLINE + Mode Idle + low MB/min | Healthy baseline | No action |
| Mode Alert + Findings > 0 | Detector saw scored items | Open approvals table / run `scan` |
| Pending Approvals ≥ 1 | Waiting on human or timeout | Approve, Deny, or wait for auto policy |
| Outbound MB/min ≥ 300 (red) | Possible exfiltration or backup/sync storm | Investigate top remotes; consider PCAP |
| FULL packet capture banner | `pcap` job active | Wait for completion; open file under `captures/` |
| OFFLINE | Engine/sim/capture not updating status | `start` or `install`; check logs |

### 7.4 Approving from the dashboard

1. Identify the row (name, score, reasons).
2. Click **Approve** to execute the planned action (e.g. kill + quarantine).
3. Click **Deny** to dismiss without action.
4. Table refreshes on the next 3-second poll.

Same operations exist on the CLI for scripting and SSH-only hosts.

---

## 8. Network capture

### 8.1 Flow-level capture (always available)

Measures real throughput and connection tables; feeds the dashboard.

```powershell
.\Sniffton.ps1 capture -DurationSec 120 -SampleSec 5
```

```bash
python3 sniffton.py capture 120 5
```

**Sources:**

- Windows: `Get-NetAdapterStatistics`, `Get-NetTCPConnection`
- Linux: `/proc/net/dev`, `/proc/net/tcp`

**Alerts:** High outbound volume (≥ 300 MB/min) or large external fan-out can create pending alerts.

### 8.2 Full packet capture

**Windows (pktmon):**

```powershell
.\Sniffton.ps1 pcap -DurationSec 60
.\Sniffton.ps1 capture -Full -DurationSec 60 -Filter "TCP Port 443"
```

Requires Windows 10 1809+ or Server 2019+. Output under `Data\captures\`:

- `sniffton_YYYYMMDD_HHMMSS.etl`
- `.pcap` when conversion succeeds
- `.summary.txt`

**Linux (tcpdump):**

```bash
sudo python3 sniffton.py pcap 60
sudo python3 sniffton.py pcap 60 port 443
```

Install tcpdump if missing (`sudo apt install tcpdump`). Output: `data/captures/sniffton_*.pcap`.

Open PCAP files in **Wireshark** for protocol-level analysis.

---

## 9. Simulation (demo / training)

Synthetic metrics and optional fake alerts — **no real packets sent**.

```powershell
.\Sniffton.ps1 simulate -SimMode exfil -DurationSec 60
.\Sniffton.ps1 simulate -SimMode mixed -DurationSec 120
```

```bash
python3 sniffton.py simulate exfil 60
python3 sniffton.py simulate mixed 120
```

| Mode | Behaviour |
|------|-----------|
| `baseline` | Low MB/min, mostly private/legit destinations |
| `exfil` | High outbound bursts toward cloud-like hosts |
| `c2` | Low-and-slow beaconing to suspicious IPs |
| `ransomware` | Mix of staging / C2 / probe-style patterns |
| `mixed` | Alternates baseline, exfil, and C2 (default) |

Use with the dashboard open to train analysts on reading MB/min spikes and approval rows.

---

## 10. Approval workflow

```
Finding (score ≥ 60)
        │
        ├─ score ≥ AutoApproveScoreThreshold
        │     and not forced-impact
        │        → AUTO-APPROVE → Action → Log
        │
        └─ else
              → Write alert JSON → Notify (status/dashboard)
              → Wait up to ApprovalTimeout*
                    ├─ Admin Approve → Action
                    ├─ Admin Deny    → No action
                    └─ Timeout + AutoApproveOnTimeout → Action
```

**Impact-class** (encryption / shadow / backup keywords): if `RequireApprovalForImpact` is true, human approval is required even when the score is high.

---

## 11. Logs, data, and quarantine

### Windows paths (under `Windows\`)

| Path | Purpose |
|------|---------|
| `Logs\engine.log` | Main engine log |
| `Data\status.json` | Live status for CLI/dashboard |
| `Data\alerts\*.json` | Pending / resolved approval packages |
| `Data\Quarantine\` | Quarantined files |
| `Data\captures\` | Flow summaries / PCAP / ETL |
| `Data\threat_intel.txt` | Optional intel |
| `Config\engine.json` | Configuration |

### Linux paths (under `Linux/`)

| Path | Purpose |
|------|---------|
| `logs/engine.log` | Main log |
| `data/status.json` | Status |
| `data/alerts/` | Alerts |
| `data/quarantine/` | Quarantine |
| `data/captures/` | PCAP + summaries |
| `config/engine.json` | Configuration |

Retain logs and captures according to your incident-response policy. Quarantine is not a substitute for forensic imaging.

---

## 12. Operational recommendations

1. **Deploy with `install`** so the engine survives reboot (Scheduled Task / systemd).
2. **Keep AutoApprove enabled** for high-score non-impact malware-like processes; keep **RequireApprovalForImpact** enabled so encryption-class behaviour is not silently auto-cleared without review.
3. **Run flow capture** during suspected incidents; escalate to **full PCAP** when you need payload evidence.
4. **Use simulation only on lab/demo systems** — it creates intentional alert noise.
5. **Review quarantine** before permanent deletion; restore false positives carefully.
6. **Pair with OS backups** (VSS, Timeshift, ZFS snapshots, etc.). Sniffton complements backups; it does not replace them.
7. **Resource target:** idle footprint should stay modest (tens of MB RAM, near-zero CPU between polls). Raise poll intervals on constrained hosts.

---

## 13. Troubleshooting

| Problem | What to check |
|---------|----------------|
| `status` shows STOPPED | Run `start` or `install`; on Windows confirm Scheduled Task **SnifftonEngine** |
| Dashboard OFFLINE | Engine/capture/sim not writing `status.json`; check path permissions |
| Dashboard port in use | `dashboard -Port 8790` or `dashboard 8790` |
| PCAP fails on Windows | Need Win 10 1809+ / Server 2019+ and `pktmon`; else flow capture still works |
| PCAP fails on Linux | Install `tcpdump`; run with `sudo` |
| Access denied / cannot kill process | Run as Administrator / root |
| Too many false positives | Raise `AutoApproveScoreThreshold`; tighten `threat_intel.txt`; add exceptions for your environment |
| Script execution blocked (Windows) | `Set-ExecutionPolicy -Scope Process Bypass` |

---

## 14. License

Copyright © Sniffton  
All rights reserved.

This software is provided for authorized defensive security use on systems you own or are licensed to protect.  
You are responsible for compliance with local law and organizational policy when capturing network traffic or quarantining files.

---

### Quick start checklist

1. Install on the target OS (`install`).
2. Confirm `status` → ONLINE.
3. Open `dashboard`.
4. Optionally run `scan`, then `simulate mixed` in a lab to learn the UI.
5. Tune `engine.json` for your risk tolerance.
6. During an incident: `capture` → escalate to `pcap` → review `alerts` and quarantine.

For algorithm design context (kill-chain mapping, Zero Trust layers, competitive notes), see the companion document:

`Anti_Ransomware_Algorithm_Specification.pdf`
