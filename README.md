# VectorStryke

Cross-platform anti-ransomware and system hygiene agent for **Windows**, **Linux**, and **Unix**, with an optional multi-tenant console.

VectorStryke focuses on kill-chain monitoring, behavioral heuristics, admin approval workflows, canary/checkpoint recovery hooks, OS-security detection, and quarantine-first OS file scanning — without external package dependencies.

**Who should use this**
- SMB / mid-market IT and operators who need a lightweight agent
- Admins who want Manual or Automatic response modes
- Sites that already have OS antivirus or backup products and need coexistence + orchestration hooks
- Single machines and small fleets (optional central console)

**Who it is not replacing**
- Full enterprise EDR/XDR platforms
- Dedicated backup appliances
- Managed detection (MDR) services

---

## Architecture (summary)

```
CLI  →  Engine loop  →  Sensors → Detectors → ResponsePolicy
                              ↓
                    Actions / Approval / Recovery
                              ↓
              OS-SEC detect  →  OS file scan (optional)
                              ↓
                    status.json · local dashboard · optional Console
```

| Layer | Role |
|-------|------|
| Telemetry | Process / memory (extensible) |
| Detect | Ransomware-oriented findings + scores |
| Policy | **Automatic** (act) or **Manual** (approve; timeout never auto-acts) |
| Recovery | Canaries, checkpoint, ImpactPending |
| OS-SEC | Detect Present / Partial / Absent OS security; coexist; fallback gated |
| OS scan | Quarantine-first file scan after OS-SEC |
| Console | Optional fleet enroll / heartbeat / remote approve |

**Code layout**
- `Linux/` — `vectorstryke.py` + OOP `vs_core/`
- `Windows/` — `VectorStryke.ps1` + `Modules/00–16`
- `Unix/` — `vectorstryke.sh` lightweight sensor
- `Console/` — multi-tenant console API + UI

---

## Install and run

### Linux
```bash
cd Linux
python3 vectorstryke.py install
python3 vectorstryke.py start
python3 vectorstryke.py status
```

### Windows (PowerShell as Administrator recommended)
```powershell
cd Windows
.\VectorStryke.ps1 install
.\VectorStryke.ps1 start
.\VectorStryke.ps1 status
```

### Unix
```bash
cd Unix
sh vectorstryke.sh install   # if provided
sh vectorstryke.sh start
sh vectorstryke.sh status
```

### Console (optional)
```bash
cd Console
sh install.sh          # or install.ps1 on Windows
# open console dashboard; set agent ConsoleEnabled / ConsoleUrl / TenantId
```

---


## CLI modes (complete)

### Response mode (ransomware actions)
| Command | Effect |
|---------|--------|
| `mode automatic` | Fully automatic — no approvals |
| `mode manual` | Approvals required; timeout never auto-acts |
| `mode list` / `modes` | Show all mode settings |
| `auto-on` | Alias for automatic |
| `auto-off` | Alias for manual |

### OS-SEC mode
| Command | Effect |
|---------|--------|
| `ossec-mode auto` | Follow Present/Partial/Absent classification |
| `ossec-mode coexist` | Observe/recommend only; fallback off |
| `ossec-mode fallback` | Allow fallback when Class=Absent (admin opt-in) |
| `ossec-status` | Run detection and print Class + signals |

### Examples
```bash
# Linux
python3 vectorstryke.py modes
python3 vectorstryke.py mode automatic
python3 vectorstryke.py mode manual
python3 vectorstryke.py ossec-mode coexist
python3 vectorstryke.py ossec-status

# Windows
.\VectorStryke.ps1 modes
.\VectorStryke.ps1 mode -Id Automatic
.\VectorStryke.ps1 mode -Id Manual
.\VectorStryke.ps1 ossec-mode -Id Coexist
.\VectorStryke.ps1 ossec-status

# Unix
sh vectorstryke.sh modes
sh vectorstryke.sh mode automatic
sh vectorstryke.sh ossec-mode coexist
sh vectorstryke.sh ossec-status
```

## Response modes

| Mode | Behavior |
|------|----------|
| **Automatic** | Act on high-score findings without pending approval |
| **Manual** | Always queue for approve/deny; **timeout never auto-acts** |

```bash
# Linux
python3 vectorstryke.py mode automatic
python3 vectorstryke.py mode manual

# Windows
.\VectorStryke.ps1 mode -Id Automatic
.\VectorStryke.ps1 mode -Id Manual
```

---

## OS security (detect-first)

Always **detect** built-in / vendor OS security before applying any fallback controls.

| Class | Meaning | Engine behavior |
|-------|---------|-----------------|
| **Present** | Realtime AV/agent or strong OS protection | Coexist only |
| **Partial** | Weak signals (e.g. firewall only) | Coexist + recommendations |
| **Absent** | Nothing usable detected | Fallback eligible only if admin enables it |

Defaults: detection **on**, fallback **off** (`OsSecurityDetectionOnly=true`, `OsSecurityFallbackEnabled=false`).

```bash
# Linux
python3 vectorstryke.py ossec-status
python3 vectorstryke.py health          # includes OsSecurity block

# Windows
.\VectorStryke.ps1 ossec-status
.\VectorStryke.ps1 health

# Unix
sh vectorstryke.sh ossec-status
```

Fallback OS-security **apply** (host firewall baseline pack, etc.) is algorithm-defined (Group C) and gated; detection ships first.

---

## OS file scan (quarantine-first)

After OS-SEC classification, optional file scan:

1. Init env / exclusions / optional hash baseline  
2. Enumerate roots (default: user Downloads/Desktop/temp — not full disk unless `full`)  
3. Signature + entropy + string heuristics → score 0–100  
4. **Quarantine** Suspicious (31–70) and Malicious (71–100) **before** any delete  
5. Auto-delete malicious defaults **OFF**

```bash
# Linux
python3 vectorstryke.py osscan
python3 vectorstryke.py osscan baseline
python3 vectorstryke.py osscan full

# Windows
.\VectorStryke.ps1 osscan
.\VectorStryke.ps1 osscan -Id baseline
.\VectorStryke.ps1 osscan -Id full

# Unix (name heuristics only)
sh vectorstryke.sh osscan
```

Reports: `data/osscan_report_*.json`  
Quarantine: `data/osscan_quarantine/` (Linux) or `Data/OsScanQuarantine/` (Windows)

Config: `OsScanMaxFiles`, `OsScanAutoQuarantine`, `OsScanAutoDeleteMalicious` (false), `OsScanExtraExclusions`.

---

## Recovery and updates

```bash
# Canaries / checkpoint / impact
python3 vectorstryke.py canary-init
python3 vectorstryke.py canary-verify
python3 vectorstryke.py checkpoint
python3 vectorstryke.py impact-clear

# Updates / LKG
python3 vectorstryke.py update-check
python3 vectorstryke.py update-apply
python3 vectorstryke.py lkg-save
python3 vectorstryke.py rollback
```

Same command names on Windows (`.\VectorStryke.ps1 ...`).

Backup product orchestration (webhook/CLI on ImpactPending) is algorithm-defined; enable via `Backup.*` config when configured.

---

## Dashboard and console

- **Local dashboard** — single host status UI (`dashboard.html` / platform copy)
- **Console** — fleet view: enroll, heartbeat, remote approve/policy

Agents work **without** console (fail-soft).

---

## Modules (Windows)

| Module | Role |
|--------|------|
| 00–03 | Paths, Config, Logging, ResponsePolicy |
| 04–07 | Telemetry, Detect, Actions, Approval |
| 08–11 | Recovery, Health, Update, Console |
| 12 | Engine |
| 14 | OS-SEC detect |
| 16 | OS file scan |

## Packages (Linux `vs_core`)

`base`, `config`, `policy`, `telemetry`, `detect`, `actions`, `approval`, `recovery`, `health`, `update`, `console_client`, `engine`, `os_security`, `os_scan`

---

## Safety posture

- No external runtime package dependencies (Python stdlib / PowerShell 5.1 / POSIX sh)
- Quarantine-first file handling
- Does not disable OS antivirus or other agents
- Manual mode: timeout expires only — never auto-kill
- System-critical paths excluded from destructive scan actions

---

## Documentation in this project

| File | Content |
|------|---------|
| `README.md` | This guide |
| Algorithm Specification PDF | Kill-chain algorithm, OS-SEC, OS scan, coding steps |
| Architecture PDF | Modular architecture + diagrams |
| Competitiveness Analysis PDF | Market positioning (separate) |

---

## Quick command cheat sheet

| Action | Linux | Windows |
|--------|-------|---------|
| Start / stop / status | `start` `stop` `status` | same |
| Mode | `mode automatic\|manual` | `mode -Id Automatic\|Manual` |
| OS-SEC | `ossec-status` | `ossec-status` |
| OS scan | `osscan` `[baseline\|full]` | `osscan` `[-Id baseline\|full]` |
| Health | `health` | `health` |
| Approve / deny | `approve id` `deny id` | `approve -Id` `deny -Id` |

---

©VectorStryke
