# VectorStryke

**Anti-Ransomware + System Cleaner Engine**  
Copyright © VectorStryke · Version 1.5

Cross-platform ransomware defense for Windows, Linux, and Unix with a local dashboard and optional multi-tenant network console.

## Who should use this

- IT admins (SMB / mid-market)
- SOC analysts
- MSPs managing multiple client endpoints
- Power users and blue/red teams

## Platform layout

| Platform | Path | Notes |
|----------|------|-------|
| Windows | `Windows/VectorStryke.ps1` | Full engine, Scheduled Task, local dashboard |
| Linux | `Linux/vectorstryke.py` | Full engine (Python stdlib), systemd |
| Unix | `Unix/vectorstryke.sh` | Lightweight realtime sensor |
| Console | `Console/console.py` | Multi-tenant fleet console |

## Quick start

### Windows (Admin PowerShell)

```powershell
cd Windows
.\VectorStryke.ps1 install
.\VectorStryke.ps1 status
.\VectorStryke.ps1 dashboard
```

### Linux

```bash
cd Linux
sudo python3 vectorstryke.py install
python3 vectorstryke.py status
python3 vectorstryke.py dashboard
```

### Unix sensor

```bash
cd Unix
./vectorstryke.sh start
./vectorstryke.sh status
```

### Central console (fleet)

```bash
cd Console
sudo ./install.sh --port 9000
# or: python3 console.py --host 0.0.0.0 --port 9000
# Open http://localhost:9000/
```

Windows console host:

```powershell
cd Console
.\install.ps1 -Port 9000
```

## Local dashboard vs network console

| Surface | Scope | URL |
|---------|--------|-----|
| Local installation dashboard | One host | `http://localhost:8787/` |
| Network central console | All enrolled nodes | `http://console-host:9000/` |

When `ConsoleEnabled` and `ConsoleUrl` are set on an agent, the local dashboard shows **Open Network Console**.

### Agent console config (`engine.json`)

```json
{
  "ConsoleEnabled": true,
  "ConsoleUrl": "http://console-host:9000",
  "TenantId": "acme-corp",
  "EnrollmentToken": ""
}
```

`AgentId` is auto-generated: `win-<hash>`, `lin-<hash>`, `unix-<hash>`.

## Approval policy (safe defaults)

| Setting | Default | Meaning |
|---------|---------|--------|
| AutoApproveEnabled | false | Master auto-action switch |
| AutoApproveRemovals | false | Auto kill/quarantine |
| AutoApproveEncryptionStop | false | Auto impact mitigation |
| RequireApprovalForImpact | true | Force human for encryption-class |
| AutoApproveOnTimeout | true | Act if admin silent |

Toggles:

```text
Windows: .\VectorStryke.ps1 auto-on | auto-off
Linux:   python3 vectorstryke.py auto-on | auto-off
Unix:    ./vectorstryke.sh auto-on | auto-off
```

Also available from local dashboard policy panel and central console (Kill auto ON/OFF, tenant policy push).

## Key commands

`start` `stop` `status` `monit` `scan` `approve` `deny` `install` `dashboard` `capture` `pcap` `simulate` `auto-on` `auto-off`

## Docs in this repo

- `docs/Anti_Ransomware_Algorithm_Specification.pdf` — algorithm specification v2.5
- `vectorstryke.html` — marketing page
- `docs/ransomware_flowchart.dot` / `.png` — flowchart

## Design principles

- No pip/NuGet for core agents
- Low idle resource use
- Human approval for destructive actions by default
- Agents keep working if console is offline

## License

See `LICENSE` in this repository. Product © Sniffton / VectorStryke.
