#!/usr/bin/env python3
"""
VectorStryke — Anti-Ransomware + System Cleaner (Linux)
Modular OOP core under vs_core/ — extensible toward full EDR/XDR.
Copyright © VectorStryke

Usage:
  python3 vectorstryke.py start|stop|status|scan|approve|deny|install|health|...
  python3 vectorstryke.py mode automatic|manual
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vs_core.engine import Engine
from vs_core import __version__


def engine() -> Engine:
    return Engine(ROOT)


def cmd_status(eng: Engine) -> None:
    eng.reload()
    st = {}
    if eng.paths.status_file.exists():
        try:
            st = json.loads(eng.paths.status_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    running = eng.is_running()
    print("")
    print("=== VECTORSTRYKE STATUS ===")
    print(f"  Version      : {eng.config.get('Version') or __version__}")
    print(f"  ResponseMode : {eng.config.get('ResponseMode') or 'Automatic'}")
    print(f"  Status       : {'ONLINE' if running else 'STOPPED'}")
    print(f"  Profile      : {eng.config.get('Profile')}")
    print(f"  FirstRun     : {eng.config.get('FirstRunState')}")
    print(f"  AgentId      : {eng.config.get('AgentId')}")
    print(f"  TenantId     : {eng.config.get('TenantId')}")
    print(f"  ImpactPending: {eng.config.get('ImpactPending')}")
    if st:
        print(f"  Engine Mode  : {st.get('Mode')}")
        print(f"  Findings     : {st.get('FindingsCount')}")
        print(f"  Pending      : {st.get('PendingAlerts')}")
        print(f"  HealthOk     : {st.get('HealthOk')}")
    print(f"  Policy note  : timeout never auto-acts; Automatic mode = no approvals")
    print("")


def cmd_install(eng: Engine) -> None:
    eng.paths.ensure()
    eng.ensure_agent_id()
    cfg = eng.config
    cfg["Version"] = __version__
    if cfg.get("FirstRunState") == "PendingConfig":
        cfg["FirstRunState"] = "Enrolled"
    # Default Automatic unless already set
    if not cfg.get("ResponseMode"):
        cfg["ResponseMode"] = "Automatic"
    if cfg.get("ResponseMode") == "Manual":
        cfg["AutoApproveOnTimeout"] = False
        cfg["AutoApproveEnabled"] = False
    eng.config_mgr.save(cfg)
    eng.recovery.init_canaries()
    eng.updates.save_lkg()
    day1 = ROOT / "DAY1_OPS.txt"
    day1.write_text(
        "VectorStryke Day-1 Operations\n"
        "==============================\n"
        "1. python3 vectorstryke.py status\n"
        "2. python3 vectorstryke.py mode automatic   # fully automatic, no approvals\n"
        "3. python3 vectorstryke.py mode manual      # approvals required; timeout never auto-acts\n"
        "4. python3 vectorstryke.py health\n"
        "5. python3 vectorstryke.py start\n",
        encoding="utf-8",
    )
    unit = f"""[Unit]
Description=VectorStryke Anti-Ransomware Engine
After=network.target

[Service]
Type=simple
WorkingDirectory={ROOT}
ExecStart=/usr/bin/python3 {ROOT / 'vectorstryke.py'} start
Restart=on-failure
RestartSec=3
Nice=5

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path("/etc/systemd/system/vectorstryke.service")
    if os.geteuid() == 0:
        unit_path.write_text(unit, encoding="utf-8")
        os.system("systemctl daemon-reload")
        os.system("systemctl enable vectorstryke >/dev/null 2>&1")
        print(f"  [+] systemd unit: {unit_path}")
    else:
        print("  [!] Run with sudo to install systemd unit")
    print(f"  [+] Config: {eng.paths.config_file}")
    print(f"  [+] Day-1: {day1}")
    print("Installation complete.")


def main() -> None:
    args = sys.argv[1:]
    cmd = (args[0] if args else "help").lower()
    eng = engine()

    if cmd == "start":
        eng.run()
    elif cmd == "stop":
        if eng.paths.pid_file.exists():
            try:
                pid = int(eng.paths.pid_file.read_text().strip())
                os.kill(pid, 15)
            except Exception:
                pass
            eng.paths.pid_file.unlink(missing_ok=True)
            print("Stopped.")
        else:
            print("Not running.")
    elif cmd == "status":
        cmd_status(eng)
    elif cmd == "scan":
        eng.reload()
        snap = eng.telemetry.collect()
        findings = eng.detector.detect(snap)
        prelude = eng.recovery.detect_prelude(snap.get("processes") or [])
        if prelude:
            findings = [prelude] + findings
        print(json.dumps(findings, indent=2))
    elif cmd == "approve":
        if len(args) < 2:
            print("Usage: approve <AlertId>")
            sys.exit(1)
        a = eng.approvals.resolve(args[1], "Approved")
        if not a:
            print("Alert not found")
            sys.exit(1)
        eng.responder.respond(a.get("Finding") or {})
        print(f"Approved and executed: {args[1]}")
    elif cmd == "deny":
        if len(args) < 2:
            print("Usage: deny <AlertId>")
            sys.exit(1)
        a = eng.approvals.resolve(args[1], "Denied")
        print("Denied" if a else "Alert not found")
    elif cmd in ("mode", "modes"):
        # Response mode + list all mode settings
        if cmd == "modes" or (len(args) >= 2 and args[1].lower() in ("list", "show", "status", "all")):
            cfg = eng.config
            print("=== VectorStryke modes ===")
            print(f"  ResponseMode              : {cfg.get('ResponseMode') or 'Automatic'}")
            print(f"  OsSecurity.Mode           : {cfg.get('OsSecurityMode') or 'Auto'}")
            print(f"  OsSecurity.DetectionOnly  : {cfg.get('OsSecurityDetectionOnly', True)}")
            print(f"  OsSecurity.FallbackEnabled: {cfg.get('OsSecurityFallbackEnabled', False)}")
            print(f"  OsScan.AutoQuarantine     : {cfg.get('OsScanAutoQuarantine', True)}")
            print(f"  OsScan.AutoDeleteMalicious: {cfg.get('OsScanAutoDeleteMalicious', False)}")
            print("")
            print("Set response:  mode automatic | mode manual")
            print("Set OS-SEC:    ossec-mode auto|coexist|fallback")
            print("Aliases:       auto-on (= automatic)  auto-off (= manual)")
        elif len(args) < 2 or args[1].lower() not in ("automatic", "manual", "auto"):
            print("Usage: mode automatic|manual")
            print("       mode list   (show all modes)")
            print(f"Current ResponseMode: {eng.config.get('ResponseMode')}")
            sys.exit(1)
        else:
            m = "Automatic" if args[1].lower() in ("automatic", "auto") else "Manual"
            eng.config_mgr.set_mode(m)
            print(f"ResponseMode set to {m}")
            if m == "Manual":
                print("  — All actions require explicit approval")
                print("  — Timeout will NOT auto-act (manual only)")
            else:
                print("  — Fully automatic: no explicit approvals")
                print("  — Findings at/above threshold are acted on immediately")
    elif cmd in ("ossec-mode", "ossecmode"):
        # OsSecurity Mode: Auto | Coexist | Fallback
        if len(args) < 2:
            print("Usage: ossec-mode auto|coexist|fallback")
            print(f"Current OsSecurityMode: {eng.config.get('OsSecurityMode') or 'Auto'}")
            print(f"  DetectionOnly={eng.config.get('OsSecurityDetectionOnly', True)}")
            print(f"  FallbackEnabled={eng.config.get('OsSecurityFallbackEnabled', False)}")
            sys.exit(1)
        choice = args[1].lower()
        eng.reload()
        cfg = eng.config
        if choice in ("auto", "automatic"):
            cfg["OsSecurityMode"] = "Auto"
            print("OsSecurityMode=Auto (follow Present/Partial/Absent classification)")
        elif choice in ("coexist", "observe"):
            cfg["OsSecurityMode"] = "Coexist"
            cfg["OsSecurityDetectionOnly"] = True
            cfg["OsSecurityFallbackEnabled"] = False
            print("OsSecurityMode=Coexist (observe/recommend only; fallback off)")
        elif choice in ("fallback", "fb"):
            cfg["OsSecurityMode"] = "Fallback"
            cfg["OsSecurityDetectionOnly"] = False
            cfg["OsSecurityFallbackEnabled"] = True
            print("OsSecurityMode=Fallback (eligible when Class=Absent; apply gated)")
            print("  Note: Fallback apply controls require Class=Absent on each cycle")
        else:
            print("Usage: ossec-mode auto|coexist|fallback")
            sys.exit(1)
        eng.config_mgr.save(cfg)
        eng.reload()
    elif cmd in ("osscan", "os-scan"):
        from vs_core.os_scan import OsScanEngine
        eng.reload()
        full = "full" in args[1:]
        baseline = "baseline" in args[1:]
        scan = OsScanEngine(eng.paths, eng.config, eng.log)
        if baseline:
            print(json.dumps(scan.build_baseline(), indent=2))
        else:
            print(json.dumps(scan.scan(full=full), indent=2))
    elif cmd in ("ossec-status", "ossec"):
        from vs_core.os_security import OsSecurityAdapter
        eng.reload()
        r = OsSecurityAdapter(eng.paths, eng.config, eng.log).detect_and_classify()
        print(json.dumps(r, indent=2))
    elif cmd == "health":
        print(json.dumps(eng.health.run(), indent=2))
    elif cmd == "canary-init":
        print(json.dumps(eng.recovery.init_canaries(), indent=2))
    elif cmd == "canary-verify":
        print(json.dumps(eng.recovery.verify_canaries(), indent=2))
    elif cmd == "checkpoint":
        print(json.dumps(eng.recovery.create_checkpoint("manual-cli"), indent=2))
    elif cmd == "impact-clear":
        force = "force" in args[1:]
        r = eng.recovery.clear_impact_pending(force=force)
        eng.config["ImpactPending"] = False if r.get("ok") else eng.config.get("ImpactPending")
        if r.get("ok"):
            eng.config_mgr.save(eng.config)
        print(json.dumps(r, indent=2))
    elif cmd == "update-check":
        print(json.dumps(eng.updates.check(), indent=2))
    elif cmd == "update-apply":
        force = "force" in args[1:]
        r = eng.updates.apply(force=force)
        if r.get("ok"):
            eng.config_mgr.save(eng.config)
        print(json.dumps(r, indent=2))
    elif cmd == "rollback":
        print(json.dumps(eng.updates.rollback(), indent=2))
    elif cmd == "lkg-save":
        print(json.dumps({"ok": True, "path": eng.updates.save_lkg()}, indent=2))
    elif cmd == "install":
        cmd_install(eng)
    elif cmd in ("auto-on", "auto-off"):
        # Map legacy commands to ResponseMode
        if cmd == "auto-on":
            eng.config_mgr.set_mode("Automatic")
            print("ResponseMode=Automatic (fully automatic, no approvals)")
        else:
            eng.config_mgr.set_mode("Manual")
            print("ResponseMode=Manual (approvals required; timeout never auto-acts)")
    else:
        print(f"""
VectorStryke v{__version__} — Modular Anti-Ransomware Engine (Linux)
Copyright © VectorStryke

Usage: python3 vectorstryke.py <command>

Core:
  start | stop | status | scan | install
  approve <id> | deny <id>

Modes:
  mode automatic|manual     ResponseMode (act vs approve)
  mode list | modes         Show all mode settings
  auto-on / auto-off        Aliases for mode automatic / manual
  ossec-mode auto|coexist|fallback   OS-SEC behavior mode
  ossec-status              Detect Present|Partial|Absent

Maturity:
  health | ossec-status | osscan [full|baseline] | canary-init | canary-verify | checkpoint | impact-clear
  update-check | update-apply | lkg-save | rollback

Architecture: vs_core/ (OOP — Sensor, Detector, Responder, PolicyEngine, Engine)
""")


if __name__ == "__main__":
    main()
