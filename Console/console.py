#!/usr/bin/env python3
"""
VectorStryke Central Multi-Tenant Console
========================================
Dependency-free (Python 3 standard library only).

Run:
  python3 console.py [--host 0.0.0.0] [--port 9000]

Agents enroll and heartbeat here. Operators monitor all hosts and
Approve/Deny alerts remotely. Tenant isolation via tenant_id.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)

# Optional shared enrollment token (empty = open enroll for lab use)
ENROLLMENT_TOKEN = os.environ.get("VECTORSTRYKE_ENROLL_TOKEN", "")


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tenant_dir(tenant_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (tenant_id or "default"))
    p = DATA / safe
    (p / "agents").mkdir(parents=True, exist_ok=True)
    (p / "alerts").mkdir(parents=True, exist_ok=True)
    (p / "commands").mkdir(parents=True, exist_ok=True)
    return p


def read_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default if default is not None else {}


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def list_tenants():
    return sorted([p.name for p in DATA.iterdir() if p.is_dir()])


def list_agents(tenant_id: str):
    t = tenant_dir(tenant_id)
    agents = []
    for f in (t / "agents").glob("*.json"):
        a = read_json(f, {})
        if a:
            agents.append(a)
    agents.sort(key=lambda x: x.get("LastSeen", ""), reverse=True)
    return agents


def list_alerts(tenant_id: str, pending_only=True):
    t = tenant_dir(tenant_id)
    alerts = []
    for f in (t / "alerts").glob("*.json"):
        a = read_json(f, {})
        if not a:
            continue
        if pending_only and a.get("Status") not in (None, "Pending"):
            continue
        alerts.append(a)
    alerts.sort(key=lambda x: x.get("CreatedAt", ""), reverse=True)
    return alerts


def queue_command(tenant_id: str, agent_id: str, command: dict):
    t = tenant_dir(tenant_id)
    cmd_id = command.get("CommandId") or uuid.uuid4().hex[:12]
    command["CommandId"] = cmd_id
    command["QueuedAt"] = utcnow()
    write_json(t / "commands" / f"{agent_id}_{cmd_id}.json", command)
    return command


def pop_commands(tenant_id: str, agent_id: str):
    t = tenant_dir(tenant_id)
    out = []
    for f in sorted((t / "commands").glob(f"{agent_id}_*.json")):
        c = read_json(f, {})
        if c:
            out.append(c)
        try:
            f.unlink()
        except Exception:
            pass
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "VectorStrykeConsole/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, code, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Enrollment-Token")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8") if n else "{}"
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            html = ROOT / "console_dashboard.html"
            if html.exists():
                self._send(200, html.read_text(encoding="utf-8"), "text/html; charset=utf-8")
            else:
                self._send(200, "<h1>VectorStryke Console</h1><p>console_dashboard.html missing</p>", "text/html")
            return

        if path == "/api/health":
            self._send(200, {"ok": True, "service": "VectorStryke Console", "time": utcnow()})
            return

        if path == "/api/tenants":
            self._send(200, {"tenants": list_tenants()})
            return

        if path.startswith("/api/tenants/") and path.endswith("/agents"):
            tenant = path.split("/")[3]
            self._send(200, {"tenant": tenant, "agents": list_agents(tenant)})
            return

        if path.startswith("/api/tenants/") and path.endswith("/alerts"):
            tenant = path.split("/")[3]
            pending = (qs.get("pending") or ["1"])[0] != "0"
            self._send(200, {"tenant": tenant, "alerts": list_alerts(tenant, pending_only=pending)})
            return

        if path.startswith("/api/tenants/") and "/overview" in path:
            tenant = path.split("/")[3]
            agents = list_agents(tenant)
            alerts = list_alerts(tenant, pending_only=True)
            online = sum(1 for a in agents if a.get("Online"))
            self._send(200, {
                "tenant": tenant,
                "agentCount": len(agents),
                "onlineCount": online,
                "pendingAlerts": len(alerts),
                "agents": agents,
                "alerts": alerts[:50],
            })
            return

        # Agent polls pending commands
        if path == "/api/agent/commands":
            tenant = (qs.get("tenant") or ["default"])[0]
            agent_id = (qs.get("agent") or [""])[0]
            if not agent_id:
                self._send(400, {"error": "agent required"})
                return
            cmds = pop_commands(tenant, agent_id)
            self._send(200, {"commands": cmds})
            return

        self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json()

        if path == "/api/enroll":
            if ENROLLMENT_TOKEN:
                tok = self.headers.get("X-Enrollment-Token") or body.get("token") or ""
                if tok != ENROLLMENT_TOKEN:
                    self._send(403, {"error": "invalid enrollment token"})
                    return
            tenant = body.get("TenantId") or body.get("tenant") or "default"
            agent_id = body.get("AgentId") or body.get("agentId") or uuid.uuid4().hex[:16]
            hostname = body.get("Hostname") or body.get("hostname") or "unknown"
            platform = body.get("Platform") or "unknown"
            version = body.get("Version") or ""
            rec = {
                "AgentId": agent_id,
                "TenantId": tenant,
                "Hostname": hostname,
                "Platform": platform,
                "Version": version,
                "EnrolledAt": utcnow(),
                "LastSeen": utcnow(),
                "Online": True,
                "Status": {},
            }
            write_json(tenant_dir(tenant) / "agents" / f"{agent_id}.json", rec)
            self._send(200, {"ok": True, "AgentId": agent_id, "TenantId": tenant})
            return

        if path == "/api/heartbeat":
            tenant = body.get("TenantId") or "default"
            agent_id = body.get("AgentId") or ""
            if not agent_id:
                self._send(400, {"error": "AgentId required"})
                return
            path_a = tenant_dir(tenant) / "agents" / f"{agent_id}.json"
            rec = read_json(path_a, {
                "AgentId": agent_id,
                "TenantId": tenant,
                "EnrolledAt": utcnow(),
            })
            rec["LastSeen"] = utcnow()
            rec["Online"] = True
            rec["Hostname"] = body.get("Hostname") or rec.get("Hostname") or "unknown"
            rec["Platform"] = body.get("Platform") or rec.get("Platform") or "unknown"
            rec["Version"] = body.get("Version") or rec.get("Version") or ""
            rec["Status"] = body.get("Status") or {}
            write_json(path_a, rec)
            # Mark stale agents offline (best-effort)
            for f in (tenant_dir(tenant) / "agents").glob("*.json"):
                a = read_json(f, {})
                ls = a.get("LastSeen") or ""
                # simple: leave Online flag as last write; UI can compute age
                if a.get("AgentId") != agent_id and ls:
                    pass
            cmds = pop_commands(tenant, agent_id)
            self._send(200, {"ok": True, "commands": cmds})
            return

        if path == "/api/alert":
            tenant = body.get("TenantId") or "default"
            agent_id = body.get("AgentId") or ""
            alert_id = body.get("AlertId") or uuid.uuid4().hex[:12]
            alert = {
                "AlertId": alert_id,
                "AgentId": agent_id,
                "TenantId": tenant,
                "Hostname": body.get("Hostname") or "",
                "Platform": body.get("Platform") or "",
                "Finding": body.get("Finding") or {},
                "Status": "Pending",
                "CreatedAt": body.get("CreatedAt") or utcnow(),
                "ExpiresAt": body.get("ExpiresAt") or "",
            }
            write_json(tenant_dir(tenant) / "alerts" / f"{alert_id}.json", alert)
            self._send(200, {"ok": True, "AlertId": alert_id})
            return

        # Remote approve / deny → queue command to agent
        if path.startswith("/api/tenants/") and ("/approve" in path or "/deny" in path):
            parts = path.strip("/").split("/")
            # /api/tenants/{tenant}/alerts/{id}/approve
            try:
                tenant = parts[2]
                alert_id = parts[4]
                decision = "Approved" if parts[-1] == "approve" else "Denied"
            except Exception:
                self._send(400, {"error": "bad path"})
                return
            ap = tenant_dir(tenant) / "alerts" / f"{alert_id}.json"
            alert = read_json(ap, {})
            if not alert:
                self._send(404, {"error": "alert not found"})
                return
            alert["Status"] = decision
            alert["ResolvedAt"] = utcnow()
            alert["ResolvedBy"] = "console"
            write_json(ap, alert)
            agent_id = alert.get("AgentId") or ""
            if agent_id:
                queue_command(tenant, agent_id, {
                    "Type": "ResolveAlert",
                    "AlertId": alert_id,
                    "Decision": decision,
                    "Finding": alert.get("Finding") or {},
                })
            self._send(200, {"ok": True, "AlertId": alert_id, "Decision": decision})
            return

        if path.startswith("/api/tenants/") and path.endswith("/policy"):
            parts = path.strip("/").split("/")
            tenant = parts[2]
            agent_id = body.get("AgentId")
            policy = body.get("Policy") or body
            targets = [agent_id] if agent_id else [a.get("AgentId") for a in list_agents(tenant) if a.get("AgentId")]
            policy_keys = (
                "AutoApproveEnabled", "AutoApproveRemovals",
                "AutoApproveEncryptionStop", "RequireApprovalForImpact",
                "AutoApproveOnTimeout", "AutoApproveScoreThreshold",
                "AgentEnabled", "AllowlistProcesses", "AllowlistPaths",
            )
            for aid in targets:
                queue_command(tenant, aid, {
                    "Type": "ApplyPolicy",
                    "Policy": {k: policy[k] for k in policy_keys if k in policy},
                })
            self._send(200, {"ok": True, "targets": targets})
            return

        # /api/tenants/{tenant}/agents/{agent}/enable
        if "/agents/" in path and path.endswith("/enable"):
            parts = path.strip("/").split("/")
            try:
                tenant = parts[2]
                agent_id = parts[4]
            except Exception:
                self._send(400, {"error": "bad path"})
                return
            enabled = bool(body.get("Enabled", True))
            queue_command(tenant, agent_id, {"Type": "SetEnabled", "Enabled": enabled})
            ap = tenant_dir(tenant) / "agents" / f"{agent_id}.json"
            rec = read_json(ap, {})
            if rec:
                st = rec.get("Status") or {}
                cfg = st.get("Config") or {}
                cfg["AgentEnabled"] = enabled
                st["Config"] = cfg
                rec["Status"] = st
                write_json(ap, rec)
            self._send(200, {"ok": True, "AgentId": agent_id, "Enabled": enabled})
            return

        # /api/tenants/{tenant}/agents/{agent}/exceptions
        if "/agents/" in path and path.endswith("/exceptions"):
            parts = path.strip("/").split("/")
            try:
                tenant = parts[2]
                agent_id = parts[4]
            except Exception:
                self._send(400, {"error": "bad path"})
                return
            queue_command(tenant, agent_id, {
                "Type": "SetExceptions",
                "AllowlistProcesses": body.get("AllowlistProcesses") or [],
                "AllowlistPaths": body.get("AllowlistPaths") or [],
            })
            self._send(200, {"ok": True, "AgentId": agent_id})
            return

        self._send(404, {"error": "not found"})


def mark_stale_loop(interval=30, stale_sec=120):
    while True:
        try:
            now = time.time()
            for tenant in list_tenants():
                for f in (tenant_dir(tenant) / "agents").glob("*.json"):
                    a = read_json(f, {})
                    ls = a.get("LastSeen") or ""
                    online = False
                    try:
                        # parse Z
                        ts = datetime.strptime(ls.replace("Z", ""), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                        online = (now - ts.timestamp()) <= stale_sec
                    except Exception:
                        online = False
                    if a.get("Online") != online:
                        a["Online"] = online
                        write_json(f, a)
        except Exception:
            pass
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="VectorStryke Central Multi-Tenant Console")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    t = threading.Thread(target=mark_stale_loop, daemon=True)
    t.start()

    httpd = HTTPServer((args.host, args.port), Handler)
    print(f"VectorStryke Central Console listening on http://{args.host}:{args.port}/")
    print(f"Data directory: {DATA}")
    if ENROLLMENT_TOKEN:
        print("Enrollment token: required (VECTORSTRYKE_ENROLL_TOKEN)")
    else:
        print("Enrollment token: not set (open enrollment — lab mode)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()
