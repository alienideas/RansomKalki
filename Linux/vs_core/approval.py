"""Approval workflow — Manual mode only uses pending queue."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .base import Component


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApprovalManager(Component):
    def _alert_path(self, alert_id: str) -> Path:
        return self._paths.alert_dir / f"{alert_id}.json"

    def submit(self, finding: dict, timeout_sec: int) -> str:
        alert_id = os.urandom(6).hex()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=timeout_sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
        package = {
            "AlertId": alert_id,
            "Finding": finding,
            "Status": "Pending",
            "SubmittedAt": _utc(),
            "ExpiresAt": expires,
            "TimeoutSec": timeout_sec,
        }
        self._paths.alert_dir.mkdir(parents=True, exist_ok=True)
        self._alert_path(alert_id).write_text(json.dumps(package, indent=2), encoding="utf-8")
        self.log_warn(f"Pending approval {alert_id} for {finding.get('name')} score={finding.get('score')}")
        return alert_id

    def get_pending(self) -> list[dict]:
        out = []
        for f in self._paths.alert_dir.glob("*.json"):
            try:
                a = json.loads(f.read_text(encoding="utf-8"))
                if a.get("Status") == "Pending":
                    out.append(a)
            except Exception:
                continue
        return out

    def resolve(self, alert_id: str, decision: str) -> dict | None:
        path = self._alert_path(alert_id)
        if not path.exists():
            # search
            for f in self._paths.alert_dir.glob("*.json"):
                try:
                    a = json.loads(f.read_text(encoding="utf-8"))
                    if a.get("AlertId") == alert_id:
                        path = f
                        break
                except Exception:
                    continue
        if not path.exists():
            return None
        try:
            a = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        a["Status"] = decision
        a["ResolvedAt"] = _utc()
        path.write_text(json.dumps(a, indent=2), encoding="utf-8")
        return a

    def process_timeouts_manual_only(self) -> list[str]:
        """
        Manual mode: on timeout, expire only — never auto-act.
        Automatic mode: no pending items expected; still expire any stragglers without acting.
        """
        expired = []
        now = datetime.now(timezone.utc)
        for p in self.get_pending():
            try:
                exp = datetime.fromisoformat(p["ExpiresAt"].replace("Z", "+00:00"))
            except Exception:
                continue
            if now > exp:
                aid = p.get("AlertId")
                self.resolve(aid, "Timeout-Expired-ManualOnly")
                self.log_warn(f"Timeout expired (manual-only, no auto-action) for {aid}")
                expired.append(aid)
        return expired
