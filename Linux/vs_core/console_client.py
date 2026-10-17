"""Optional central console client — fails soft when offline."""
from __future__ import annotations

import json
import urllib.request
from typing import Any

from .base import Component


class ConsoleClient(Component):
    def _base(self) -> str:
        return (self._config.get("ConsoleUrl") or "").rstrip("/")

    def _http(self, method: str, url: str, payload: dict | None = None, timeout: int = 5) -> Any:
        data = None
        headers = {"Content-Type": "application/json", "User-Agent": "VectorStryke-Agent/1.7"}
        token = self._config.get("EnrollmentToken") or ""
        if token:
            headers["X-Enrollment-Token"] = token
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}

    def enroll(self) -> dict:
        if not self._config.get("ConsoleEnabled") or not self._base():
            return self._config
        try:
            import socket
            host = self._config.get("HostnameOverride") or socket.gethostname()
            r = self._http("POST", f"{self._base()}/api/enroll", {
                "TenantId": self._config.get("TenantId") or "default",
                "AgentId": self._config.get("AgentId") or "",
                "Hostname": host,
                "Platform": "Linux",
                "Version": self._config.get("Version") or "1.7.0",
            })
            if r.get("AgentId") and not self._config.get("AgentId"):
                self._config["AgentId"] = r["AgentId"]
        except Exception as e:
            self.log_warn(f"Console enroll failed: {e}")
        return self._config

    def heartbeat(self, status: dict) -> list:
        if not self._config.get("ConsoleEnabled") or not self._base():
            return []
        try:
            import socket
            host = self._config.get("HostnameOverride") or socket.gethostname()
            r = self._http("POST", f"{self._base()}/api/heartbeat", {
                "TenantId": self._config.get("TenantId") or "default",
                "AgentId": self._config.get("AgentId") or "",
                "Hostname": host,
                "Platform": "Linux",
                "Version": self._config.get("Version") or "1.7.0",
                "Status": status,
            })
            return r.get("commands") or []
        except Exception:
            return []
