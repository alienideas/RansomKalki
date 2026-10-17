"""Self-health checks — packaging maturity PKG-1."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .base import Component
from .os_security import OsSecurityAdapter


class HealthChecker(Component):
    def run(self) -> dict:
        issues = []
        ok = True
        for label, p in (
            ("ROOT", self._paths.root),
            ("config", self._paths.config_dir),
            ("data", self._paths.data),
            ("logs", self._paths.logs),
            ("quarantine", self._paths.quarantine),
            ("canaries", self._paths.canary_dir),
            ("checkpoints", self._paths.checkpoint_dir),
            ("lkg", self._paths.lkg_dir),
        ):
            if not p.exists():
                issues.append(f"missing_path:{label}")
                ok = False
        if not self._paths.config_file.exists():
            issues.append("missing_config")
            ok = False
        for k in ("Profile", "FirstRunState", "ResponseMode", "RecoveryEnabled"):
            if k not in self._config:
                issues.append(f"schema_missing:{k}")
                ok = False
        if self._config.get("ConsoleEnabled") and not (self._config.get("ConsoleUrl") or "").strip():
            issues.append("console_enabled_without_url")
            ok = False
        ossec = {}
        try:
            ossec = OsSecurityAdapter(self._paths, self._config, self._log).detect_and_classify()
        except Exception as e:
            ossec = {"Class": "Unknown", "Errors": [str(e)], "FallbackEligible": False, "FallbackActive": False}
        result = {
            "Ok": ok,
            "Version": self._config.get("Version") or "1.7.0",
            "Profile": self._config.get("Profile") or "Server",
            "FirstRunState": self._config.get("FirstRunState") or "PendingConfig",
            "ResponseMode": self._config.get("ResponseMode") or "Automatic",
            "Issues": issues,
            "OsSecurity": ossec,
            "CheckedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self._paths.health_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
