"""Configuration manager — single source of policy truth."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "Version": "1.7.0",
    "Profile": "Server",  # Desktop | Server | DC
    "FirstRunState": "PendingConfig",  # PendingConfig | Enrolled | Steady
    # ResponseMode:
    #   Automatic — fully automatic, no explicit approvals (act on findings)
    #   Manual    — human approval required; timeout never auto-acts
    "ResponseMode": "Automatic",
    "PollIntervalIdleSec": 60,
    "PollIntervalAlertSec": 15,
    "ApprovalTimeoutImpact": 600,
    "ApprovalTimeoutNormal": 3600,
    "HighMemoryMB": 700,
    "HighThreadCount": 90,
    "AdminEmail": "admin@company.com",
    "EnableEmail": False,
    # Legacy flags — only used when ResponseMode == Manual for scoring thresholds
    "AutoApproveEnabled": False,
    "AutoApproveScoreThreshold": 80,
    "AutoApproveOnTimeout": False,  # Manual-only: never auto on timeout
    "RequireApprovalForImpact": True,
    "AutoApproveRemovals": False,
    "AutoApproveEncryptionStop": False,
    "ConsoleEnabled": False,
    "ConsoleUrl": "",
    "TenantId": "default",
    "AgentId": "",
    "EnrollmentToken": "",
    "HostnameOverride": "",
    "AgentEnabled": True,
    "AllowlistProcesses": [],
    "AllowlistPaths": [],
    "UpdateChannel": "stable",
    "UpdateAutoApply": False,
    "UpdateCheckUrl": "",
    "UpdateDeferDays": 0,
    "UpdateRing": "Ring2",
    "RecoveryEnabled": True,
    "CanaryEnabled": True,
    "CanaryPaths": [],
    "CheckpointWebhook": "",
    "SoftContainmentEnabled": True,
    "ImpactPending": False,
    "LastCheckpointId": "",
}


class ConfigManager:
    """Load/save/merge engine config with encapsulation."""

    def __init__(self, config_file: Path):
        self._path = config_file
        self._data: dict[str, Any] = deepcopy(DEFAULTS)

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def load(self) -> dict[str, Any]:
        cfg = deepcopy(DEFAULTS)
        if self._path.exists():
            try:
                user = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(user, dict):
                    cfg.update(user)
            except Exception:
                pass
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(DEFAULTS, indent=2), encoding="utf-8")
        # Enforce Manual-mode timeout rule
        mode = (cfg.get("ResponseMode") or "Automatic").strip().title()
        if mode not in ("Automatic", "Manual"):
            mode = "Automatic"
        cfg["ResponseMode"] = mode
        if mode == "Manual":
            cfg["AutoApproveOnTimeout"] = False
            cfg["AutoApproveEnabled"] = False
        self._data = cfg
        return cfg

    def save(self, cfg: dict[str, Any] | None = None) -> None:
        data = cfg if cfg is not None else self._data
        mode = (data.get("ResponseMode") or "Automatic").strip().title()
        data["ResponseMode"] = mode
        if mode == "Manual":
            data["AutoApproveOnTimeout"] = False
            data["AutoApproveEnabled"] = False
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._data = data

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set_mode(self, mode: str) -> dict[str, Any]:
        mode = mode.strip().title()
        if mode not in ("Automatic", "Manual"):
            raise ValueError("ResponseMode must be Automatic or Manual")
        self._data["ResponseMode"] = mode
        if mode == "Manual":
            self._data["AutoApproveOnTimeout"] = False
            self._data["AutoApproveEnabled"] = False
        self.save()
        return self._data

    def is_automatic(self) -> bool:
        return (self._data.get("ResponseMode") or "Automatic").title() == "Automatic"

    def is_manual(self) -> bool:
        return not self.is_automatic()
