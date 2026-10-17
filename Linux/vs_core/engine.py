"""Main engine orchestrator — composes sensors, detectors, policy, responders."""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .paths import Paths
from .config import ConfigManager
from .policy import ResponsePolicy
from .telemetry import CompositeTelemetry
from .detect import CompositeDetector
from .actions import KillQuarantineResponder, SoftContainResponder
from .approval import ApprovalManager
from .recovery import RecoveryEngine
from .health import HealthChecker
from .update import UpdateManager
from .console_client import ConsoleClient


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engine:
    """
    Encapsulated anti-ransomware engine.
    Designed so additional EDR modules (AV scanner, identity sensor, backup orchestrator)
    plug in via Sensor/Detector/Responder subclasses without rewriting the loop.
    """

    def __init__(self, root: Path | None = None):
        self.paths = Paths(root)
        self.paths.ensure()
        self._setup_logging()
        self.config_mgr = ConfigManager(self.paths.config_file)
        self.config = self.config_mgr.load()
        self._wire_components()

    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[
                logging.FileHandler(self.paths.log_file),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.log = logging.getLogger("vectorstryke")

    def _wire_components(self) -> None:
        c, p, log = self.config, self.paths, self.log
        self.policy = ResponsePolicy(p, c, log)
        self.telemetry = CompositeTelemetry(p, c, log)
        self.detector = CompositeDetector(p, c, log)
        self.responder = KillQuarantineResponder(p, c, log)
        self.soft_contain = SoftContainResponder(p, c, log)
        self.approvals = ApprovalManager(p, c, log)
        self.recovery = RecoveryEngine(p, c, log)
        self.health = HealthChecker(p, c, log)
        self.updates = UpdateManager(p, c, log)
        self.console = ConsoleClient(p, c, log)

    def reload(self) -> None:
        self.config = self.config_mgr.load()
        for comp in (
            self.policy, self.telemetry, self.detector, self.responder,
            self.soft_contain, self.approvals, self.recovery, self.health,
            self.updates, self.console,
        ):
            comp.reload_config(self.config)

    def ensure_agent_id(self) -> None:
        if self.config.get("AgentId"):
            return
        mid = Path("/etc/machine-id")
        raw = mid.read_text().strip() if mid.exists() else os.urandom(8).hex()
        import hashlib
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        self.config["AgentId"] = f"lin-{h}"
        self.config_mgr.save(self.config)

    def advance_first_run(self) -> None:
        state = self.config.get("FirstRunState") or "PendingConfig"
        if state == "PendingConfig" and self.config.get("AgentId"):
            self.config["FirstRunState"] = "Enrolled"
            self.config_mgr.save(self.config)
            state = "Enrolled"
        if state == "Enrolled":
            h = self.health.run()
            if h.get("Ok") and self.paths.status_file.exists():
                self.config["FirstRunState"] = "Steady"
                self.config_mgr.save(self.config)

    def is_running(self) -> bool:
        if not self.paths.pid_file.exists():
            return False
        try:
            pid = int(self.paths.pid_file.read_text().strip())
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def save_status(self, status: dict) -> None:
        self.paths.status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")

    def handle_finding(self, finding: dict) -> None:
        """Core decision: Automatic → act; Manual → pending approval only."""
        score = int(finding.get("score") or 0)
        if score < 60:
            return
        self.policy.reload_config(self.config)
        if self.policy.should_act_immediately(finding):
            self.log.warning(
                f"AUTOMATIC action (mode={self.policy.mode()}) score={score}: {finding.get('name')}"
            )
            self.responder.respond(finding)
            return
        if self.policy.requires_human_approval(finding):
            is_impact = bool(finding.get("impact_class"))
            timeout = (
                int(self.config.get("ApprovalTimeoutImpact") or 600)
                if is_impact or finding.get("severity") == "High"
                else int(self.config.get("ApprovalTimeoutNormal") or 3600)
            )
            self.approvals.submit(finding, timeout)

    def run(self) -> None:
        if self.is_running():
            print("VectorStryke is already running.")
            return
        self.paths.pid_file.write_text(str(os.getpid()))
        self.ensure_agent_id()
        self.log.info(f"VectorStryke engine started (PID {os.getpid()}) mode={self.config.get('ResponseMode')}")
        if self.config.get("ConsoleEnabled"):
            self.config = self.console.enroll()
            self.config_mgr.save(self.config)

        def _stop(signum, frame):
            self.log.info("Shutdown signal received")
            if self.paths.pid_file.exists():
                self.paths.pid_file.unlink()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        alert_mode = False

        while True:
            try:
                self.reload()
                self.advance_first_run()
                health = self.health.run()
                if not health.get("Ok"):
                    self.log.warning(f"Self-health issues: {health.get('Issues')}")

                # Manual-only timeout handling (never auto-act)
                self.approvals.process_timeouts_manual_only()

                snap = self.telemetry.collect()
                findings = self.detector.detect(snap)

                prelude = self.recovery.detect_prelude(snap.get("processes") or [])
                if prelude:
                    findings = [prelude] + findings
                    if not self.config.get("ImpactPending"):
                        meta = self.recovery.enter_impact_pending(prelude)
                        self.config["ImpactPending"] = True
                        self.config["LastCheckpointId"] = meta.get("CheckpointId") or ""
                        self.config_mgr.save(self.config)
                        self.soft_contain.respond(prelude)
                        # In Automatic mode, also act on prelude immediately
                        if self.policy.is_automatic():
                            self.responder.respond(prelude)

                agent_on = self.config.get("AgentEnabled", True)
                if findings and agent_on:
                    alert_mode = True
                    for f in findings:
                        self.handle_finding(f)
                else:
                    alert_mode = len(self.approvals.get_pending()) > 0

                status = {
                    "Engine": "Running",
                    "Pid": os.getpid(),
                    "LastCycle": _utc(),
                    "MemoryUsedPct": snap.get("memory_used_pct"),
                    "FindingsCount": len(findings),
                    "PendingAlerts": len(self.approvals.get_pending()),
                    "Mode": "Alert" if alert_mode else "Idle",
                    "ResponseMode": self.config.get("ResponseMode") or "Automatic",
                    "Version": self.config.get("Version") or "1.7.0",
                    "Platform": "Linux",
                    "Profile": self.config.get("Profile") or "Server",
                    "FirstRunState": self.config.get("FirstRunState") or "PendingConfig",
                    "HealthOk": health.get("Ok", True),
                    "ImpactPending": bool(self.config.get("ImpactPending")),
                    "LastCheckpointId": self.config.get("LastCheckpointId") or "",
                    "AgentId": self.config.get("AgentId") or "",
                    "TenantId": self.config.get("TenantId") or "default",
                }
                self.save_status(status)
                cmds = self.console.heartbeat(status)
                # remote commands could be processed here (policy/approve)

                sleep = (
                    int(self.config.get("PollIntervalAlertSec") or 15)
                    if alert_mode
                    else int(self.config.get("PollIntervalIdleSec") or 60)
                )
                time.sleep(sleep)
            except Exception as e:
                self.log.error(f"Cycle error: {e}")
                time.sleep(30)
