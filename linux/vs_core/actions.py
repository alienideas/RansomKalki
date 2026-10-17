"""Response actions — kill, quarantine; extensible to isolate/backup freeze."""
from __future__ import annotations

import os
import signal
import time
from datetime import datetime
from pathlib import Path

from .base import Responder


class KillQuarantineResponder(Responder):
    def respond(self, finding: dict) -> bool:
        if not self._config.get("AgentEnabled", True):
            self.log_info("Agent disabled — skip action")
            return False
        name = (finding.get("name") or "").lower()
        exe = (finding.get("exe") or "").lower()
        for n in (self._config.get("AllowlistProcesses") or []):
            if n and n.lower() in name:
                self.log_info(f"Allowlisted process: {name}")
                return False
        for p in (self._config.get("AllowlistPaths") or []):
            if p and p.lower() in exe:
                self.log_info(f"Allowlisted path: {exe}")
                return False
        try:
            pid = int(finding.get("pid") or 0)
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.3)
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.log_warn(f"Killed PID {pid} ({finding.get('name')})")
            exe_path = finding.get("exe") or ""
            if exe_path and os.path.isfile(exe_path) and not exe_path.startswith(
                ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib")
            ):
                dest = self._paths.quarantine / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{Path(exe_path).name}"
                try:
                    os.rename(exe_path, dest)
                    self.log_warn(f"Quarantined {exe_path} → {dest}")
                except Exception as e:
                    self.log_error(f"Quarantine failed: {e}")
            return True
        except Exception as e:
            self.log_error(f"Action failed: {e}")
            return False


class SoftContainResponder(Responder):
    def respond(self, finding: dict) -> bool:
        if not self._config.get("SoftContainmentEnabled", True):
            return False
        pid = int(finding.get("pid") or 0)
        if pid <= 1:
            return False
        try:
            os.kill(pid, signal.SIGSTOP)
            self.log_warn(f"Soft-containment SIGSTOP pid={pid}")
            return True
        except Exception as e:
            self.log_error(f"Soft-containment failed: {e}")
            return False
