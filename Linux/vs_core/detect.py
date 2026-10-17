"""Detection engines — ransomware and extensible detectors."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import Detector


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThreatIntel:
    def __init__(self, intel_file: Path):
        self.process_names = ["xmrig", "minerd", "encrypt", "ransom", "mimikatz", "cobalt"]
        self.path_patterns = ["/tmp/", "/dev/shm/"]
        if intel_file.exists():
            try:
                for line in intel_file.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self.process_names.append(line.lower())
            except Exception:
                pass


class RansomwareDetector(Detector):
    """Heuristic ransomware / abuse detector — replaceable by ML detector subclass later."""

    CRITICAL = {"systemd", "kthreadd", "ksoftirqd", "migration", "rcu_", "init", "bash", "sshd", "python3", "vectorstryke"}

    def __init__(self, paths, config, log=None, intel: ThreatIntel | None = None):
        super().__init__(paths, config, log)
        self._intel = intel or ThreatIntel(paths.intel_file)

    def detect(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        fid = 0
        high_mem = int(self._config.get("HighMemoryMB") or 700)
        high_thr = int(self._config.get("HighThreadCount") or 90)
        for p in snapshot.get("processes") or []:
            if any((p.get("name") or "").startswith(c) for c in self.CRITICAL):
                continue
            score = 0
            reasons = []
            name = (p.get("name") or "").lower()
            exe = (p.get("exe") or "").lower()
            for bad in self._intel.process_names:
                if bad.lower() in name:
                    score += 40
                    reasons.append(f"Name matches threat intel: {bad}")
                    break
            for pat in self._intel.path_patterns:
                if pat.replace("*", "") in exe:
                    score += 25
                    reasons.append("Suspicious path")
                    break
            if float(p.get("memory_mb") or 0) > high_mem:
                score += 15
                reasons.append(f"High memory ({p.get('memory_mb')} MB)")
            if int(p.get("threads") or 0) > high_thr:
                score += 15
                reasons.append(f"High threads ({p.get('threads')})")
            if score >= 40:
                fid += 1
                findings.append({
                    "id": fid,
                    "type": "Process",
                    "name": p.get("name"),
                    "pid": p.get("pid"),
                    "exe": p.get("exe"),
                    "memory_mb": p.get("memory_mb"),
                    "score": score,
                    "reasons": " | ".join(reasons),
                    "severity": "High" if score >= 70 else "Medium",
                    "timestamp": _utc(),
                })
        if float(snapshot.get("memory_used_pct") or 0) >= 90:
            fid += 1
            findings.append({
                "id": fid, "type": "System", "name": "HighMemoryPressure",
                "pid": 0, "exe": "", "memory_mb": 0, "score": 50,
                "reasons": f"Memory {snapshot.get('memory_used_pct')}%",
                "severity": "High", "timestamp": _utc(),
            })
        return findings


class CompositeDetector(Detector):
    """Runs multiple detectors — add AV/malware/identity detectors here for XDR growth."""

    def __init__(self, paths, config, log=None, detectors: list[Detector] | None = None):
        super().__init__(paths, config, log)
        self._detectors = detectors or [RansomwareDetector(paths, config, log)]

    def detect(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for d in self._detectors:
            try:
                out.extend(d.detect(snapshot))
            except Exception as e:
                self.log_error(f"Detector {type(d).__name__} failed: {e}")
        return out
