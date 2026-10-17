"""OS security detect-first adapter — Present/Partial/Absent classification.
Fallback apply is gated; defaults never auto-enforce.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from .base import Component

# Built-in process name hints (lowercase)
_DEFAULT_AGENTS = [
    "msmpeng", "mssense", "defender", "windefend",
    "csfalconservice", "falcon-sensor", "sentinelagent", "s1agent",
    "xagt", "trellix", "mfeesp", "mcshield", "savservice",
    "clamd", "clamav", "freshclam", "sophos", "bdagent",
    "carbonblack", "cbosx", "elastic-agent", "osqueryd",
]


def _run(cmd: list[str], timeout: float = 2.0) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


class OsSecurityAdapter(Component):
    """Detect existing OS/vendor security; classify; optional fallback gate."""

    def detect(self) -> dict[str, Any]:
        signals: dict[str, Any] = {
            "DefenderPresent": False,
            "RealTimeOn": None,
            "CFA": None,
            "Firewall": None,
            "Agents": [],
            "Platform": "Linux",
            "Errors": [],
        }
        try:
            agents = self._detect_agents()
            signals["Agents"] = agents
            # Soft firewall signals
            fw = self._detect_firewall()
            signals["Firewall"] = fw
            # Soft MAC
            signals["Mac"] = self._detect_mac()
        except Exception as e:
            signals["Errors"].append(str(e))
        return signals

    def _known_names(self) -> list[str]:
        names = list(_DEFAULT_AGENTS)
        extra = self._config.get("OsSecurityKnownAgentNames") or self._config.get("KnownAgentNames") or []
        for n in extra:
            if n and n.lower() not in names:
                names.append(n.lower())
        return names

    def _detect_agents(self) -> list[str]:
        found = []
        known = self._known_names()
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    name = (Path(f"/proc/{pid}/comm").read_text(errors="ignore") or "").strip().lower()
                    cmdline = ""
                    try:
                        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "ignore").lower()
                    except Exception:
                        pass
                    for k in known:
                        if k in name or k in cmdline:
                            if k not in found:
                                found.append(k)
                except Exception:
                    continue
        except Exception:
            pass
        # systemd units (optional)
        out = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
        for k in ("clamav", "clamd", "falcon", "sentinel", "sophos", "defender"):
            if k in out.lower() and k not in found:
                found.append(k)
        return found

    def _detect_firewall(self) -> dict[str, Any]:
        info: dict[str, Any] = {"Active": None, "Backend": None}
        out = _run(["systemctl", "is-active", "firewalld"])
        if "active" in out and "inactive" not in out.split():
            info["Active"] = True
            info["Backend"] = "firewalld"
            return info
        out = _run(["systemctl", "is-active", "ufw"])
        if "active" in out and "inactive" not in out.split():
            info["Active"] = True
            info["Backend"] = "ufw"
            return info
        # nft/iptables presence is weak signal
        if Path("/usr/sbin/nft").exists() or Path("/sbin/iptables").exists():
            info["Backend"] = "nft/iptables"
            info["Active"] = None
        return info

    def _detect_mac(self) -> dict[str, Any]:
        mac = {"SELinux": None, "AppArmor": None}
        if Path("/sys/fs/selinux").exists():
            out = _run(["getenforce"])
            mac["SELinux"] = out.strip() or "present"
        if Path("/sys/kernel/security/apparmor").exists():
            mac["AppArmor"] = "present"
        return mac

    def classify(self, signals: dict[str, Any]) -> str:
        agents = signals.get("Agents") or []
        # Any known AV/EDR agent → Present
        if agents:
            return "Present"
        fw = signals.get("Firewall") or {}
        if fw.get("Active") is True:
            return "Partial"
        # MAC alone is not Present
        return "Absent"

    def recommend(self, klass: str, signals: dict[str, Any]) -> list[str]:
        recs = []
        if klass == "Partial":
            if not (signals.get("Agents") or []):
                recs.append("InstallOrEnableEndpointAV")
            fw = signals.get("Firewall") or {}
            if fw.get("Active") is not True:
                recs.append("EnableHostFirewall")
        if klass == "Absent":
            recs.append("NoOsSecurityDetected_ConsiderFallbackOrInstallAV")
        return recs

    def detect_and_classify(self) -> dict[str, Any]:
        if self._config.get("OsSecurityEnabled") is False:
            return {
                "Class": "Unknown",
                "Signals": {},
                "Recommendations": [],
                "FallbackEligible": False,
                "FallbackActive": False,
                "Skipped": True,
            }
        signals = self.detect()
        klass = self.classify(signals)
        recs = self.recommend(klass, signals)
        detection_only = self._config.get("OsSecurityDetectionOnly", True)
        if detection_only is None:
            detection_only = True
        fallback_enabled = bool(self._config.get("OsSecurityFallbackEnabled", False))
        eligible = (klass == "Absent") and fallback_enabled and (not detection_only)
        # Group C apply not implemented here — gate only
        fallback_active = False
        if eligible and self._config.get("OsSecurityFallbackAutoOnAbsent"):
            # Future: apply_fallback(); for now only mark eligible
            fallback_active = False
        return {
            "Class": klass,
            "Signals": signals,
            "Recommendations": recs,
            "FallbackEligible": eligible,
            "FallbackActive": fallback_active,
            "Skipped": False,
        }
