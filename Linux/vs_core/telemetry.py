"""Telemetry collection sensors."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .base import Sensor


class ProcessSensor(Sensor):
    def collect(self) -> dict[str, Any]:
        procs = []
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                base = Path("/proc") / pid
                try:
                    status = (base / "status").read_text(errors="ignore")
                    name = ""
                    threads = 0
                    rss_kb = 0
                    for line in status.splitlines():
                        if line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("Threads:"):
                            threads = int(line.split(":", 1)[1].strip())
                        elif line.startswith("VmRSS:"):
                            rss_kb = int(line.split(":", 1)[1].strip().split()[0])
                    exe = ""
                    try:
                        exe = os.readlink(base / "exe")
                    except Exception:
                        pass
                    procs.append({
                        "pid": int(pid),
                        "name": name,
                        "exe": exe,
                        "memory_mb": round(rss_kb / 1024, 1),
                        "threads": threads,
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return {"processes": procs}


class MemorySensor(Sensor):
    def collect(self) -> dict[str, Any]:
        mem_total = mem_avail = 0
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail = int(line.split()[1])
        except Exception:
            pass
        used_pct = 0
        if mem_total > 0:
            used_pct = round(100 * (mem_total - mem_avail) / mem_total, 1)
        return {"memory_used_pct": used_pct, "memory_total_kb": mem_total}


class CompositeTelemetry(Sensor):
    """Aggregates multiple sensors — extend with network/file/identity sensors for XDR."""

    def __init__(self, paths, config, log=None, sensors: list[Sensor] | None = None):
        super().__init__(paths, config, log)
        self._sensors = sensors or [
            ProcessSensor(paths, config, log),
            MemorySensor(paths, config, log),
        ]

    def collect(self) -> dict[str, Any]:
        snap: dict[str, Any] = {
            "processes": [],
            "memory_used_pct": 0,
            "net_external_conns": 0,
            "net_unique_ips": 0,
            "net_remotes": [],
        }
        for s in self._sensors:
            try:
                part = s.collect()
                if "processes" in part:
                    snap["processes"] = part["processes"]
                snap.update({k: v for k, v in part.items() if k != "processes"})
            except Exception as e:
                self.log_error(f"Sensor {type(s).__name__} failed: {e}")
        return snap
