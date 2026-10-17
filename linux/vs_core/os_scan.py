"""OS security file scanner — quarantine-first, exclusion-aware.
Integrates with OsSecurityAdapter detect-first classification.
No external deps. Optional VT hook left as config stub.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import Component
from .os_security import OsSecurityAdapter

_SUSPICIOUS = [
    "powershell -enc", "downloadstring", "frombase64string", "invoke-expression",
    "eval(", "cmd /c", "reg add", "schtasks", "mimikatz", "virtualalloc",
    "/bin/bash -c", "base64 -d", "curl | sh", "wget | bash",
]
_EXEC_EXT = {".exe", ".dll", ".sys", ".so", ".sh", ".py", ".pl", ".elf", ""}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path, max_bytes: int = 50 * 1024 * 1024) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            read = 0
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                h.update(chunk)
                if read >= max_bytes:
                    break
        return h.hexdigest()
    except Exception:
        return None


def _entropy(path: Path, max_bytes: int = 65536) -> float:
    try:
        data = path.read_bytes()[:max_bytes]
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for c in freq:
            if c == 0:
                continue
            p = c / n
            ent -= p * math.log2(p)
        return round(ent, 3)
    except Exception:
        return 0.0


def _string_hits(path: Path) -> list[str]:
    hits = []
    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            return hits
        text = path.read_bytes()[:2_000_000].decode("utf-8", "ignore").lower()
        for p in _SUSPICIOUS:
            if p.lower() in text:
                hits.append(p)
    except Exception:
        pass
    return hits


def _score(sig: str, entropy: float, hits: int, external: bool = False) -> int:
    s = 0
    if sig == "Valid":
        s += 0
    elif sig == "Invalid":
        s += 50
    elif sig == "Missing":
        s += 40
    else:
        s += 15
    if entropy > 7.0:
        s += int(((entropy - 7.0) / 0.5)) * 10
    s += hits * 5
    if external:
        s += 50
    return min(s, 100)


class OsScanEngine(Component):
    def _env(self) -> dict[str, Path]:
        data = self._paths.data
        work = data / "osscan_tmp"
        quar = data / "osscan_quarantine"
        work.mkdir(parents=True, exist_ok=True)
        quar.mkdir(parents=True, exist_ok=True)
        excl = data / "osscan_exclusions.txt"
        if not excl.exists():
            excl.write_text(
                "# path prefixes to skip\n/proc\n/sys\n/dev\n/run\n",
                encoding="utf-8",
            )
        return {
            "work": work,
            "quarantine": quar,
            "baseline": data / "osscan_baseline.csv",
            "exclusions": excl,
            "manifest": quar / "quarantine.log",
        }

    def _exclusions(self) -> list[str]:
        env = self._env()
        out = ["/proc", "/sys", "/dev", "/run", "/snap"]
        try:
            for line in env["exclusions"].read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
        except Exception:
            pass
        for p in self._config.get("OsScanExtraExclusions") or []:
            if p:
                out.append(p)
        return out

    def _is_excluded(self, path: str, excl: list[str]) -> bool:
        for e in excl:
            if path == e or path.startswith(e.rstrip("/") + "/"):
                return True
        return False

    def build_baseline(self, max_files: int = 200) -> dict[str, Any]:
        env = self._env()
        rows = ["filepath,sha256"]
        count = 0
        roots = [Path("/bin"), Path("/sbin"), Path("/usr/bin"), Path("/usr/lib")]
        for root in roots:
            if not root.is_dir():
                continue
            try:
                for p in root.iterdir():
                    if count >= max_files:
                        break
                    if p.is_file() and not p.is_symlink():
                        h = _sha256(p)
                        if h:
                            rows.append(f'"{p}",{h}')
                            count += 1
            except Exception:
                continue
        env["baseline"].write_text("\n".join(rows) + "\n", encoding="utf-8")
        return {"ok": True, "files": count, "path": str(env["baseline"])}

    def scan(self, roots: list[str] | None = None, full: bool = False) -> dict[str, Any]:
        # Layer 1: OS-SEC detect-first
        ossec = OsSecurityAdapter(self._paths, self._config, self._log).detect_and_classify()
        self.log_info(f"OS-SEC pre-scan class={ossec.get('Class')}")

        excl = self._exclusions()
        if not roots:
            if full:
                roots = ["/home", "/opt", "/tmp", "/var/tmp"]
            else:
                roots = [
                    str(Path.home() / "Downloads"),
                    str(Path.home() / "Desktop"),
                    "/tmp",
                    "/var/tmp",
                ]
        max_files = int(self._config.get("OsScanMaxFiles") or 2000)
        scanned = 0
        findings: list[dict[str, Any]] = []
        env = self._env()

        for root in roots:
            rp = Path(root)
            if not rp.exists():
                continue
            for dirpath, dirnames, filenames in os.walk(rp, followlinks=False):
                # prune excluded dirs
                dirnames[:] = [d for d in dirnames if not self._is_excluded(str(Path(dirpath) / d), excl)]
                for fn in filenames:
                    if scanned >= max_files:
                        break
                    fp = Path(dirpath) / fn
                    if self._is_excluded(str(fp), excl):
                        continue
                    try:
                        if not fp.is_file() or fp.is_symlink():
                            continue
                    except Exception:
                        continue
                    scanned += 1
                    ext = fp.suffix.lower()
                    is_exec = ext in _EXEC_EXT or os.access(fp, os.X_OK)
                    ent = _entropy(fp) if is_exec else 0.0
                    hits = _string_hits(fp) if is_exec or ext in {".sh", ".py", ".pl"} else []
                    # Linux: signature N/A → Missing for executables
                    sig = "Missing" if is_exec else "N/A"
                    score = _score(sig, ent, len(hits))
                    if not is_exec and score > 40:
                        score = 40
                    tier = "Clean" if score <= 30 else ("Suspicious" if score <= 70 else "Malicious")
                    if tier == "Clean":
                        continue
                    findings.append({
                        "Path": str(fp),
                        "Size": fp.stat().st_size,
                        "Score": score,
                        "Tier": tier,
                        "Signature": sig,
                        "Entropy": ent,
                        "StringHits": hits,
                        "Sha256": _sha256(fp),
                        "OsSecClass": ossec.get("Class"),
                    })
                if scanned >= max_files:
                    break

        auto_q = self._config.get("OsScanAutoQuarantine", True)
        actions = []
        for r in findings:
            if not auto_q:
                continue
            guid = uuid.uuid4().hex
            dest_dir = env["quarantine"] / guid
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / Path(r["Path"]).name
            try:
                shutil.move(r["Path"], dest)
                r["Quarantined"] = True
                r["QuarantinePath"] = str(dest)
                line = f"{_utc()}|{r['Path']}|{dest}|{r['Score']}|{r['Tier']}\n"
                with env["manifest"].open("a", encoding="utf-8") as mf:
                    mf.write(line)
                actions.append(f"Quarantined:{r['Path']}")
                self.log_warn(f"OS scan quarantined score={r['Score']} {r['Path']}")
            except Exception as e:
                r["Quarantined"] = False
                r["Error"] = str(e)

        report = {
            "ScannedFiles": scanned,
            "Findings": findings,
            "Actions": actions,
            "OsSecClass": ossec.get("Class"),
            "OsSecFallbackEligible": ossec.get("FallbackEligible"),
            "QuarantineDir": str(env["quarantine"]),
            "CompletedAt": _utc(),
            "ExitCode": 0,
        }
        report_path = self._paths.data / f"osscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["ReportPath"] = str(report_path)
        return report
