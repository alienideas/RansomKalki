"""Recovery engine — canaries, checkpoints, ImpactPending."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .base import Component


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RecoveryEngine(Component):
    def init_canaries(self) -> dict:
        d = self._paths.canary_dir
        d.mkdir(parents=True, exist_ok=True)
        paths = [
            d / "VS_CANARY_IMPORTANT.txt",
            d / "documents" / "VS_CANARY_DOC.txt",
            d / "finance" / "VS_CANARY_FIN.txt",
        ]
        for extra in self._config.get("CanaryPaths") or []:
            if extra:
                paths.append(Path(extra))
        created = []
        content = f"VectorStryke canary file — do not modify.\nCreated={_utc()}\n"
        for p in paths:
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                p.write_text(content, encoding="utf-8")
                created.append(str(p))
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            (d / (p.name + ".sha256")).write_text(h, encoding="utf-8")
        existing = [str(p) for p in paths if p.exists()]
        (d / "manifest.json").write_text(json.dumps({
            "paths": existing, "InitializedAt": _utc()
        }, indent=2), encoding="utf-8")
        return {"ok": True, "created": created, "paths": existing}

    def verify_canaries(self) -> dict:
        man_path = self._paths.canary_dir / "manifest.json"
        if not man_path.exists():
            return {"ok": True, "skipped": True, "reason": "no_canaries"}
        try:
            man = json.loads(man_path.read_text(encoding="utf-8"))
        except Exception:
            return {"ok": False, "error": "canary_manifest_corrupt"}
        failures = []
        for ps in man.get("paths") or []:
            p = Path(ps)
            if not p.is_file():
                failures.append({"path": ps, "reason": "missing"})
                continue
            hp = self._paths.canary_dir / (p.name + ".sha256")
            if hp.exists():
                expect = hp.read_text(encoding="utf-8").strip()
                actual = hashlib.sha256(p.read_bytes()).hexdigest()
                if actual != expect:
                    failures.append({"path": ps, "reason": "hash_mismatch"})
        return {"ok": len(failures) == 0, "failures": failures}

    def detect_prelude(self, processes: list[dict] | None = None) -> dict | None:
        if not self._config.get("RecoveryEnabled", True):
            return None
        score = 0
        reasons = []
        v = self.verify_canaries()
        if not v.get("ok") and not v.get("skipped"):
            score += 50
            reasons.append("CanaryIntegrityFailed:" + str(len(v.get("failures") or [])))
        for p in processes or []:
            n = (p.get("name") or "").lower()
            if any(k in n for k in ("encrypt", "ransom", "locker", "crypt")):
                score += 30
                reasons.append(f"SuspiciousProcess:{p.get('name')}:{p.get('pid')}")
            if n in ("vssadmin", "wbadmin") or "shadow" in n:
                score += 25
                reasons.append(f"BackupTamperTool:{p.get('name')}")
        try:
            hits = sum(
                1 for p in self._paths.canary_dir.rglob("*")
                if p.is_file() and any(p.name.endswith(ext) for ext in (".locked", ".encrypted", ".crypted", ".onion"))
            )
            if hits:
                score += 20
                reasons.append(f"EncryptedExtensions={hits}")
        except Exception:
            pass
        if score < 40:
            return None
        return {
            "id": 9001, "type": "ImpactPrelude", "name": "EncryptionPrelude",
            "pid": 0, "exe": "", "memory_mb": 0, "score": min(score, 100),
            "reasons": " | ".join(reasons), "severity": "High",
            "timestamp": _utc(), "impact_class": True,
        }

    def create_checkpoint(self, reason: str = "manual") -> dict:
        cid = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + os.urandom(3).hex()
        dest = self._paths.checkpoint_dir / cid
        dest.mkdir(parents=True, exist_ok=True)
        copied = []
        if self._paths.canary_dir.exists():
            for p in self._paths.canary_dir.rglob("*"):
                if p.is_file():
                    rel = p.relative_to(self._paths.canary_dir)
                    target = dest / "canaries" / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(p.read_bytes())
                    copied.append(str(rel))
        meta = {
            "CheckpointId": cid, "Reason": reason, "CreatedAt": _utc(),
            "CopiedCanaries": copied, "Notes": [], "Host": os.uname().nodename if hasattr(os, "uname") else "linux",
        }
        (dest / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self._config["LastCheckpointId"] = cid
        self.log_warn(f"Checkpoint created {cid}")
        return meta

    def enter_impact_pending(self, finding: dict) -> dict:
        self._config["ImpactPending"] = True
        return self.create_checkpoint(reason="ImpactPending:" + (finding.get("name") or ""))

    def clear_impact_pending(self, force: bool = False) -> dict:
        if not force:
            v = self.verify_canaries()
            if not v.get("ok"):
                return {"ok": False, "error": "canary_verify_failed", "verify": v}
        self._config["ImpactPending"] = False
        return {"ok": True}
