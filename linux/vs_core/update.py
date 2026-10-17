"""Update manager — verify, apply, LKG rollback."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .base import Component


class UpdateManager(Component):
    def save_lkg(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest = self._paths.lkg_dir / stamp
        dest.mkdir(parents=True, exist_ok=True)
        if self._paths.config_file.exists():
            (dest / "engine.json").write_text(
                self._paths.config_file.read_text(encoding="utf-8"), encoding="utf-8"
            )
        meta = {
            "Version": self._config.get("Version"),
            "SavedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Profile": self._config.get("Profile"),
            "ResponseMode": self._config.get("ResponseMode"),
        }
        (dest / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (self._paths.lkg_dir / "CURRENT").write_text(str(dest), encoding="utf-8")
        self.log_info(f"LKG saved at {dest}")
        return str(dest)

    def rollback(self) -> dict:
        cur = self._paths.lkg_dir / "CURRENT"
        if cur.exists():
            dest = Path(cur.read_text(encoding="utf-8").strip())
        else:
            dirs = sorted([p for p in self._paths.lkg_dir.iterdir() if p.is_dir()], reverse=True)
            if not dirs:
                return {"ok": False, "error": "no_lkg"}
            dest = dirs[0]
        cfg_src = dest / "engine.json"
        if not cfg_src.exists():
            return {"ok": False, "error": "lkg_config_missing"}
        self._paths.config_file.write_text(cfg_src.read_text(encoding="utf-8"), encoding="utf-8")
        self.log_warn(f"Rolled back config from LKG {dest}")
        return {"ok": True, "restored_from": str(dest)}

    def check(self) -> dict:
        result = {
            "CurrentVersion": self._config.get("Version") or "1.7.0",
            "Channel": self._config.get("UpdateChannel") or "stable",
            "Available": False,
            "Manifest": None,
            "Error": "",
        }
        local = self._paths.update_dir / "manifest.json"
        if local.exists():
            try:
                man = json.loads(local.read_text(encoding="utf-8"))
                result["Manifest"] = man
                if man.get("Version") and man.get("Version") != result["CurrentVersion"]:
                    result["Available"] = True
            except Exception as e:
                result["Error"] = f"local_manifest:{e}"
        (self._paths.update_dir / "last_check.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        return result

    def apply(self, force: bool = False) -> dict:
        if self._config.get("FirstRunState") != "Steady" and not force:
            return {"ok": False, "error": "first_run_not_steady"}
        check = self.check()
        man = check.get("Manifest") or {}
        if not check.get("Available") and not force:
            return {"ok": False, "error": "no_update_available", "check": check}
        files = man.get("Files") or man.get("files") or []
        package_root = self._paths.update_dir / "package"
        for item in files:
            rel = item.get("path") or item.get("Path") or ""
            expect = (item.get("sha256") or item.get("Sha256") or "").lower()
            fp = package_root / rel
            if not fp.is_file():
                return {"ok": False, "error": f"missing_file:{rel}"}
            if expect:
                h = hashlib.sha256(fp.read_bytes()).hexdigest()
                if h != expect:
                    return {"ok": False, "error": f"hash_mismatch:{rel}"}
        lkg = self.save_lkg()
        applied = []
        for item in files:
            rel = item.get("path") or item.get("Path") or ""
            src = package_root / rel
            if Path(rel).name == "threat_intel.txt":
                dst = self._paths.data / "threat_intel.txt"
            else:
                dst = self._paths.root / rel
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
                applied.append(rel)
            except Exception as e:
                self.rollback()
                return {"ok": False, "error": f"apply:{rel}:{e}", "lkg": lkg}
        if man.get("Version"):
            self._config["Version"] = man["Version"]
        return {"ok": True, "applied": applied, "version": self._config.get("Version"), "lkg": lkg}
