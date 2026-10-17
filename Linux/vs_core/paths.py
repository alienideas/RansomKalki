"""Filesystem layout for agent install."""
from pathlib import Path


class Paths:
    def __init__(self, root: Path | None = None):
        self.root = (root or Path(__file__).resolve().parent.parent)
        self.data = self.root / "data"
        self.logs = self.root / "logs"
        self.config_dir = self.root / "config"
        self.config_file = self.config_dir / "engine.json"
        self.status_file = self.data / "status.json"
        self.pid_file = self.data / "vectorstryke.pid"
        self.log_file = self.logs / "engine.log"
        self.alert_dir = self.data / "alerts"
        self.quarantine = self.data / "quarantine"
        self.intel_file = self.data / "threat_intel.txt"
        self.lkg_dir = self.data / "last_known_good"
        self.update_dir = self.data / "updates"
        self.canary_dir = self.data / "canaries"
        self.checkpoint_dir = self.data / "checkpoints"
        self.health_file = self.data / "health.json"

    def ensure(self) -> None:
        for d in (
            self.data, self.logs, self.config_dir, self.alert_dir,
            self.quarantine, self.lkg_dir, self.update_dir,
            self.canary_dir, self.checkpoint_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
