"""Abstract bases — extension points for full EDR/XDR growth."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Component(ABC):
    """Base encapsulated component with shared config/paths/logger."""

    def __init__(self, paths, config: dict, log=None):
        self._paths = paths
        self._config = config
        self._log = log

    @property
    def config(self) -> dict:
        return self._config

    def reload_config(self, config: dict) -> None:
        self._config = config

    def log_info(self, msg: str) -> None:
        if self._log:
            self._log.info(msg)

    def log_warn(self, msg: str) -> None:
        if self._log:
            self._log.warning(msg)

    def log_error(self, msg: str) -> None:
        if self._log:
            self._log.error(msg)


class Sensor(Component, ABC):
    """Collects telemetry. Subclass for process, network, file, identity sensors."""

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        ...


class Detector(Component, ABC):
    """Produces findings from telemetry. Subclass per domain (ransomware, malware, ...)."""

    @abstractmethod
    def detect(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        ...


class Responder(Component, ABC):
    """Acts on findings. Subclass for kill, quarantine, network isolate, backup freeze."""

    @abstractmethod
    def respond(self, finding: dict[str, Any]) -> bool:
        ...


class PolicyEngine(Component, ABC):
    """Decides Manual vs Automatic and whether to act."""

    @abstractmethod
    def should_act_immediately(self, finding: dict[str, Any]) -> bool:
        ...

    @abstractmethod
    def requires_human_approval(self, finding: dict[str, Any]) -> bool:
        ...
