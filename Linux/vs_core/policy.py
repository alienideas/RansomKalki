"""Response policy — Manual vs Automatic decision engine."""
from __future__ import annotations

from .base import PolicyEngine


class ResponsePolicy(PolicyEngine):
    """
    Automatic: fully automatic — no explicit approvals; act when score >= threshold.
    Manual: human approval required for all actions; timeout never auto-acts.
    """

    def mode(self) -> str:
        return (self._config.get("ResponseMode") or "Automatic").title()

    def is_automatic(self) -> bool:
        return self.mode() == "Automatic"

    def is_manual(self) -> bool:
        return self.mode() == "Manual"

    def score_threshold(self) -> int:
        return int(self._config.get("AutoApproveScoreThreshold") or 80)

    def should_act_immediately(self, finding: dict) -> bool:
        if not self._config.get("AgentEnabled", True):
            return False
        if (self._config.get("FirstRunState") or "PendingConfig") != "Steady" and self.is_automatic():
            # still allow Automatic after Steady; before Steady be cautious unless high impact prelude
            if not finding.get("impact_class") and int(finding.get("score") or 0) < 90:
                return False
        score = int(finding.get("score") or 0)
        if self.is_automatic():
            return score >= min(60, self.score_threshold())
        return False

    def requires_human_approval(self, finding: dict) -> bool:
        if self.is_automatic():
            return False
        return True

    def allow_timeout_auto_action(self) -> bool:
        """Timeout automation is Manual-only (never auto)."""
        return False
