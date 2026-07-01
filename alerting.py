"""
alerting.py — alert delivery, mirroring the existing NanoJS Alert Bot pattern
(Telegram, severity-tiered). Swap `send` targets to add Slack/Discord/email
without touching the orchestrator.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import requests

from .classifier import ClassificationResult
from .config import SuiSentinelConfig
from .explorer_integration import WalletRiskScore
from .monitor import TxEvent
from .simulator import SimulationResult

logger = logging.getLogger("sui_sentinel.alerting")

SEVERITY_EMOJI = {5: "🔴", 4: "🟠", 3: "🟡", 2: "🔵", 1: "⚪"}


def format_alert(tx: TxEvent, classification: ClassificationResult,
                  risk: Optional[WalletRiskScore] = None,
                  sim: Optional[SimulationResult] = None) -> str:
    ts = datetime.fromtimestamp(tx.timestamp_ms / 1000, tz=timezone.utc).isoformat() if tx.timestamp_ms else "unknown"
    emoji = SEVERITY_EMOJI.get(classification.severity, "⚪")
    lines = [
        f"{emoji} SuiSentinel Alert — {classification.category.value.upper()} (sev {classification.severity}/5)",
        f"Digest: {tx.digest}",
        f"Package: {tx.package_id}",
        f"Sender: {tx.sender}",
        f"Status: {tx.status} | Time: {ts}",
        f"Confidence: {classification.confidence:.2f} ({classification.stage})",
        f"Rationale: {classification.rationale}",
    ]
    if risk:
        lines.append(f"Sender risk score: {risk.score:.2f} — {', '.join(risk.reasons) or 'no flags'}")
    if sim:
        lines.append(f"Simulation: {'ran' if sim.ran else 'skipped'} — {sim.estimated_impact_note}")
    return "\n".join(lines)


class TelegramAlerter:
    def __init__(self, cfg: SuiSentinelConfig):
        self.cfg = cfg

    def send(self, message: str) -> bool:
        if not self.cfg.telegram_bot_token or not self.cfg.telegram_chat_id:
            logger.info("Telegram not configured; alert suppressed:\n%s", message)
            return False
        url = f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage"
        try:
            resp = requests.post(url, json={
                "chat_id": self.cfg.telegram_chat_id, "text": message,
            }, timeout=10)
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Telegram send failed: %s", exc)
            return False
