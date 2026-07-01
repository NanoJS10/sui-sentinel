"""
agent.py — SentinelAgent: the orchestration loop tying every module into a
single agentic workflow.

Loop per observed transaction (observe -> classify -> [simulate] -> score ->
decide -> act -> log), with the LLM only invoked where the classifier
decides escalation is warranted (cost control) and simulation only run for
severity >= 4 (compute control). This keeps the "agentic" part of the
workflow — escalation/simulation decisions — adaptive rather than running
every expensive step on every transaction.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .alerting import TelegramAlerter, format_alert
from .classifier import LlmCaller, classify
from .config import SuiSentinelConfig
from .explorer_integration import WalletRiskScorer
from .monitor import ExploitMonitor, TxEvent
from .simulator import ExploitSimulator

logger = logging.getLogger("sui_sentinel.agent")

SIMULATE_AT_SEVERITY = 4  # run exploit simulation for tx classified at/above this severity


class SentinelAgent:
    def __init__(self, cfg: SuiSentinelConfig, llm_call: Optional[LlmCaller] = None,
                 screening_lookup: Optional[callable] = None):
        self.cfg = cfg
        self.llm_call = llm_call
        self.monitor = ExploitMonitor(cfg)
        self.simulator = ExploitSimulator(cfg)
        self.risk_scorer = WalletRiskScorer(screening_lookup=screening_lookup)
        self.alerter = TelegramAlerter(cfg)
        os.makedirs(cfg.log_dir, exist_ok=True)

    def handle_event(self, tx: TxEvent):
        self.risk_scorer.ingest(tx)

        classification = classify(tx, llm_call=self.llm_call)
        risk = self.risk_scorer.score(tx.sender)

        sim_result = None
        if classification.severity >= SIMULATE_AT_SEVERITY:
            sim_result = self.simulator.replay_transaction(tx)

        self._log_event(tx, classification, risk, sim_result)

        if classification.severity >= SIMULATE_AT_SEVERITY or risk.score >= self.cfg.risk_score_alert_threshold:
            message = format_alert(tx, classification, risk, sim_result)
            self.alerter.send(message)
            logger.info("Alert dispatched for %s (%s)", tx.digest, classification.category.value)

    def _log_event(self, tx: TxEvent, classification, risk, sim_result):
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "digest": tx.digest,
            "package_id": tx.package_id,
            "sender": tx.sender,
            "status": tx.status,
            "classification": asdict(classification) if hasattr(classification, "__dataclass_fields__") else classification.__dict__,
            "risk": risk.__dict__,
            "simulation": sim_result.__dict__ if sim_result else None,
        }
        # Convert any non-serializable Enum values
        record["classification"]["category"] = classification.category.value
        path = os.path.join(self.cfg.log_dir, "events.jsonl")
        with open(path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def run(self, stop_after_iterations: Optional[int] = None):
        logger.info("SentinelAgent starting, watching %d package(s)", len(self.cfg.watchlist_packages))
        self.monitor.run_forever(self.handle_event, stop_after_iterations=stop_after_iterations)
