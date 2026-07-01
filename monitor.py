"""
monitor.py — Exploit monitoring & alerting.

Polls Sui full-node JSON-RPC (or a websocket subscription) for transactions
touching watchlisted packages/objects, extracts effects, and emits
TxEvent objects for the rest of the pipeline (classifier -> simulator ->
alerting) to consume.

This module is transport-pluggable: swap `SuiRpcClient` for a websocket
subscription client without touching downstream code.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

import requests

from .config import SuiSentinelConfig

logger = logging.getLogger("sui_sentinel.monitor")


@dataclass
class TxEvent:
    digest: str
    package_id: Optional[str]
    sender: str
    timestamp_ms: int
    status: str  # "success" | "failure"
    gas_used: int
    balance_changes: List[dict] = field(default_factory=list)
    events: List[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def text_blob(self) -> str:
        """Flattened text used by the rule-based pre-filter in classifier.py."""
        parts = [self.status]
        for e in self.events:
            parts.append(json.dumps(e.get("parsedJson", {})))
            parts.append(e.get("type", ""))
        return " ".join(parts).lower()


class SuiRpcClient:
    """Thin JSON-RPC wrapper over a Sui full node."""

    def __init__(self, cfg: SuiSentinelConfig):
        self.cfg = cfg
        self._session = requests.Session()

    def _call(self, method: str, params: list) -> dict:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        resp = self._session.post(self.cfg.sui_rpc_url, json=payload, timeout=20)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"Sui RPC error on {method}: {body['error']}")
        return body["result"]

    def query_transactions_for_package(self, package_id: str, limit: int = 25,
                                        cursor: Optional[str] = None) -> dict:
        """suix_queryTransactionBlocks filtered by InputObject/MoveFunction."""
        return self._call(
            "suix_queryTransactionBlocks",
            [
                {"filter": {"InputObject": package_id}, "options": {
                    "showEffects": True, "showEvents": True,
                    "showBalanceChanges": True, "showInput": True,
                }},
                cursor, limit, True,
            ],
        )

    def get_object(self, object_id: str) -> dict:
        return self._call("sui_getObject", [object_id, {"showContent": True, "showOwner": True}])


def _parse_tx(raw: dict) -> TxEvent:
    effects = raw.get("effects", {}) or {}
    status = (effects.get("status", {}) or {}).get("status", "unknown")
    return TxEvent(
        digest=raw.get("digest", ""),
        package_id=None,  # filled by caller, since query is package-scoped
        sender=(raw.get("transaction", {}) or {}).get("data", {}).get("sender", ""),
        timestamp_ms=int(raw.get("timestampMs", 0) or 0),
        status=status,
        gas_used=int((effects.get("gasUsed", {}) or {}).get("computationCost", 0) or 0),
        balance_changes=raw.get("balanceChanges", []) or [],
        events=raw.get("events", []) or [],
        raw=raw,
    )


class ExploitMonitor:
    """
    Polling loop over watchlisted packages. Calls `on_event` for every new
    transaction observed since the last poll. Designed to run inside the
    SentinelAgent orchestrator (agent.py) or standalone.
    """

    def __init__(self, cfg: SuiSentinelConfig, client: Optional[SuiRpcClient] = None):
        self.cfg = cfg
        self.client = client or SuiRpcClient(cfg)
        self._seen_digests: set[str] = set()

    def poll_once(self, package_id: str) -> List[TxEvent]:
        new_events: List[TxEvent] = []
        try:
            result = self.client.query_transactions_for_package(package_id)
        except Exception as exc:
            logger.warning("poll failed for %s: %s", package_id, exc)
            return new_events

        for raw_tx in result.get("data", []):
            digest = raw_tx.get("digest")
            if not digest or digest in self._seen_digests:
                continue
            self._seen_digests.add(digest)
            ev = _parse_tx(raw_tx)
            ev.package_id = package_id
            new_events.append(ev)
        return new_events

    def run_forever(self, on_event: Callable[[TxEvent], None],
                     stop_after_iterations: Optional[int] = None):
        """Blocking loop. In production run this inside a `screen`/systemd
        unit, mirroring the existing NanoJS alert-bot pattern."""
        i = 0
        while stop_after_iterations is None or i < stop_after_iterations:
            for pkg in self.cfg.watchlist_packages:
                for ev in self.poll_once(pkg):
                    try:
                        on_event(ev)
                    except Exception:
                        logger.exception("on_event handler raised for tx %s", ev.digest)
            i += 1
            time.sleep(self.cfg.poll_interval_seconds)
