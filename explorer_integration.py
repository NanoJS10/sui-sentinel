"""
explorer_integration.py — explorer-integrated tools.

Produces the three artifacts meant to be embedded into a block explorer UI:
  1. transaction graph edges (for visualization)
  2. wallet risk scores (0-1)
  3. address attribution tags (drawing on the same OFAC/Chainabuse-style
     enrichment pattern already used in nanojs_enrichment.py)

Kept storage-agnostic: `build_address_graph` returns plain dict structures
so they can be dumped to JSON for any front-end (D3, Cytoscape, a custom
explorer plugin) to consume.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .monitor import TxEvent

logger = logging.getLogger("sui_sentinel.explorer")


@dataclass
class WalletRiskScore:
    address: str
    score: float  # 0 (clean) - 1 (high risk)
    reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)  # e.g. "ofac_sdn", "mixer", "bridge_relayer"


@dataclass
class GraphEdge:
    src: str
    dst: str
    digest: str
    amount: float
    coin_type: str


class WalletRiskScorer:
    """
    Pluggable risk scoring: combines local heuristics (velocity, fan-out,
    known-bad-address proximity) with optional external feeds. Pass in a
    `screening_lookup` callable to reuse your existing OFAC SDN / Chainabuse
    lookup logic from nanojs_enrichment.py rather than duplicating it here.
    """

    def __init__(self, screening_lookup: Optional[callable] = None):
        self.screening_lookup = screening_lookup
        self._tx_count: Dict[str, int] = {}
        self._counterparties: Dict[str, Set[str]] = {}

    def ingest(self, tx: TxEvent):
        for bc in tx.balance_changes:
            owner = (bc.get("owner") or {}).get("AddressOwner")
            if not owner:
                continue
            self._tx_count[owner] = self._tx_count.get(owner, 0) + 1
            self._counterparties.setdefault(owner, set()).add(tx.sender)

    def score(self, address: str) -> WalletRiskScore:
        reasons: List[str] = []
        tags: List[str] = []
        score = 0.0

        velocity = self._tx_count.get(address, 0)
        if velocity > 50:
            score += 0.2
            reasons.append(f"high tx velocity ({velocity} txs observed)")

        fan_out = len(self._counterparties.get(address, set()))
        if fan_out > 20:
            score += 0.15
            reasons.append(f"high counterparty fan-out ({fan_out} distinct addresses)")

        if self.screening_lookup:
            try:
                hit = self.screening_lookup(address)
                if hit:
                    score += 0.6
                    reasons.append("matched external screening list (OFAC/Chainabuse)")
                    tags.append(hit.get("tag", "screened"))
            except Exception as exc:
                logger.warning("screening_lookup failed for %s: %s", address, exc)

        score = min(score, 1.0)
        return WalletRiskScore(address=address, score=score, reasons=reasons, tags=tags)


def build_address_graph(events: List[TxEvent]) -> Dict[str, List[dict]]:
    """Flattens a batch of TxEvents into nodes/edges suitable for explorer
    transaction-graph visualization widgets."""
    nodes: Set[str] = set()
    edges: List[GraphEdge] = []

    for tx in events:
        nodes.add(tx.sender)
        for bc in tx.balance_changes:
            owner = (bc.get("owner") or {}).get("AddressOwner")
            if not owner:
                continue
            nodes.add(owner)
            amount = float(bc.get("amount", 0) or 0)
            if amount != 0:
                edges.append(GraphEdge(
                    src=tx.sender, dst=owner, digest=tx.digest,
                    amount=amount, coin_type=bc.get("coinType", "unknown"),
                ))

    return {
        "nodes": [{"id": n} for n in nodes],
        "edges": [edge.__dict__ for edge in edges],
    }
