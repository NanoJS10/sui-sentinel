"""
classifier.py — the exploit-classifier agent.

Two-stage classification, cheapest-first:
  1. Rule-based pre-filter (CATEGORY_SIGNALS keyword/heuristic match) — fast,
     free, runs on every tx.
  2. LLM agent escalation — only for txs that clear a suspicion threshold
     (failed status, large balance change, matched >=1 rule-based signal,
     or touches a known bridge/verifier function). Uses the Anthropic API
     with a structured-JSON system prompt so output maps directly onto
     ExploitCategory.

Bring your own Anthropic client — `classify_with_llm` accepts an injected
callable so this module has no hard dependency on a specific SDK version.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .config import CATEGORY_SEVERITY, CATEGORY_SIGNALS, ExploitCategory
from .monitor import TxEvent

logger = logging.getLogger("sui_sentinel.classifier")

LLM_SYSTEM_PROMPT = """You are an on-chain exploit classification agent for the Sui \
blockchain, operating inside NanoJS Investigations' SuiSentinel pipeline.

Given a transaction summary, classify it into exactly one of these categories:
fund_theft, verifier_bypass_theft, verifier_bypass_dos, cryptographic_theft, \
consensus_liveness, smart_contract, bridge, network_dos, unknown.

Definitions:
- fund_theft: unauthorized asset transfer/drain not caused by a verifier or crypto flaw.
- verifier_bypass_theft: an on-chain invariant/Move Prover guarantee was bypassed AND \
funds moved as a result.
- verifier_bypass_dos: a verifier/prover bypass that caused denial-of-service rather \
than theft (e.g. infinite loop, crash, gas exhaustion).
- cryptographic_theft: theft enabled by a cryptographic flaw (signature forgery, weak \
randomness, nonce reuse, key recovery).
- consensus_liveness: validator/consensus layer stall or fork-choice issue, no direct \
theft.
- smart_contract: a logic bug (reentrancy-equivalent, access control, object ownership \
race) not better described by the categories above.
- bridge: incident involving a cross-chain bridge or messaging protocol (e.g. LayerZero \
OFT, Wormhole).
- network_dos: network/RPC/mempool level denial-of-service, not contract-specific.
- unknown: insufficient signal to classify confidently.

Respond with ONLY a JSON object, no markdown, no preamble:
{"category": "<one of the labels above>", "confidence": <0-1 float>, "rationale": "<1-2 sentences>"}
"""


@dataclass
class ClassificationResult:
    category: ExploitCategory
    confidence: float
    rationale: str
    severity: int
    matched_signals: List[str] = field(default_factory=list)
    stage: str = "rule_based"  # "rule_based" | "llm"


def rule_based_prefilter(tx: TxEvent) -> Optional[ClassificationResult]:
    """Cheap keyword/heuristic pass. Returns a result only on a confident
    match; otherwise returns None so the agent can decide whether to
    escalate to the LLM stage."""
    blob = tx.text_blob
    best_category: Optional[ExploitCategory] = None
    best_hits: List[str] = []

    for category, signals in CATEGORY_SIGNALS.items():
        hits = [s for s in signals if s in blob]
        if len(hits) > len(best_hits):
            best_category, best_hits = category, hits

    if best_category and best_hits:
        return ClassificationResult(
            category=best_category,
            confidence=min(0.5 + 0.15 * len(best_hits), 0.9),
            rationale=f"Matched signal(s): {', '.join(best_hits)}",
            severity=CATEGORY_SEVERITY[best_category],
            matched_signals=best_hits,
            stage="rule_based",
        )
    return None


def should_escalate(tx: TxEvent, prefilter_result: Optional[ClassificationResult]) -> bool:
    """Decide whether a tx warrants the more expensive LLM classification."""
    if tx.status == "failure":
        return True
    if prefilter_result and prefilter_result.confidence < 0.75:
        return True
    if any(abs(int(bc.get("amount", 0))) > 10**9 for bc in tx.balance_changes):  # >1 SUI-ish raw units, tune per token decimals
        return True
    if prefilter_result is None:
        return False  # nothing suspicious at all, skip LLM call to save cost
    return False


LlmCaller = Callable[[str, str], str]  # (system_prompt, user_content) -> raw text response


def classify_with_llm(tx: TxEvent, llm_call: LlmCaller) -> ClassificationResult:
    """
    `llm_call` should send LLM_SYSTEM_PROMPT + the user content to your
    Anthropic client and return the raw text response. Example wiring:

        from anthropic import Anthropic
        client = Anthropic()
        def llm_call(system, user):
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return msg.content[0].text
    """
    user_content = json.dumps({
        "digest": tx.digest,
        "status": tx.status,
        "package_id": tx.package_id,
        "gas_used": tx.gas_used,
        "balance_changes": tx.balance_changes[:10],
        "events": [e.get("type") for e in tx.events][:10],
        "event_payloads": [e.get("parsedJson") for e in tx.events][:5],
    }, default=str)

    raw = llm_call(LLM_SYSTEM_PROMPT, user_content)
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        parsed = json.loads(cleaned)
        category = ExploitCategory(parsed["category"])
        return ClassificationResult(
            category=category,
            confidence=float(parsed.get("confidence", 0.5)),
            rationale=parsed.get("rationale", ""),
            severity=CATEGORY_SEVERITY[category],
            stage="llm",
        )
    except Exception as exc:
        logger.warning("LLM classification parse failed for %s: %s | raw=%r", tx.digest, exc, raw)
        return ClassificationResult(
            category=ExploitCategory.UNKNOWN, confidence=0.0,
            rationale="LLM response unparsable", severity=CATEGORY_SEVERITY[ExploitCategory.UNKNOWN],
            stage="llm",
        )


def classify(tx: TxEvent, llm_call: Optional[LlmCaller] = None) -> ClassificationResult:
    """Top-level entry point used by agent.py's orchestration loop."""
    prefilter_result = rule_based_prefilter(tx)

    if llm_call is not None and should_escalate(tx, prefilter_result):
        return classify_with_llm(tx, llm_call)

    return prefilter_result or ClassificationResult(
        category=ExploitCategory.UNKNOWN, confidence=0.0,
        rationale="No signals matched and LLM escalation skipped",
        severity=CATEGORY_SEVERITY[ExploitCategory.UNKNOWN],
        stage="rule_based",
    )
