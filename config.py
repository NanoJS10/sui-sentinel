"""
config.py — taxonomy, thresholds, and runtime configuration for SuiSentinel.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class ExploitCategory(str, Enum):
    """Classification labels used by the exploit-classifier agent."""
    FUND_THEFT = "fund_theft"
    VERIFIER_BYPASS_THEFT = "verifier_bypass_theft"
    VERIFIER_BYPASS_DOS = "verifier_bypass_dos"
    CRYPTOGRAPHIC_THEFT = "cryptographic_theft"
    CONSENSUS_LIVENESS = "consensus_liveness"
    SMART_CONTRACT = "smart_contract"
    BRIDGE = "bridge"
    NETWORK_DOS = "network_dos"
    UNKNOWN = "unknown"


# Severity weighting per category — drives alert routing/escalation in alerting.py
CATEGORY_SEVERITY: Dict[ExploitCategory, int] = {
    ExploitCategory.FUND_THEFT: 5,
    ExploitCategory.BRIDGE: 5,
    ExploitCategory.CRYPTOGRAPHIC_THEFT: 5,
    ExploitCategory.VERIFIER_BYPASS_THEFT: 5,
    ExploitCategory.VERIFIER_BYPASS_DOS: 4,
    ExploitCategory.CONSENSUS_LIVENESS: 4,
    ExploitCategory.NETWORK_DOS: 3,
    ExploitCategory.SMART_CONTRACT: 3,
    ExploitCategory.UNKNOWN: 1,
}

# Keyword / heuristic signals used by the rule-based pre-filter before
# escalating to the LLM-based classifier agent (cheap first pass).
CATEGORY_SIGNALS: Dict[ExploitCategory, List[str]] = {
    ExploitCategory.FUND_THEFT: [
        "unauthorized transfer", "drain", "withdraw_all", "balance_of exploit",
        "unexpected outflow", "treasury cap misuse",
    ],
    ExploitCategory.VERIFIER_BYPASS_THEFT: [
        "move prover bypass", "invariant violated", "signature check skipped",
        "auth bypass", "capability forged",
    ],
    ExploitCategory.VERIFIER_BYPASS_DOS: [
        "prover timeout", "verifier crash", "infinite loop", "gas exhaustion proof",
    ],
    ExploitCategory.CRYPTOGRAPHIC_THEFT: [
        "signature forgery", "weak randomness", "nonce reuse", "ed25519 fault",
        "hash collision", "key recovery",
    ],
    ExploitCategory.CONSENSUS_LIVENESS: [
        "validator stall", "checkpoint delay", "narwhal", "bullshark", "fork choice",
        "epoch change failure",
    ],
    ExploitCategory.SMART_CONTRACT: [
        "reentrancy", "integer overflow", "access control", "object ownership bug",
        "shared object race", "fee miscalculation", "reward miscalculation",
        "rounding exploit", "precision loss", "division before multiplication",
        "rebase exploit", "yield manipulation",
    ],
    ExploitCategory.BRIDGE: [
        "wormhole", "layerzero", "bridge relayer", "oft", "cross-chain message",
        "mint without lock", "double spend bridge",
    ],
    ExploitCategory.NETWORK_DOS: [
        "spam transactions", "mempool flood", "rpc overload", "checkpoint backlog",
    ],
}


@dataclass
class SuiSentinelConfig:
    sui_rpc_url: str = "https://fullnode.mainnet.sui.io:443"
    sui_ws_url: str = "wss://fullnode.mainnet.sui.io:443"
    explorer_api_url: str = "https://suiscan.xyz/api"  # placeholder, swap for chosen explorer API
    poll_interval_seconds: int = 15
    risk_score_alert_threshold: float = 0.65  # 0-1 scale, see explorer_integration.py
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    move_prover_path: str = "move-prover"  # CLI binary, must be on PATH
    simulation_fork_url: str = ""  # local sui-test-validator fork RPC, if used
    watchlist_packages: List[str] = field(default_factory=list)  # Move package IDs to watch
    log_dir: str = "./sui_sentinel_logs"
