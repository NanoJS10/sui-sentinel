"""
simulator.py — Exploit simulation.

Goal: before (or immediately after) a suspicious tx lands on mainnet, replay
it — or fuzzed variants of it — against a local fork so we can quantify
worst-case impact and confirm whether a flagged pattern is actually
exploitable, not just suspicious-looking.

This wraps the `sui` CLI's local network / replay tooling. It is
intentionally a thin subprocess wrapper: the heavy lifting (state fork,
execution) is delegated to Sui's own tooling rather than reimplemented,
since reimplementing a Move VM here would be both wasteful and unreliable.

Requires: `sui` CLI on PATH, and either a local `sui-test-validator` or
`cfg.simulation_fork_url` pointing at one.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from .config import SuiSentinelConfig
from .monitor import TxEvent

logger = logging.getLogger("sui_sentinel.simulator")


@dataclass
class SimulationResult:
    digest: str
    ran: bool
    success: bool
    estimated_impact_note: str
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)


class ExploitSimulator:
    def __init__(self, cfg: SuiSentinelConfig):
        self.cfg = cfg
        self._sui_bin = shutil.which("sui")

    def available(self) -> bool:
        return self._sui_bin is not None and bool(self.cfg.simulation_fork_url)

    def replay_transaction(self, tx: TxEvent) -> SimulationResult:
        """Dry-runs the transaction's effects against the fork using
        `sui client replay-transaction` (or `sui_dryRunTransactionBlock`
        on the fork RPC if the CLI subcommand is unavailable in your sui
        version — swap as needed)."""
        if not self.available():
            return SimulationResult(
                digest=tx.digest, ran=False, success=False,
                estimated_impact_note=(
                    "Simulator unavailable: install `sui` CLI and set "
                    "SuiSentinelConfig.simulation_fork_url to a local "
                    "sui-test-validator RPC endpoint."
                ),
            )

        cmd = [
            self._sui_bin, "client", "replay-transaction",
            "--tx-digest", tx.digest,
            "--rpc", self.cfg.simulation_fork_url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return SimulationResult(
                digest=tx.digest, ran=True, success=False,
                estimated_impact_note="Replay timed out — possible DoS/infinite-loop pattern.",
                errors=["timeout"],
            )
        except Exception as exc:
            return SimulationResult(
                digest=tx.digest, ran=False, success=False,
                estimated_impact_note=f"Replay invocation failed: {exc}",
                errors=[str(exc)],
            )

        success = proc.returncode == 0
        note = "Replay completed; inspect raw_output for effects/events delta." if success \
            else "Replay failed — see errors. May indicate fork desync or genuinely broken tx."
        return SimulationResult(
            digest=tx.digest, ran=True, success=success,
            estimated_impact_note=note,
            raw_output=proc.stdout, errors=[proc.stderr] if proc.stderr else [],
        )

    def fuzz_function(self, package_id: str, module: str, function: str,
                       arg_templates: List[list], max_runs: int = 20) -> List[SimulationResult]:
        """
        Pre-attack simulation: try a batch of boundary-value argument sets
        (zero, max-int, empty vector, duplicate object IDs, etc.) against a
        target entry function on the fork to surface unhandled-input
        vulnerabilities before an attacker does. `arg_templates` is a list
        of argument-list variants the caller constructs (kept generic here
        since Move call signatures vary per contract).
        """
        results: List[SimulationResult] = []
        if not self.available():
            results.append(SimulationResult(
                digest="fuzz", ran=False, success=False,
                estimated_impact_note="Simulator unavailable (see replay_transaction)."))
            return results

        for i, args in enumerate(arg_templates[:max_runs]):
            cmd = [
                self._sui_bin, "client", "call",
                "--package", package_id, "--module", module, "--function", function,
                "--args", *[str(a) for a in args],
                "--rpc", self.cfg.simulation_fork_url,
                "--dry-run",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                results.append(SimulationResult(
                    digest=f"fuzz-{i}", ran=True, success=proc.returncode == 0,
                    estimated_impact_note="Dry-run call completed.",
                    raw_output=proc.stdout, errors=[proc.stderr] if proc.stderr else [],
                ))
            except Exception as exc:
                results.append(SimulationResult(
                    digest=f"fuzz-{i}", ran=False, success=False,
                    estimated_impact_note=f"Fuzz call failed: {exc}", errors=[str(exc)],
                ))
        return results
