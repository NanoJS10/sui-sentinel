"""
static_scanner.py — pre-deployment static scanner (Phase 1, source-level).

This is the static-analysis counterpart to monitor.py's live transaction
watching: instead of watching deployed packages for exploit-shaped
transactions, this scans Move *source* before deployment for patterns
resembling known exploit classes -- currently just the Cetus-style unsafe
shift/overflow pattern (CVE-equivalent: integer-mate's checked_shlw bug,
May 2025, ~$223M).

Deliberately heuristic (regex-based), not a real Move parser/AST walk.
Findings are candidates for manual review, not confirmed bugs -- same
posture as the rule-based pre-filter in classifier.py: cheap, fast,
high-recall first pass.

Designed to plug into the same JSONL logging convention as agent.py so
scan results and live-monitoring results can be merged into one report
by your existing Word report generator.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

logger = logging.getLogger("sui_sentinel.static_scanner")


# ---------------------------------------------------------------------------
# Detection patterns (v0.1, heuristic). Extend as you learn more Move or
# encounter new exploit classes worth detecting statically.
# ---------------------------------------------------------------------------

SHIFT_PATTERN = re.compile(r"<<\s*\d+|<<\s*[a-zA-Z_]\w*")

CHECKED_SHIFT_FN_PATTERN = re.compile(
    r"fun\s+(checked_shl\w*|safe_shl\w*|\w*shl\w*)\s*\(", re.IGNORECASE
)

LARGE_LITERAL_PATTERN = re.compile(r"\b\d{15,}\b")

# Functions whose names suggest they compute fees, rewards, interest, or
# payouts -- high-value targets historically (reward/fee math errors are
# one of the most common real-world DeFi bug classes, alongside overflow).
FEE_REWARD_FN_PATTERN = re.compile(
    r"fun\s+(\w*(?:fee|reward|payout|distribute|claim_\w*|stake\w*|"
    r"unstake\w*|yield|apr|apy|interest|rebase|mint_to|withdraw_\w*)\w*)\s*\(",
    re.IGNORECASE,
)

# Division appearing before a multiplication on the same or a nearby line --
# classic precision-loss pattern (a / b * c truncates before scaling, often
# losing significant value at small a or large c). Heuristic: division
# operator followed later on the line by a multiplication operator.
DIVISION_BEFORE_MULT_PATTERN = re.compile(r"/[^/*\n]*\*")

# Basis-points / percentage-style scaling without an obvious denominator
# constant nearby (10000, 1000, 100) -- common source of off-by-factor-of-10
# bugs in fee calculations.
BPS_PATTERN = re.compile(r"\b(bps|basis_points?|percent(?:age)?)\b", re.IGNORECASE)

# Raw division that could silently truncate to zero for small inputs --
# flagged only when it appears inside a fee/reward-named function (see
# in_fee_reward_fn tracking below), since division itself is everywhere
# and not inherently a bug outside that context.
DIVISION_PATTERN = re.compile(r"[^/]/[^/]")


@dataclass
class StaticFinding:
    file: str
    line_no: int
    line: str
    rule: str
    note: str
    severity_hint: int = 2  # 1-5, advisory only -- mirrors classifier.py severity scale


@dataclass
class StaticScanResult:
    files_scanned: int = 0
    findings: List[StaticFinding] = field(default_factory=list)


def scan_file(path: Path) -> List[StaticFinding]:
    findings: List[StaticFinding] = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return findings

    lines = text.splitlines()
    in_shift_fn = False
    fn_brace_depth = 0
    in_fee_reward_fn = False
    fee_fn_name = ""
    fee_fn_brace_depth = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        code_only = stripped.split('//')[0].strip()

        fn_match = CHECKED_SHIFT_FN_PATTERN.search(stripped)
        if fn_match:
            in_shift_fn = True
            fn_brace_depth = 0
            findings.append(StaticFinding(
                file=str(path), line_no=i, line=stripped,
                rule="checked_shift_fn_declared",
                note=(f"Function '{fn_match.group(1)}' looks like a checked-shift "
                      "helper -- the exact shape of function where the Cetus "
                      "checked_shlw bug lived. Verify the overflow threshold "
                      "against the actual bit-width being shifted."),
                severity_hint=4,
            ))

        fee_fn_match = FEE_REWARD_FN_PATTERN.search(stripped)
        if fee_fn_match:
            in_fee_reward_fn = True
            fee_fn_name = fee_fn_match.group(1)
            fee_fn_brace_depth = 0
            findings.append(StaticFinding(
                file=str(path), line_no=i, line=stripped,
                rule="fee_reward_fn_declared",
                note=(f"Function '{fee_fn_name}' looks like it computes fees, "
                      "rewards, interest, or payouts. These are high-value "
                      "manual-review targets: check rounding direction "
                      "(who absorbs dust -- protocol or user?), division "
                      "order, and whether small inputs can truncate to a "
                      "free/zero-cost operation."),
                severity_hint=3,
            ))

        if in_shift_fn:
            fn_brace_depth += stripped.count("{") - stripped.count("}")
            if fn_brace_depth <= 0 and "{" in "".join(lines[max(0, i - 5):i]):
                in_shift_fn = False

        if in_fee_reward_fn:
            fee_fn_brace_depth += stripped.count("{") - stripped.count("}")

            if DIVISION_BEFORE_MULT_PATTERN.search(code_only):
                findings.append(StaticFinding(
                    file=str(path), line_no=i, line=stripped,
                    rule="division_before_multiplication",
                    note=(f"Inside '{fee_fn_name}': division appears before a "
                          "multiplication on this line. Integer division "
                          "truncates -- dividing before scaling up loses "
                          "precision that multiplying first would preserve. "
                          "Verify operation order is (amount * rate) / "
                          "denominator, not (amount / denominator) * rate."),
                    severity_hint=4,
                ))

            if DIVISION_PATTERN.search(code_only) and not DIVISION_BEFORE_MULT_PATTERN.search(code_only):
                findings.append(StaticFinding(
                    file=str(path), line_no=i, line=stripped,
                    rule="raw_division_in_fee_fn",
                    note=(f"Inside '{fee_fn_name}': raw division found. Check "
                          "whether small input amounts can cause this to "
                          "truncate to zero (e.g. a fee that rounds down to "
                          "nothing below some threshold, letting users dodge "
                          "it entirely by transacting in small increments)."),
                    severity_hint=2,
                ))

            if BPS_PATTERN.search(code_only):
                findings.append(StaticFinding(
                    file=str(path), line_no=i, line=stripped,
                    rule="bps_percentage_scaling",
                    note=(f"Inside '{fee_fn_name}': basis-points/percentage "
                          "terminology found. Confirm the scaling denominator "
                          "actually matches what's documented (10000 for bps, "
                          "100 for percent) -- off-by-factor-of-10 errors here "
                          "are a common real-world fee/reward bug."),
                    severity_hint=3,
                ))

            if fee_fn_brace_depth <= 0 and "{" in "".join(lines[max(0, i - 5):i]):
                in_fee_reward_fn = False

        if SHIFT_PATTERN.search(stripped):
            findings.append(StaticFinding(
                file=str(path), line_no=i, line=stripped,
                rule="shift_operator",
                note=("Left-shift operation found."
                      + (" INSIDE a checked-shift-named function -- high "
                         "priority for manual review." if in_shift_fn else
                         " Verify there is a correct overflow guard before "
                         "this line.")),
                severity_hint=4 if in_shift_fn else 2,
            ))

        if LARGE_LITERAL_PATTERN.search(stripped):
            findings.append(StaticFinding(
                file=str(path), line_no=i, line=stripped,
                rule="large_literal_threshold",
                note=("Large numeric literal found, possibly an overflow "
                      "threshold/bound. Confirm it matches the correct "
                      "bit-width cutoff for the type being checked "
                      "(e.g. 1 << 192 for a u256 shifted by 64)."),
                severity_hint=3,
            ))

    return findings


def scan_directory(root: Path) -> StaticScanResult:
    result = StaticScanResult()
    for path in root.rglob("*.move"):
        if any(part in {"tests", "test", "vendors", "vendor", "sui_x_oracle", "pyth_rule", "switchboard_rule", "supra_rule", "wormhole"} for part in path.parts):
            continue
        if any(part in {"tests", "test", "vendors", "vendor", "sui_x_oracle", "pyth_rule", "switchboard_rule", "supra_rule", "wormhole"} for part in path.parts):
            continue
        result.files_scanned += 1
        result.findings.extend(scan_file(path))
    return result


def log_results(result: StaticScanResult, log_dir: str = "./sui_sentinel_logs") -> Path:
    """Writes findings to the same events.jsonl convention agent.py uses,
    so a single downstream report generator can read both live-monitoring
    alerts and static-scan findings from one file."""
    import os
    os.makedirs(log_dir, exist_ok=True)
    path = Path(log_dir) / "events.jsonl"
    with open(path, "a") as f:
        for finding in result.findings:
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": "static_scanner",
                "finding": asdict(finding),
            }
            f.write(json.dumps(record, default=str) + "\n")
    return path


def print_human(result: StaticScanResult) -> None:
    print(f"\nScanned {result.files_scanned} .move file(s).")
    print(f"Found {len(result.findings)} candidate flag(s).\n")

    if not result.findings:
        print("No candidates found. (This does not mean the code is safe -- "
              "it means this v0.1 heuristic scanner found nothing. Expand "
              "the rules as you learn more Move.)")
        return

    by_file = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    for file, flags in by_file.items():
        print(f"--- {file} ---")
        for f in sorted(flags, key=lambda x: x.line_no):
            print(f"  L{f.line_no:<5} [{f.rule}] severity~{f.severity_hint}")
            print(f"          {f.line}")
            print(f"          -> {f.note}")
        print()
