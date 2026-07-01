"""
main.py — CLI entrypoint.

Usage:
    python -m sui_sentinel.main --watch 0xPACKAGE_ID [0xPACKAGE_ID2 ...]
    python -m sui_sentinel.main --dry-run-sample sample_tx.json
    python -m sui_sentinel.main --scan-source /path/to/move/repo [--json out.json]

--scan-source runs the static, pre-deployment scanner (static_scanner.py)
against a directory of .move source files. No network calls, no RPC, no
watchlist needed -- this is the offline counterpart to --watch. Findings
are also appended to the same events.jsonl log as live-monitoring alerts
(tagged "source": "static_scanner") so one report generator can read both.

Configure via environment variables or edit SuiSentinelConfig defaults:
    SUI_RPC_URL, SUI_SENTINEL_TELEGRAM_TOKEN, SUI_SENTINEL_TELEGRAM_CHAT_ID,
    SUI_SENTINEL_FORK_URL
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

from .agent import SentinelAgent
from .config import SuiSentinelConfig
from .monitor import TxEvent
from . import static_scanner
from . import report_generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def build_config(watchlist: list[str]) -> SuiSentinelConfig:
    return SuiSentinelConfig(
        sui_rpc_url=os.environ.get("SUI_RPC_URL", SuiSentinelConfig.sui_rpc_url),
        telegram_bot_token=os.environ.get("SUI_SENTINEL_TELEGRAM_TOKEN", ""),
        telegram_chat_id=os.environ.get("SUI_SENTINEL_TELEGRAM_CHAT_ID", ""),
        simulation_fork_url=os.environ.get("SUI_SENTINEL_FORK_URL", ""),
        watchlist_packages=watchlist,
    )


def make_llm_caller():
    """Optional: wires up the Anthropic SDK if installed and ANTHROPIC_API_KEY
    is set. Returns None otherwise, in which case the agent runs rule-based
    classification only."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        from anthropic import Anthropic
    except ImportError:
        logging.warning("anthropic package not installed; running rule-based classification only.")
        return None

    client = Anthropic()

    def llm_call(system: str, user: str) -> str:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=300,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    return llm_call


def main():
    parser = argparse.ArgumentParser(description="SuiSentinel — agentic Sui exploit detection")
    parser.add_argument("--watch", nargs="+", default=[], help="Move package IDs to watch")
    parser.add_argument("--iterations", type=int, default=None,
                         help="Stop after N poll iterations (omit to run forever)")
    parser.add_argument("--dry-run-sample", type=str, default=None,
                         help="Path to a sample tx JSON (Sui suix_queryTransactionBlocks "
                              "single-result shape) to run through the pipeline once, no polling")
    parser.add_argument("--scan-source", type=str, default=None,
                         help="Path to a directory of .move source files to statically scan "
                              "(pre-deployment, no network calls)")
    parser.add_argument("--json", type=str, default=None,
                         help="With --scan-source, also write findings to this JSON file")
    parser.add_argument("--report", type=str, default=None, help="Path to findings JSON")
    parser.add_argument("--out", type=str, default="sui_sentinel_report.html", help="HTML output path")
    args = parser.parse_args()

    if args.report:
        from pathlib import Path as _P
        if not _P(args.report).exists():
            parser.error(f"not found: {args.report}")
        repo = _P(args.report).stem.replace("_findings","").replace("r_","")
        out = report_generator.generate_html_report(args.report, args.out, repo)
        print(f"Report written to {out}")
        return

    if args.scan_source:
        root = Path(args.scan_source)
        if not root.exists():
            parser.error(f"--scan-source path does not exist: {root}")
        result = static_scanner.scan_directory(root)
        static_scanner.print_human(result)
        cfg = build_config([])
        log_path = static_scanner.log_results(result, log_dir=cfg.log_dir)
        print(f"Findings appended to {log_path}")
        if args.json:
            out = {
                "files_scanned": result.files_scanned,
                "findings": [f.__dict__ for f in result.findings],
            }
            Path(args.json).write_text(json.dumps(out, indent=2))
            print(f"JSON report written to {args.json}")
        return

    if args.dry_run_sample:
        from .monitor import _parse_tx
        with open(args.dry_run_sample) as f:
            raw = json.load(f)
        tx = _parse_tx(raw)
        tx.package_id = "dry-run"
        cfg = build_config([])
        agent = SentinelAgent(cfg, llm_call=make_llm_caller())
        agent.handle_event(tx)
        print(f"Logged to {cfg.log_dir}/events.jsonl")
        return

    if not args.watch:
        parser.error("--watch requires at least one package ID (or use --dry-run-sample)")

    cfg = build_config(args.watch)
    agent = SentinelAgent(cfg, llm_call=make_llm_caller())
    agent.run(stop_after_iterations=args.iterations)


if __name__ == "__main__":
    main()
