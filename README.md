# SuiSentinel

Agentic exploit-detection workflow for Sui, built standalone alongside
nanojs-pipeline. Implements, as discrete pluggable modules:

| Module | Maps to funded tooling area |
|---|---|
| `monitor.py` | Exploit monitoring & alerting |
| `explorer_integration.py` | Explorer-integrated tools (tx graphs, wallet risk scores, attribution) |
| `simulator.py` | Exploit simulation |
| `classifier.py` | Crowdsourced-style AI bugfinding (rule-based + LLM agent classification) |
| `templates/secure_by_default_template.move` | Secure-by-default contract template |
| `agent.py` | Orchestrator — the agentic loop |

Move Prover integration is referenced via `cfg.move_prover_path` (CLI path)
for teams wanting to wire formal verification checks into the same
pipeline; the simulator currently focuses on dynamic replay/fuzzing rather
than re-implementing the Prover itself.

## Classification taxonomy
`config.py: ExploitCategory` — fund_theft, verifier_bypass_theft,
verifier_bypass_dos, cryptographic_theft, consensus_liveness,
smart_contract, bridge, network_dos, unknown.

# SuiSentinel

Agentic exploit-detection workflow for Sui, built standalone alongside
nanojs-pipeline. Implements, as discrete pluggable modules:

| Module | Maps to funded tooling area |
|---|---|
| `static_scanner.py` | Formal verification / pre-deployment audit support (static, no network) |
| `monitor.py` | Exploit monitoring & alerting (live, on-chain) |
| `explorer_integration.py` | Explorer-integrated tools (tx graphs, wallet risk scores, attribution) |
| `simulator.py` | Exploit simulation |
| `classifier.py` | Crowdsourced-style AI bugfinding (rule-based + LLM agent classification) |
| `templates/secure_by_default_template.move` | Secure-by-default contract template |
| `agent.py` | Orchestrator — the agentic loop (live-monitoring path only) |

`static_scanner.py` and the `monitor.py`/`agent.py` live-monitoring path are
two separate entry points covering different points in a contract's
lifecycle: static_scanner runs **pre-deployment** against source code
(no RPC, no network, no cost), while monitor/agent runs **post-deployment**
against live on-chain transactions. Both write to the same
`sui_sentinel_logs/events.jsonl` file (tagged by `"source"`), so a single
downstream report generator can read findings from either path.

Move Prover integration is referenced via `cfg.move_prover_path` (CLI path)
for teams wanting to wire formal verification checks into the same
pipeline; the simulator currently focuses on dynamic replay/fuzzing rather
than re-implementing the Prover itself, and static_scanner is a heuristic
regex-based pre-filter, not a Prover replacement.

## Classification taxonomy
`config.py: ExploitCategory` — fund_theft, verifier_bypass_theft,
verifier_bypass_dos, cryptographic_theft, consensus_liveness,
smart_contract, bridge, network_dos, unknown.

## Quickstart

```bash
pip install -r requirements.txt
```

**Static scan (pre-deployment, no network, free):**
```bash
python -m sui_sentinel.main --scan-source /path/to/move/repo --json findings.json
```

**Live monitoring (post-deployment, requires RPC + optional Telegram):**
```bash
export SUI_RPC_URL="https://fullnode.mainnet.sui.io:443"
export SUI_SENTINEL_TELEGRAM_TOKEN="..."
export SUI_SENTINEL_TELEGRAM_CHAT_ID="..."
export ANTHROPIC_API_KEY="..."   # optional, enables LLM-stage classification (paid)

python -m sui_sentinel.main --watch 0xYOUR_PACKAGE_ID --iterations 5
```

Dry-run against a saved sample transaction (no polling, no network):
```bash
python -m sui_sentinel.main --dry-run-sample sample_tx.json
```

## Design notes
- **Agentic, not blind-polling**: the classifier decides per-tx whether to
  escalate to the LLM (cost control), and the orchestrator decides per-tx
  whether to run a fork simulation (compute control) — both gated on
  severity/confidence rather than running every expensive step on every
  transaction.
- **Pluggable, not monolithic**: `llm_call`, `screening_lookup` (OFAC/Chainabuse,
  reuse your `nanojs_enrichment.py` logic), and the RPC client are all
  injected, so this drops next to nanojs-pipeline without import collisions.
- **Static and live paths are independent**: you can run `--scan-source`
  with zero setup (no RPC, no Telegram, no API key) before ever touching
  the live-monitoring path. Get the free, offline half working first.
- **Logs to JSONL** (`sui_sentinel_logs/events.jsonl`) for downstream
  reporting (e.g. feeding into your existing Word report generator).

## Known limitations (read before treating findings as conclusions)
- `static_scanner.py` is regex-based, not a real Move parser/AST walk. It
  will produce false positives and can miss obfuscated or restructured
  versions of the same bug class. Every finding is a candidate for manual
  review, not a confirmed vulnerability.
- `classifier.py`'s rule-based prefilter relies on keyword matching against
  event payloads/types — it will miss exploits that don't surface obvious
  keywords, and the LLM escalation stage costs money (Anthropic API) once
  enabled.
- `simulator.py` shells out to external CLI tools (`sui`, optionally
  `move-prover`) via subprocess — these must be installed and on PATH
  separately; this repo does not bundle them.
- None of this has been run against real, sustained mainnet traffic yet.
  Treat this as a v0.2 development build, not production-hardened software.

