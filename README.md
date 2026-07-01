# SuiSentinel

**Sui Move static security scanner and live exploit monitor — by NanoJS Investigations (NanoJS10)**

A two-stage security pipeline for the Sui ecosystem: pre-deployment static analysis for known Move exploit patterns, and post-deployment live transaction monitoring with wallet risk scoring and Telegram alerting. Built alongside nanojs-pipeline, tested against 7 real Sui protocols.

---

## Why this exists

On May 22, 2025, the Cetus Protocol was exploited for $223M via a single integer overflow bug in a shared math library — a function called `checked_shlw` with a wrong overflow threshold constant. Three other protocols (Kriya, Momentum, Bluefin) had shared exposure to the same library.

SuiSentinel was built to answer one question: can a lightweight heuristic scanner identify this class of bug before deployment, and correctly distinguish it from safe implementations after the fact?

The answer, based on real testing, is yes — with important caveats documented below.

---

## Case study: checked_shlw — the $223M function

This is the core finding that validates the scanner's approach.

**Cetus (vulnerable):** `checked_shlw` used a hardcoded decimal constant as its overflow threshold. The constant was wrong — it allowed values through that should have been rejected, letting the attacker overflow the math and mint unlimited liquidity.

**Bluefin (fixed):** After the Cetus exploit, Bluefin built their own integer library and reimplemented `checked_shlw` using `let mask = 1 << 192` — the mathematically correct threshold for a 64-bit left shift on u256 (since 256 - 64 = 192). They also wrote a formal verification spec proving correctness:

```
#[spec(prove, target = checked_shlw)]
public fun checked_shlw_spec(n: u256): (u256, bool) {
    let (result, overflow) = checked_shlw(n);
    let n_shifted = n.to_int().shl(64u64.to_int());
    if (n_shifted.gt(std::u256::max_value!().to_int())) {
        ensures(overflow == true);
        ensures(result == 0);
    } else {
        ensures(overflow == false);
        ensures(result == n_shifted.to_u256());
    };
}
```

**SuiSentinel flagged `checked_shlw` in both.** Human review confirmed the difference. That is exactly the intended workflow: scanner finds the right location, human determines whether it is safe or dangerous. The scanner is not a replacement for review — it is a tool to focus review on the right lines.

---

## Testing results — 7 protocols scanned

All scans run on July 1, 2026 against public GitHub repos using SuiSentinel v0.3.0.

| Protocol | checked_shift_fn | div_before_mul | Notes |
|---|---|---|---|
| integer-mate (Cetus pre-patch) | 16 TRUE POSITIVES | 0 | Caught the exact Cetus bug function class |
| cetus-clmm-interface (patched) | 0 TRUE NEGATIVES | 0 | Correctly clean after patch |
| deepbookv3 (MystenLabs) | 0 | 0 | Clean — heavily audited |
| sui-lending-protocol (Scallop) | 0 | 4 (false pos) | Uses fixed_point32_empower safely |
| navi-smart-contracts (NAVI) | 0 | 4 (false pos) | Fixed-point math throughout |
| sui-defi (Interest Protocol) | 0 | 0 | Clean, intentional bit ops in i256 lib |
| integer-library (Bluefin) | 2 TRUE POSITIVES | 0 | Found checked_shlw — formally verified as safe |

**False positive sources discovered and fixed through testing:**
- Test files (`tests/`, `test/` directories) — filtered out
- Vendor/oracle integrations (`vendors/`, `switchboard_sui/`, etc.) — filtered out
- Single-line `//` comments containing division symbols — stripped before analysis
- Formulas inside `/* */` block comments — partially stripped (multi-line blocks remain a known gap)
- `FlashLoanMultiple` matching `shl` via case-insensitive regex — regex tightened to require explicit `shl` naming

---

## What it can do right now

**Static scanning — pre-deployment, free, no network**

```bash
pip install -r requirements.txt
python3 -m sui_sentinel.main --scan-source /path/to/move/repo --json findings.json
```

Detects:
- Functions shaped like overflow-guard helpers (the Cetus `checked_shlw` pattern)
- Left-shift operations, weighted by context
- Suspiciously large numeric literals (possible wrong overflow thresholds)
- Fee, reward, interest, payout, staking, and yield functions
- Division-before-multiplication inside those functions (precision loss)
- Raw division inside fee functions (truncation-to-zero risk)
- Basis-points and percentage terminology (scaling factor errors)

Automatically skips: test files, vendor directories, oracle integrations, block and line comments, safe fixed-point math library calls (`fixed_point32`, `math::div`, etc.)

Every finding includes: file path, line number, rule name, explanation, and an advisory severity 1-5.

**Live monitoring — post-deployment, requires Sui RPC**

```bash
export SUI_RPC_URL="https://fullnode.mainnet.sui.io:443"
export SUI_SENTINEL_TELEGRAM_TOKEN="your_token"
export SUI_SENTINEL_TELEGRAM_CHAT_ID="your_chat_id"
# Optional — enables LLM classification (costs money, off by default):
# export ANTHROPIC_API_KEY="..."

python3 -m sui_sentinel.main --watch 0xYOUR_PACKAGE_ID
```

Polls the Sui full node every 15 seconds for transactions touching the watchlisted package. For each transaction runs: rule-based keyword classification (free), optional LLM escalation for suspicious transactions, wallet risk scoring (velocity + counterparty fan-out + optional OFAC/Chainabuse screening), and Telegram alerting above the severity threshold.

**Dry run — test the pipeline without live network:**
```bash
python3 -m sui_sentinel.main --dry-run-sample sample_tx.json
```

Both paths write to `sui_sentinel_logs/events.jsonl` tagged by source, so one report generator reads everything.

---

## Module map

| Module | Purpose |
|---|---|
| `static_scanner.py` | Pre-deployment Move source scanner |
| `monitor.py` | Live transaction polling via Sui JSON-RPC |
| `classifier.py` | Two-stage exploit classifier (rule-based + optional LLM) |
| `explorer_integration.py` | Wallet risk scoring and transaction graph builder |
| `simulator.py` | Exploit simulation via `sui` CLI subprocess |
| `alerting.py` | Telegram alert delivery |
| `agent.py` | Orchestrator — wires all live-monitoring modules together |
| `config.py` | Exploit taxonomy, severity weights, signal keywords |
| `templates/secure_by_default_template.move` | Baseline Move contract template |

Classification categories: `fund_theft`, `verifier_bypass_theft`, `verifier_bypass_dos`, `cryptographic_theft`, `consensus_liveness`, `smart_contract`, `bridge`, `network_dos`, `unknown`.

---

## Known limitations

- `static_scanner.py` is regex-based, not a real Move AST parser. It cannot understand Move's type system, so it cannot automatically distinguish raw integer division from safe fixed-point library calls — those require human review. Every finding is a candidate, not a confirmed vulnerability.
- Multi-line `/* */` block comments are not fully stripped — formulas documented in multi-line comments can still trigger false positives.
- The live monitoring path has not been tested against sustained mainnet traffic. Treat it as a working prototype, not production-hardened software.
- `simulator.py` requires the `sui` CLI binary installed separately and on PATH.
- LLM classification (`classifier.py` escalation stage) costs money via the Anthropic API and is off by default.

---

## Roadmap

- Phase 2: Sui wallet clustering and fund-tracing module (porting nanojs-pipeline Ethereum clustering to Sui's object model via GraphQL RPC)
- Phase 3: Multi-line block comment stripping and fixed-point library context awareness
- Phase 4: Move Prover integration for formal verification of flagged functions

---

## About

Built by **NanoJS10 / NanoJS Investigations** — independent blockchain forensic investigator.

Previous cases: NanoJS01 MerlinDEX ($1.82M, zkSync Era), NanoJS02 Zunami Protocol ($2.1M, flash loan), NanoJS03 Unizen Protocol ($2.1M, unsafe external call), NanoJS-FixerSell01 (live rugpull caught), NanoJS-PhishFactory01 (14+ coordinated attacker wallets).

Contact: nanojs@proton.me | x.com/NanoJS10
