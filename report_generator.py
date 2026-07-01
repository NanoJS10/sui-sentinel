from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

SEVERITY_META = {
    5: ("CRITICAL", "#ff4444", "#fff0f0"),
    4: ("HIGH",     "#ff8800", "#fff8f0"),
    3: ("MEDIUM",   "#ffcc00", "#fffdf0"),
    2: ("LOW",      "#4488ff", "#f0f4ff"),
    1: ("INFO",     "#888888", "#f8f8f8"),
}

RULE_DESCRIPTIONS = {
    "checked_shift_fn_declared": "Function shaped like overflow-guard helper -- the exact class where the Cetus checked_shlw bug ($223M) lived. Verify overflow threshold against bit-width.",
    "shift_operator": "Left-shift operation found. Verify there is a correct overflow guard before this line.",
    "large_literal_threshold": "Large numeric literal found, possibly an overflow threshold. Confirm it matches the correct bit-width cutoff.",
    "fee_reward_fn_declared": "Function computes fees/rewards AND contains arithmetic. Check rounding direction and division order.",
    "division_before_multiplication": "Division before multiplication -- integer division truncates. Correct order is (amount * rate) / denominator.",
    "raw_division_in_fee_fn": "Raw division inside fee/reward function. Check whether small inputs can truncate to zero.",
    "bps_percentage_scaling": "Basis-points/percentage terminology. Confirm scaling denominator matches documentation.",
}

def _severity_label(hint):
    return SEVERITY_META.get(hint, SEVERITY_META[1])

def _escape(text):
    return str(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def generate_html_report(findings_json, output_html="sui_sentinel_report.html", repo_name=""):
    data = json.loads(Path(findings_json).read_text())
    findings = data.get("findings", [])
    files_scanned = data.get("files_scanned", "?")
    scan_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not repo_name:
        repo_name = Path(findings_json).stem.replace("_findings","").replace("r_","")

    by_sev = {5:[],4:[],3:[],2:[],1:[]}
    rule_counts = {}
    for f in findings:
        sev = f.get("severity_hint", 1)
        by_sev.setdefault(sev,[]).append(f)
        rule_counts[f["rule"]] = rule_counts.get(f["rule"],0) + 1

    total = len(findings)
    crit = len(by_sev.get(5,[]))
    high = len(by_sev.get(4,[]))

    rows = ""
    for sev in [5,4,3,2,1]:
        for f in by_sev.get(sev,[]):
            label,color,bg = _severity_label(sev)
            rule = f.get("rule","")
            desc = RULE_DESCRIPTIONS.get(rule, f.get("note",""))
            rows += f'<tr style="background:{bg}"><td style="padding:8px;border:1px solid #ddd"><span style="background:{color};color:white;padding:2px 8px;border-radius:3px;font-size:12px">{label}</span></td><td style="padding:8px;border:1px solid #ddd;font-size:11px">{_escape(f.get("file",""))}</td><td style="padding:8px;border:1px solid #ddd;text-align:center">{f.get("line_no","")}</td><td style="padding:8px;border:1px solid #ddd"><code style="background:#f4f4f4;padding:2px 4px;font-size:11px;display:block">{_escape(f.get("line",""))}</code><span style="font-size:11px;color:#555">[{_escape(rule)}] {_escape(desc)}</span></td></tr>'

    srules = ""
    for rule,count in sorted(rule_counts.items(),key=lambda x:-x[1]):
        srules += f'<tr><td style="padding:6px 12px;border:1px solid #ddd">{_escape(rule)}</td><td style="padding:6px 12px;border:1px solid #ddd;text-align:center;font-weight:bold">{count}</td></tr>'

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>SuiSentinel Report - {_escape(repo_name)}</title>
<style>body{{font-family:-apple-system,sans-serif;margin:0;background:#f5f7fa}}
.hdr{{background:linear-gradient(135deg,#1a1a2e,#0f3460);color:white;padding:32px}}
.hdr h1{{margin:0 0 8px;font-size:26px}}.hdr p{{margin:4px 0;opacity:.8;font-size:13px}}
.box{{max-width:1100px;margin:0 auto;padding:20px}}
.card{{background:white;border-radius:8px;padding:20px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.card h2{{margin:0 0 14px;font-size:17px;border-bottom:2px solid #f0f0f0;padding-bottom:10px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}
.stat{{text-align:center;padding:16px;border-radius:8px}}
.stat-n{{font-size:32px;font-weight:bold}}.stat-l{{font-size:12px;opacity:.8}}
table{{width:100%;border-collapse:collapse}}th{{background:#f8f9fa;padding:8px 12px;border:1px solid #ddd;text-align:left;font-size:13px}}
.disc{{background:#fff8e1;border-left:4px solid #ffcc00;padding:10px 14px;border-radius:4px;font-size:13px;margin-top:14px}}
.ftr{{text-align:center;padding:20px;color:#888;font-size:12px}}</style></head>
<body>
<div class="hdr"><h1>SuiSentinel Security Report</h1>
<p>Static Move source analysis &mdash; <strong>{_escape(repo_name)}</strong></p>
<p>Generated: {scan_ts} &nbsp;|&nbsp; Files scanned: {files_scanned} &nbsp;|&nbsp; Total findings: {total} &nbsp;|&nbsp; SuiSentinel v0.3.0 by NanoJS Investigations</p></div>
<div class="box">
<div class="card"><h2>Summary</h2>
<div class="grid">
<div class="stat" style="background:#fff0f0"><div class="stat-n" style="color:#ff4444">{crit}</div><div class="stat-l" style="color:#ff4444">CRITICAL</div></div>
<div class="stat" style="background:#fff8f0"><div class="stat-n" style="color:#ff8800">{high}</div><div class="stat-l" style="color:#ff8800">HIGH</div></div>
<div class="stat" style="background:#f0f4ff"><div class="stat-n" style="color:#4488ff">{total-crit-high}</div><div class="stat-l" style="color:#4488ff">MED/LOW</div></div>
<div class="stat" style="background:#f0f8f0"><div class="stat-n" style="color:#44aa44">{files_scanned}</div><div class="stat-l" style="color:#44aa44">FILES</div></div>
</div>
<div class="disc">All findings are <em>candidates for manual review</em>, not confirmed vulnerabilities. Every flagged line requires human judgment.</div></div>
<div class="card"><h2>Findings by Rule</h2><table><tr><th>Rule</th><th>Count</th></tr>{srules if srules else "<tr><td colspan=2 style=padding:12px;text-align:center;color:#888>No findings</td></tr>"}</table></div>
<div class="card"><h2>All Findings</h2><table><tr><th style=width:80px>Severity</th><th>File</th><th style=width:50px;text-align:center>Line</th><th>Code & Explanation</th></tr>{rows if rows else "<tr><td colspan=4 style=padding:20px;text-align:center;color:#44aa44;font-size:15px>No findings</td></tr>"}</table></div>
<div class="card"><h2>About</h2><p style="font-size:13px;color:#555">SuiSentinel is open-source Sui Move security tooling by <strong>NanoJS Investigations (NanoJS10)</strong>. Tested against 7 real Sui protocols. Correctly identified the checked_shlw function class responsible for the $223M Cetus exploit.</p>
<p style="font-size:12px;color:#888">GitHub: github.com/NanoJS10/sui-sentinel &nbsp;|&nbsp; Contact: nanojs@proton.me &nbsp;|&nbsp; X: @NanoJS10</p></div>
</div>
<div class="ftr">SuiSentinel v0.3.0 &mdash; NanoJS Investigations &mdash; {scan_ts}<br><span style="font-size:10px">For informational purposes only. Not a formal security audit.</span></div>
</body></html>"""

    out = Path(output_html)
    out.write_text(html)
    return out
