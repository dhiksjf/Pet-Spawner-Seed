"""Report generator (spec 28): markdown + self-contained HTML, real evidence."""
from __future__ import annotations

import html
import time

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "information": 3}


def build_report(app, *, scope_hosts: list[str] | None = None,
                 include_ai: bool = True, redact_secrets: bool = False) -> dict:
    findings = app.db.list_findings()
    if scope_hosts:
        hs = [h.lower() for h in scope_hosts]
        findings = [f for f in findings
                    if any(h in (f["url"] or "").lower() for h in hs)]
    if redact_secrets:
        # spec 61/225: scrub credentials/cookies from evidence before export
        from .ai import redact as _red
        findings = [{**f, "evidence": _red(f.get("evidence") or ""),
                     "description": _red(f.get("description") or "")}
                    for f in findings]
    history = app.db.list_history(limit=5000)
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in SEV_RANK}
    ai_conv = app.db.ai_history("default", 200) if include_ai else []

    md = []
    md.append("# OWSI Security Test Report")
    md.append(f"\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')} · "
              f"OMEGA Web Security Interceptor v1.0 · local project export\n")
    md.append("## Executive summary")
    md.append(f"- Requests analysed: **{len(history)}**")
    md.append(f"- Findings: **{len(findings)}** "
              f"(high {counts['high']}, medium {counts['medium']}, "
              f"low {counts['low']}, info {counts['information']})")
    hosts = sorted({e['host'] for e in history if e['host']})
    md.append(f"- Hosts in scope touched: {', '.join(hosts) or '—'}\n")

    md.append("## Findings")
    if not findings:
        md.append("_No findings recorded._")
    for f in sorted(findings, key=lambda x: SEV_RANK.get(x["severity"], 9)):
        md.append(f"\n### [{f['severity'].upper()}] {f['title']}")
        md.append(f"- **URL:** `{f['url']}`")
        md.append(f"- **Confidence:** {f['confidence']} · **Source:** {f['source']}"
                  f" · **Status:** {f['status']}")
        md.append(f"- **Description:** {f['description']}")
        if f["evidence"]:
            md.append(f"- **Evidence:**\n```\n{f['evidence'][:1500]}\n```")
        md.append(f"- **Recommendation:** {f['recommendation']}")

    md.append("\n## Traffic appendix (last 100)")
    md.append("| Time | Method | URL | Status | Bytes | Tech |")
    md.append("|---|---|---|---|---|---|")
    for e in history[-100:]:
        md.append(f"| {time.strftime('%H:%M:%S', time.localtime(e['ts']))} "
                  f"| {e['method']} | `{e['url'][:90]}` | {e['status']} "
                  f"| {e['respLen']} | {e['tech'][:40]} |")

    if ai_conv:
        md.append("\n## AI copilot conversation log")
        for m in ai_conv[-40:]:
            who = "User" if m["role"] == "user" else "Copilot"
            md.append(f"\n**{who}:** {m['content'][:1200]}")

    markdown = "\n".join(md)
    body_html = _md_to_html(markdown)
    full_html = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>OWSI Report</title><style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;
color:#1c2330;line-height:1.5}}
h1{{border-bottom:3px solid #d9534f;padding-bottom:.4rem}}
table{{border-collapse:collapse;width:100%;font-size:.85rem}}
td,th{{border:1px solid #ccd;padding:.35rem .5rem;text-align:left}}
tr:nth-child(even){{background:#f5f7fb}}
code,pre{{background:#f0f2f7;border-radius:4px;padding:.1rem .3rem;font-size:.85em}}
pre{{padding:.6rem;overflow:auto}}
.sev-high{{color:#b00020;font-weight:700}} .sev-medium{{color:#c66900;font-weight:600}}
.sev-low{{color:#3a6ea5}} .badge{{display:inline-block;background:#eef;border-radius:6px;
padding:0 .5rem;margin-left:.4rem;font-size:.8rem}}
</style></head><body>{body_html}
<p style='color:#889;margin-top:3rem'>Generated locally by OWSI — no data left this
machine.</p></body></html>"""
    return {"markdown": markdown, "html": full_html,
            "findingCount": len(findings), "counts": counts}


def _md_to_html(md: str) -> str:
    import re
    lines = md.split("\n")
    out, in_pre, in_tbl = [], False, False
    for ln in lines:
        if ln.startswith("```"):
            in_pre = not in_pre
            out.append("<pre>" if in_pre else "</pre>")
            continue
        esc = html.escape(ln)
        if in_pre:
            out.append(esc)
            continue
        if ln.startswith("| "):
            cells = [html.escape(c.strip()) for c in ln.strip("|").split("|")]
            if all(re.fullmatch(r":?-+:?", c) for c in cells):
                continue
            tag = "th" if not out or out[-1].startswith("<table") or in_tbl and \
                "<tr><th>" in out[-1] else "td"
            if not in_tbl:
                out.append("<table>")
                tag = "th"
                in_tbl = True
            out.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        elif in_tbl:
            out.append("</table>")
            in_tbl = False
        if ln.startswith("### "):
            sev = ""
            m = re.match(r"### \[(\w+)\]", ln)
            if m:
                sev = f" class='sev-{m.group(1).lower()}'"
            out.append(f"<h3{sev}>{_inline(html.escape(ln[4:]))}</h3>")
        elif ln.startswith("## "):
            out.append(f"<h2>{_inline(html.escape(ln[3:]))}</h2>")
        elif ln.startswith("# "):
            out.append(f"<h1>{_inline(html.escape(ln[2:]))}</h1>")
        elif ln.startswith("- "):
            out.append(f"<div>&bull; {_inline(html.escape(ln[2:]))}</div>")
        elif ln.strip() == "":
            out.append("<br>")
        else:
            out.append(f"<p>{_inline(html.escape(ln))}</p>")
    if in_tbl:
        out.append("</table>")
    return "\n".join(out)


def _inline(s: str) -> str:
    import re
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    return s
