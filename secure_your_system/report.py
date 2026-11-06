"""Export scan results as a self-contained HTML report, JSON, or plain text."""
from __future__ import annotations

import html
import json

from . import __version__
from .models import Severity, fmt_time

# Same dark violet theme as the app
SEV_COLORS = {"Critical": "#ff4d6d", "High": "#ff8c5a", "Medium": "#f6c945", "Low": "#6fb2ff", "Info": "#9b93b0"}
RISK_COLORS = {0: "#4ade80", 1: "#6fb2ff", 2: "#f6c945", 3: "#ff8c5a", 4: "#ff4d6d"}


def to_json(result, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, default=str)


def to_text(result) -> str:
    a = result.analysis
    L = [f"Evan's Secure Your System v{__version__}",
         f"Host: {result.host.get('hostname')}  OS: {result.host.get('os')}  "
         f"Admin: {'yes' if result.host.get('admin') else 'no'}",
         f"Scan: {result.options.get('scan_type')}  window: last {result.options.get('window_days')} day(s)  "
         f"finished: {fmt_time(result.finished)}", "",
         f"RESULT: {a['headline'].upper()}", a["narrative"], ""]
    L.append("FINDINGS")
    for f in result.findings:
        L.append(f"  [{f.severity.label:<8}] {f.title}")
        for p in f.paths[:3]:
            L.append(f"             {p}")
    if not result.findings:
        L.append("  none")
    if a["origin"]:
        L += ["", "WHERE IT LIKELY CAME FROM"]
        L += [f"  - {o['source']} ({o['confidence']})" for o in a["origin"]]
    if a["possibly_taken"]:
        L += ["", "WHAT MAY HAVE BEEN TAKEN"]
        L += [f"  - [{i['risk']}] {i['what']}: {i['why']}" for i in a["possibly_taken"]]
    if a["sniffed"]:
        L += ["", "WHAT MAY HAVE BEEN SNIFFED"]
        L += [f"  - {i['what']}: {i['why']}" for i in a["sniffed"]]
    L += ["", "DO THIS NOW"]
    L += [f"  {n}. [{s['priority']}] {s['step']} — {s['detail']}" for n, s in enumerate(a["actions_now"], 1)]
    L += ["", "FURTHER CHECKS"]
    for g in a["further_checks"]:
        L.append(f"  {g['group']}")
        L += [f"    - {i['check']}: {i['how']}" for i in g["items"]]
    return "\n".join(L)


def to_html(result, path: str) -> None:
    a = result.analysis
    e = html.escape
    color = RISK_COLORS.get(a["risk_level"], "#9b93b0")

    def sev_badge(label):
        c = SEV_COLORS.get(label, "#9b93b0")
        return f'<span class="b" style="color:{c};border-color:{c}66;background:{c}1f">{e(label)}</span>'

    rows = []
    for f in result.findings:
        ev = "".join(f"<tr><th>{e(str(k))}</th><td>{e(_s(v))}</td></tr>" for k, v in f.evidence.items())
        paths = "".join(f"<li><code>{e(p)}</code></li>" for p in f.paths)
        rows.append(f"""<details class="f"><summary>{sev_badge(f.severity.label)} <b>{e(f.title)}</b>
        <span class="m">{e(f.check)}</span></summary><p>{e(f.description)}</p>
        {'<table class="ev">' + ev + '</table>' if ev else ''}{'<ul>' + paths + '</ul>' if paths else ''}</details>""")

    def lst(items, fmt):
        return "<ul>" + "".join(fmt(i) for i in items) + "</ul>" if items else "<p class='m'>None identified.</p>"

    origin = lst(a["origin"], lambda o: f"<li><b>{e(o['source'])}</b> <span class='m'>({e(o['confidence'])} "
                 f"confidence)</span>{'<br><small>' + e('; '.join(o['evidence'][:4])) + '</small>' if o['evidence'] else ''}</li>")
    taken = lst(a["possibly_taken"], lambda i: f"<li>{sev_badge(i['risk'] if i['risk'] != 'Medium' else 'Medium')} "
                f"<b>{e(i['what'])}</b> — {e(i['why'])}" + ("<ul>" + "".join(
                    f"<li><code>{e(p)}</code></li>" for p in i['paths'][:8]) + "</ul>" if i['paths'] else "") + "</li>")
    sniffed = lst(a["sniffed"], lambda i: f"<li><b>{e(i['what'])}</b> — {e(i['why'])}</li>")
    dest = lst(a["destinations"], lambda d: f"<li><code>{e(d['endpoint'])}</code> {e(d['process'])}</li>")
    locs = lst(a["affected_locations"], lambda l: f"<li>{sev_badge(l['severity'])} <code>{e(l['path'])}</code>"
               f"<br><small>{e(l['reason'])}</small></li>")
    actions = "<ol>" + "".join(f"<li><span class='p p-{e(s['priority'].replace(' ', ''))}'>{e(s['priority'])}</span> "
                               f"<b>{e(s['step'])}</b><br>{e(s['detail'])}</li>" for s in a["actions_now"]) + "</ol>"
    further = "".join(f"<h3>{e(g['group'])}</h3><p class='m'>{e(g['why'])}</p><ul>" + "".join(
        f"<li><b>{e(i['check'])}</b><br><small>{e(i['how'])}</small></li>" for i in g["items"]) + "</ul>"
        for g in a["further_checks"])
    checks = "".join(f"<tr><td>{e(c.name)}</td><td>{'Ran' if c.ran else 'Skipped'}</td><td>{len(c.findings)}</td>"
                     f"<td>{e('; '.join(c.limited) or c.error or '—')}</td></tr>" for c in result.checks)
    sens = "".join(f"<tr><td>{e(s.kind)}</td><td>{e(s.label)}</td><td><code>{e(s.path)}</code></td>"
                   f"<td>{e(fmt_time(s.modified))}</td><td>{'Yes' if s.in_window else ''}</td></tr>"
                   for s in result.sensitive)
    counts = " ".join(f"{sev_badge(k)} {v}" for k, v in a["counts"].items() if v)
    lim = "".join(f"<li>{e(x)}</li>" for x in a["limitations"])

    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evan's Secure Your System report — {e(result.host.get('hostname', ''))}</title>
<style>
:root{{--bg:#0d0a14;--s1:#15111f;--s2:#1e1830;--bd:#2e2645;--tx:#f1eef8;--mu:#9b93b0;--vi:#8b5cf6;--vl:#b8a1ff;--mg:#d65cf0;--li:#b8f23e;--acc:{color}}}
*{{box-sizing:border-box}}
body{{font:15px/1.6 Inter,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--tx);background:var(--bg);margin:0;
background-image:radial-gradient(900px 420px at 85% -10%,rgba(139,92,246,.28),transparent 70%),radial-gradient(700px 380px at 0% 0%,rgba(214,92,240,.10),transparent 70%);background-repeat:no-repeat}}
.w{{max-width:1040px;margin:0 auto;padding:32px 28px 60px}}
.top{{display:flex;align-items:center;gap:14px}} .logo{{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,var(--vi),var(--mg));display:grid;place-items:center;font-weight:800;color:#fff;box-shadow:0 0 24px rgba(139,92,246,.5)}}
h1{{margin:0;font-size:26px;letter-spacing:-.02em}} h1 .g{{background:linear-gradient(90deg,var(--vl),var(--mg));-webkit-background-clip:text;background-clip:text;color:transparent}}
.meta{{color:var(--mu);font-size:13px;margin-top:8px}}
h2{{margin:40px 0 12px;font-size:19px;letter-spacing:-.01em;color:var(--tx)}} h2::before{{content:"";display:inline-block;width:4px;height:16px;border-radius:2px;background:linear-gradient(var(--vi),var(--mg));margin-right:10px;vertical-align:-2px}}
h3{{color:var(--vl);font-size:15px;margin:18px 0 4px}}
.hero{{background:linear-gradient(135deg,var(--s2),var(--s1));border:1px solid var(--bd);border-left:5px solid var(--acc);border-radius:14px;padding:24px 28px;margin:24px 0;box-shadow:0 10px 40px rgba(0,0,0,.35)}}
.hero .k{{font-size:12px;font-weight:700;letter-spacing:.12em;color:var(--acc)}} .hero h2{{margin:4px 0 8px;font-size:26px;color:var(--acc)}} .hero h2::before{{display:none}}
.card{{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 22px;margin:12px 0}}
.b{{display:inline-block;border:1px solid;border-radius:999px;padding:1px 9px;font-size:11.5px;font-weight:700;letter-spacing:.02em}} .m{{color:var(--mu)}}
details.f{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;margin:8px 0;padding:12px 16px}}
details.f[open]{{border-color:rgba(139,92,246,.6)}} details.f summary{{cursor:pointer}} details.f summary .m{{font-size:12px;margin-left:6px}}
table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:13px}}
th{{color:var(--vl);font-weight:600}} table.ev th{{width:190px;color:var(--mu);font-weight:500}}
code{{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;word-break:break-all;background:#1b1529;color:#d9ccff;padding:2px 6px;border-radius:5px}}
ol li,ul li{{margin:8px 0}} ol{{padding-left:22px}} a{{color:var(--vl)}}
.p{{font-size:11px;font-weight:800;border-radius:999px;padding:1px 9px;margin-right:4px;color:var(--mu);border:1px solid currentColor}}
.p-Now{{color:#ff4d6d}} .p-Today{{color:#ff8c5a}} .p-Thisweek{{color:#f6c945}} .p-Soon{{color:#6fb2ff}}
.foot{{margin-top:48px;color:var(--mu);font-size:12px;text-align:center}}
@media print{{body{{background:#fff;color:#111}} .card,details.f,.hero{{background:#fff;box-shadow:none;border-color:#ccc}} code{{background:#f2f2f2;color:#222}} h1 .g{{color:#6d28d9;-webkit-text-fill-color:#6d28d9}}}}
</style></head><body><div class="w">
<div class="top"><div class="logo">ES</div><h1>Evan's Secure Your System <span class="g">Scan Report</span></h1></div>
<div class="meta">{e(result.host.get('hostname', ''))} · {e(result.host.get('os', ''))} · user {e(str(result.host.get('user')))} ·
admin rights: {'yes' if result.host.get('admin') else 'no'} · {e(result.options.get('scan_type', ''))} scan,
last {result.options.get('window_days')} day(s) · {e(fmt_time(result.finished))} · v{__version__}</div>
<div class="hero"><div class="k">SCAN RESULT</div><h2>{e(a['headline'])}</h2><div>{e(a['narrative'])}</div><div style="margin-top:10px">{counts}</div></div>
<h2>Do this now</h2><div class="card">{actions}</div>
<h2>Where it likely came from</h2><div class="card">{origin}
{'<p><b>Earliest suspicious activity:</b> ' + e(a['first_activity']) + '</p>' if a['first_activity'] else ''}</div>
<h2>What may have been taken</h2><div class="card">{taken}</div>
<h2>What may have been sniffed</h2><div class="card">{sniffed}</div>
<h2>Where data may have gone</h2><div class="card">{dest}</div>
<h2>Affected file locations</h2><div class="card">{locs}</div>
<h2>Findings ({len(result.findings)})</h2>{''.join(rows) or '<p class="m">No findings.</p>'}
<h2>Further checks</h2><div class="card">{further}</div>
<h2>Sensitive data on this device</h2><div class="card"><table><tr><th>Type</th><th>Item</th><th>Location</th>
<th>Last changed</th><th>Used in window</th></tr>{sens}</table></div>
<h2>Scan coverage</h2><div class="card"><table><tr><th>Check</th><th>Status</th><th>Findings</th><th>Limits</th></tr>{checks}</table></div>
<h2>Limitations</h2><div class="card"><ul>{lim}</ul></div>
<div class="foot">Generated by Evan's Secure Your System v{__version__} · read-only scan · keep this report as a record</div>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def _s(v) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return ", ".join(f"{k}={x}" for k, x in v.items())
    return str(v)
