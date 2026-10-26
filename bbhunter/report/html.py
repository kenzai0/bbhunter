"""
Self-contained HTML rapor + basit grafikler (inline SVG).

Harici JS/CSS bagimliligi YOKTUR; tek dosya offline acilir. Store'daki tum
kullanici-kontrollu veri (hedef, kanit, baslik) HTML-escape edilir; boylece
yanit govdesinden gelen icerik raporu bir XSS vektorune cevirmez.
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from .store import Store

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}
_ASSET_COLOR = "#0ea5e9"


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _hbar_chart(rows: list[tuple[str, int, str]], *, width: int = 420, bar_h: int = 26,
                gap: int = 10, label_w: int = 88) -> str:
    """Yatay bar grafigi (inline SVG). rows: (etiket, deger, renk)."""
    rows = [r for r in rows if r[1] > 0]
    if not rows:
        return '<p class="muted">Veri yok.</p>'
    maxv = max(v for _, v, _ in rows) or 1
    plot_w = width - label_w - 48
    height = len(rows) * (bar_h + gap) + gap
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'role="img" class="chart" preserveAspectRatio="xMinYMin meet">']
    y = gap
    for label, value, color in rows:
        bw = max(2, int(plot_w * value / maxv))
        parts.append(
            f'<text x="0" y="{y + bar_h * 0.7:.0f}" class="bar-label">{_esc(label)}</text>'
        )
        parts.append(
            f'<rect x="{label_w}" y="{y}" width="{bw}" height="{bar_h}" rx="4" '
            f'fill="{color}"><title>{_esc(label)}: {value}</title></rect>'
        )
        parts.append(
            f'<text x="{label_w + bw + 6}" y="{y + bar_h * 0.7:.0f}" '
            f'class="bar-value">{value}</text>'
        )
        y += bar_h + gap
    parts.append("</svg>")
    return "".join(parts)


def _stat_cards(stats: dict) -> str:
    ff = stats.get("findings", {})
    af = stats.get("assets", {})
    total_f = sum(ff.values())
    total_a = sum(af.values())
    cards = [
        ("Toplam bulgu", total_f, "#111827"),
        ("Kritik", ff.get("critical", 0), _SEV_COLOR["critical"]),
        ("Yuksek", ff.get("high", 0), _SEV_COLOR["high"]),
        ("Orta", ff.get("medium", 0), _SEV_COLOR["medium"]),
        ("Toplam varlik", total_a, _ASSET_COLOR),
    ]
    out = ['<div class="cards">']
    for label, value, color in cards:
        out.append(
            f'<div class="card"><div class="card-v" style="color:{color}">{value}</div>'
            f'<div class="card-l">{_esc(label)}</div></div>'
        )
    out.append("</div>")
    return "".join(out)


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return '<p class="muted">Bulgu yok.</p>'
    rows = []
    for f in findings:
        sev = f["severity"]
        color = _SEV_COLOR.get(sev, "#6b7280")
        data = f.get("data") or {}
        loc = data.get("matched_at") or data.get("location") or ""
        refs = data.get("reference") or []
        ref_html = ""
        if refs:
            ref_html = " ".join(
                f'<a href="{_esc(r)}" rel="noopener noreferrer nofollow" target="_blank">ref</a>'
                for r in refs
            )
        rows.append(
            f'<tr data-sev="{_esc(sev)}">'
            f'<td><span class="badge" style="background:{color}">{_esc(sev.upper())}</span></td>'
            f'<td><strong>{_esc(f["name"])}</strong><div class="cat">{_esc(f["category"])}</div></td>'
            f'<td class="mono">{_esc(f["target"])}'
            + (f'<div class="loc mono">{_esc(loc)}</div>' if loc else "")
            + f'</td>'
            f'<td class="ev mono">{_esc((f.get("detail") or "")[:400])}</td>'
            f'<td>{ref_html}</td>'
            f'</tr>'
        )
    return (
        '<table class="findings"><thead><tr>'
        '<th>Siddet</th><th>Bulgu</th><th>Hedef</th><th>Kanit</th><th></th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table>"
    )


def _assets_section(store: Store) -> str:
    out = []
    for kind in ("subdomain", "host", "url", "port", "param", "endpoint"):
        items = [a["value"] for a in store.assets(kind)]
        if not items:
            continue
        listed = "\n".join(_esc(i) for i in items[:3000])
        more = "" if len(items) <= 3000 else f"\n... (+{len(items) - 3000} daha)"
        out.append(
            f'<details><summary>{_esc(kind)} '
            f'<span class="count">{len(items)}</span></summary>'
            f'<pre class="mono">{listed}{more}</pre></details>'
        )
    return "".join(out) or '<p class="muted">Varlik yok.</p>'


_FILTER_JS = """
(function(){
  var buttons = document.querySelectorAll('[data-filter]');
  buttons.forEach(function(b){
    b.addEventListener('click', function(){
      var sev = b.getAttribute('data-filter');
      buttons.forEach(function(x){ x.classList.remove('active'); });
      b.classList.add('active');
      document.querySelectorAll('tr[data-sev]').forEach(function(tr){
        tr.style.display = (sev === 'all' || tr.getAttribute('data-sev') === sev) ? '' : 'none';
      });
    });
  });
})();
"""

_CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--muted:#64748b;--card:#fff;--border:#e2e8f0;}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#e2e8f0;--muted:#94a3b8;--card:#1e293b;--border:#334155;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}
.sub{color:var(--muted);margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.card-v{font-size:28px;font-weight:700}.card-l{color:var(--muted);font-size:13px;margin-top:2px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:720px){.grid2{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
.panel h3{margin:0 0 10px;font-size:14px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.chart{display:block}.bar-label{font-size:12px;fill:var(--fg)}.bar-value{font-size:12px;fill:var(--muted)}
table.findings{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.findings th{text-align:left;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid var(--border)}
.findings td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.findings tr:last-child td{border-bottom:none}
.badge{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}
.cat{color:var(--muted);font-size:12px;margin-top:2px}
.loc{color:var(--muted);font-size:12px;margin-top:4px;word-break:break-all}
.ev{color:var(--muted);font-size:12px;max-width:360px;word-break:break-word}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.muted{color:var(--muted)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 14px}
.filters button{background:var(--card);border:1px solid var(--border);color:var(--fg);border-radius:999px;padding:5px 14px;cursor:pointer;font-size:13px}
.filters button.active{background:var(--fg);color:var(--bg);border-color:var(--fg)}
details{background:var(--card);border:1px solid var(--border);border-radius:10px;margin:8px 0;padding:4px 12px}
summary{cursor:pointer;font-weight:600;padding:6px 0}
.count{background:var(--border);border-radius:999px;padding:1px 8px;font-size:12px;color:var(--muted);font-weight:400}
pre{overflow:auto;max-height:340px;font-size:12px;background:transparent;margin:6px 0}
a{color:#2563eb}
footer{color:var(--muted);font-size:12px;margin-top:40px;text-align:center}
"""


def write_html(store: Store, path: str | Path, program: str = "") -> Path:
    path = Path(path)
    stats = store.stats()
    findings = store.findings()
    ff = stats.get("findings", {})
    af = stats.get("assets", {})

    sev_rows = [(s, ff.get(s, 0), _SEV_COLOR[s]) for s in _SEV_ORDER]
    asset_rows = [(k, af.get(k, 0), _ASSET_COLOR)
                  for k in ("subdomain", "host", "url", "port", "param", "endpoint")]

    title = "Bug Bounty Recon Raporu" + (f" — {program}" if program else "")
    filters = ['<div class="filters"><button data-filter="all" class="active">Hepsi</button>']
    for s in _SEV_ORDER:
        if ff.get(s, 0):
            filters.append(f'<button data-filter="{s}">{_esc(s.upper())} '
                           f'({ff.get(s,0)})</button>')
    filters.append("</div>")

    doc = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>{_esc(title)}</h1>
<p class="sub">Olusturulma: {_esc(time.strftime('%Y-%m-%d %H:%M:%S'))}</p>
{_stat_cards(stats)}
<div class="grid2">
  <div class="panel"><h3>Siddete gore bulgular</h3>{_hbar_chart(sev_rows)}</div>
  <div class="panel"><h3>Varlik turleri</h3>{_hbar_chart(asset_rows)}</div>
</div>
<h2>Bulgular</h2>
{''.join(filters)}
{_findings_table(findings)}
<h2>Varliklar</h2>
{_assets_section(store)}
<footer>bbhunter — yalnizca yetkili / kapsam ici hedefler icin</footer>
</div>
<script>{_FILTER_JS}</script>
</body></html>"""

    path.write_text(doc, encoding="utf-8")
    return path
