"""
Markdown ve JSON rapor uretimi. Store'daki asset ve bulgulari okunakli
bir rapora donusturur.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .store import Store

_SEV_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}


def write_json(store: Store, path: str | Path) -> Path:
    path = Path(path)
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stats": store.stats(),
        "assets": store.assets(),
        "findings": store.findings(),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_markdown(store: Store, path: str | Path, program: str = "") -> Path:
    path = Path(path)
    stats = store.stats()
    findings = store.findings()
    lines: list[str] = []

    lines.append(f"# Bug Bounty Recon Raporu{(' - ' + program) if program else ''}")
    lines.append(f"\n_Olusturulma: {time.strftime('%Y-%m-%d %H:%M:%S')}_\n")

    # Ozet
    lines.append("## Ozet\n")
    af = stats.get("assets", {})
    ff = stats.get("findings", {})
    lines.append("| Varlik turu | Adet |")
    lines.append("|---|---|")
    for kind in ("subdomain", "host", "url", "port", "param", "endpoint"):
        if kind in af:
            lines.append(f"| {kind} | {af[kind]} |")
    lines.append("")
    lines.append("| Siddet | Bulgu |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in ff:
            lines.append(f"| {_SEV_EMOJI.get(sev,'')} {sev} | {ff[sev]} |")
    lines.append("")

    # Bulgular
    lines.append("## Bulgular\n")
    if not findings:
        lines.append("_Bulgu yok._\n")
    else:
        for f in findings:
            emoji = _SEV_EMOJI.get(f["severity"], "")
            lines.append(f"### {emoji} [{f['severity'].upper()}] {f['name']}")
            lines.append(f"- **Hedef:** `{f['target']}`")
            lines.append(f"- **Kategori:** {f['category']}")
            if f["detail"]:
                detail = f["detail"].replace("`", "'")
                lines.append(f"- **Kanit:** `{detail[:300]}`")
            data = f.get("data") or {}
            if data.get("matched_at"):
                lines.append(f"- **Konum:** {data['matched_at']}")
            if data.get("reference"):
                for ref in data["reference"]:
                    lines.append(f"- **Referans:** {ref}")
            lines.append("")

    # Varliklar (ek)
    lines.append("## Varliklar\n")
    for kind in ("subdomain", "host", "url", "port", "param", "endpoint"):
        items = [a["value"] for a in store.assets(kind)]
        if not items:
            continue
        lines.append(f"<details><summary>{kind} ({len(items)})</summary>\n")
        lines.append("```")
        lines.extend(items[:2000])
        lines.append("```")
        lines.append("</details>\n")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
