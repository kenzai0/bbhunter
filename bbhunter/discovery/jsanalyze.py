"""
JavaScript analizi: JS dosyalarindan endpoint/yol ve olasi gizli anahtar
(API key, token) imzalarini cikarir. Yalnizca kapsam ici URL'lerden ceker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..http_client import HttpClient, OutOfScopeError
from ..util import dedup_keep_order, good, info, parallel_map, warn

# JS icindeki yol/endpoint imzalari
_ENDPOINT_RE = re.compile(
    rb"""['"`]((?:/|\.\./|\./)[a-zA-Z0-9_\-/.]+?(?:\?[^'"`]*)?|https?://[a-zA-Z0-9_\-./%?&=]+)['"`]"""
)

# Olasi sir imzalari (yuksek sinyalli olanlar). Yalnizca ipucu uretir;
# dogrulama/raporlama kullaniciya kalir.
_SECRET_SIGS = [
    ("AWS Access Key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack Token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Stripe Live Key", re.compile(rb"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Token", re.compile(rb"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("JWT", re.compile(rb"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("Private Key Block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Generic api_key assignment", re.compile(rb"""['"]?api[_-]?key['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_]{16,}['"]""", re.I)),
]


@dataclass
class JsFinding:
    source: str
    endpoints: list[str] = field(default_factory=list)
    secrets: list[tuple] = field(default_factory=list)  # (tip, eslesme)


def analyze_body(source_url: str, body: bytes) -> JsFinding:
    f = JsFinding(source=source_url)
    eps: set[str] = set()
    for m in _ENDPOINT_RE.finditer(body or b""):
        ep = m.group(1).decode("utf-8", "replace")
        # gurultu elemesi
        if len(ep) < 2 or ep in ("/", "./", "../"):
            continue
        if any(ep.endswith(x) for x in (".png", ".jpg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ttf")):
            continue
        eps.add(ep)
    f.endpoints = sorted(eps)

    for name, rx in _SECRET_SIGS:
        for m in rx.finditer(body or b""):
            snippet = m.group(0).decode("utf-8", "replace")[:80]
            f.secrets.append((name, snippet))
    return f


def analyze(client: HttpClient, js_urls: list[str], threads: int = 20) -> list[JsFinding]:
    js_urls = dedup_keep_order([u for u in js_urls if u.split("?")[0].endswith(".js")])
    info(f"JS analizi: {len(js_urls)} dosya")

    def _one(url: str) -> JsFinding | None:
        try:
            resp = client.get(url)
        except OutOfScopeError:
            return None
        if resp is None:
            return None
        return analyze_body(url, resp.body)

    results: list[JsFinding] = []
    for f in parallel_map(_one, js_urls, threads=threads):
        if f is None:
            continue
        if f.secrets:
            for name, snip in f.secrets:
                warn(f"OLASI SIR [{name}] {f.source}: {snip}")
        if f.endpoints or f.secrets:
            good(f"{f.source}: {len(f.endpoints)} endpoint, {len(f.secrets)} olasi sir")
            results.append(f)
    return results
