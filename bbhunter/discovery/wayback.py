"""
Wayback Machine (web.archive.org) CDX API uzerinden arsivlenmis URL toplama.
Pasif bir kaynaktir; hedefe istek atmaz. Sonuclar scope ile filtrelenir.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..scope import Scope
from ..util import dedup_keep_order, good, info, warn
from .. import sources


def fetch_urls(domain: str, scope: Scope, *, include_subs: bool = True) -> list[str]:
    info(f"Wayback arsiv taramasi: {domain}")
    pattern = f"*.{domain}/*" if include_subs else f"{domain}/*"
    data = sources.fetch_json(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": pattern,
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "50000",
        },
    )
    if not data or len(data) < 2:
        warn("Wayback bos dondu")
        return []

    # ilk satir baslik ["original"]
    urls = [row[0] for row in data[1:] if row]
    urls = dedup_keep_order(urls)

    # scope filtrele (host bazinda)
    in_scope = [u for u in urls if scope.in_scope(urlparse(u).hostname or "")]
    dropped = len(urls) - len(in_scope)
    if dropped:
        warn(f"{dropped} arsiv URL kapsam disi oldugu icin elendi")
    good(f"{len(in_scope)} kapsam ici arsiv URL bulundu")
    return in_scope
