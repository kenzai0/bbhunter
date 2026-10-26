"""
Harici VERI KAYNAKLARI icin ham fetch yardimcilari.

Bunlar hedefe degil, halka acik pasif istihbarat servislerine (crt.sh,
web.archive.org gibi) gider. Hedef olmadiklari icin scope motorundan gecmezler;
ancak yalnizca bu beyaz listedeki hostlara izin verilir.
"""

from __future__ import annotations

import json as _json

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:  # pragma: no cover
    raise SystemExit("requests gerekli: pip install requests (%s)" % e)

# Pasif istihbarat icin izin verilen veri kaynaklari (hedef degil).
ALLOWED_SOURCES = {
    "crt.sh",
    "web.archive.org",
    "dns.google",
}

_DEFAULT_HEADERS = {"User-Agent": "bbhunter/0.1 passive-source-client"}


def _host_allowed(url: str) -> bool:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "") in ALLOWED_SOURCES


def fetch_text(url: str, timeout: float = 20.0, params: dict | None = None) -> str | None:
    if not _host_allowed(url):
        raise ValueError(f"Izinli veri kaynagi degil: {url}")
    try:
        r = requests.get(
            url, timeout=timeout, params=params, headers=_DEFAULT_HEADERS, verify=True
        )
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        return None
    return None


def fetch_json(url: str, timeout: float = 20.0, params: dict | None = None):
    txt = fetch_text(url, timeout=timeout, params=params)
    if not txt:
        return None
    try:
        return _json.loads(txt)
    except ValueError:
        # crt.sh bazen NDJSON dondurur
        rows = []
        for line in txt.splitlines():
            line = line.strip().rstrip(",")
            if line:
                try:
                    rows.append(_json.loads(line))
                except ValueError:
                    pass
        return rows or None
