"""
Canli HTTP(S) host tespiti (httpx benzeri).
Her host icin http:// ve https:// dener; status, baslik, sunucu, uzunluk toplar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..http_client import HttpClient, OutOfScopeError
from ..util import good, info, parallel_map

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class LiveHost:
    url: str
    status: int
    title: str = ""
    server: str = ""
    content_type: str = ""
    length: int = 0
    final_url: str = ""
    redirect_chain: list = field(default_factory=list)


def _extract_title(body: bytes) -> str:
    m = _TITLE_RE.search(body or b"")
    if not m:
        return ""
    try:
        return m.group(1).decode("utf-8", "replace").strip()[:200]
    except Exception:
        return ""


def probe_host(client: HttpClient, host: str, schemes=("https", "http")) -> list[LiveHost]:
    out: list[LiveHost] = []
    for scheme in schemes:
        url = f"{scheme}://{host}"
        try:
            resp = client.get(url)
        except OutOfScopeError:
            return out  # kapsam disi, atla
        if resp is None:
            continue
        out.append(
            LiveHost(
                url=url,
                status=resp.status,
                title=_extract_title(resp.body),
                server=resp.headers.get("Server", ""),
                content_type=resp.headers.get("Content-Type", ""),
                length=resp.length,
                final_url=resp.final_url,
                redirect_chain=resp.history,
            )
        )
        # https calisiyorsa http'yi denemeye genelde gerek yok
        if scheme == "https" and resp.status < 500:
            break
    return out


def probe(client: HttpClient, hosts: list[str], threads: int = 20) -> list[LiveHost]:
    info(f"Canli host tespiti: {len(hosts)} host")
    results: list[LiveHost] = []

    def _one(host: str) -> list[LiveHost]:
        return probe_host(client, host)

    for host_results in parallel_map(_one, hosts, threads=threads):
        for lh in host_results:
            good(f"{lh.status} {lh.url} [{lh.title[:50]}] {lh.server}")
            results.append(lh)
    return results
