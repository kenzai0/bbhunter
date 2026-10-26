"""
Parametre kesfi: arsiv URL'lerinden ve canli sayfalardaki form/link'lerden
sorgu parametresi isimlerini toplar. Bu isimler ileride test icin girdi olur.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

from ..util import dedup_keep_order, good, info

_INPUT_NAME_RE = re.compile(rb"""<(?:input|textarea|select)[^>]*\bname=["']?([a-zA-Z0-9_\-\[\]]+)""", re.I)
_LINK_PARAM_RE = re.compile(rb"""[?&]([a-zA-Z0-9_\-\[\]]+)=""")


def from_urls(urls: list[str]) -> list[str]:
    counter: Counter = Counter()
    for u in urls:
        q = urlparse(u).query
        for name in parse_qs(q).keys():
            counter[name] += 1
    return [name for name, _ in counter.most_common()]


def from_body(body: bytes) -> list[str]:
    names: set[str] = set()
    for m in _INPUT_NAME_RE.finditer(body or b""):
        names.add(m.group(1).decode("utf-8", "replace"))
    for m in _LINK_PARAM_RE.finditer(body or b""):
        names.add(m.group(1).decode("utf-8", "replace"))
    return sorted(names)


def discover(archive_urls: list[str], bodies: list[bytes] | None = None) -> list[str]:
    info("Parametre kesfi")
    params = from_urls(archive_urls)
    for body in bodies or []:
        params += from_body(body)
    params = dedup_keep_order(params)
    good(f"{len(params)} benzersiz parametre ismi toplandi")
    return params
