"""
Scope motoru - framework'un kalbi.

Bir bug bounty programinin kapsamini (in-scope / out-of-scope) yukler ve
herhangi bir hedefin (domain, subdomain, IP) kapsam icinde olup olmadigini
belirler. Tum modullar istek atmadan once bir hedefi burada dogrular.

Kapsam girdileri su formatlari destekler:
    example.com            -> tam domain (ve varsayilan olarak subdomainleri)
    *.example.com          -> yalnizca subdomainler (apex haric)
    .example.com           -> *.example.com ile ayni
    https://example.com/x  -> URL; host kismi cikarilir
    10.0.0.0/8             -> CIDR blogu
    192.168.1.5            -> tek IP

Kurallar:
    - out-of-scope her zaman in-scope'u ezer (daha guvenli taraf).
    - in-scope bos ise HICBIR sey kapsamda degildir (fail-closed).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def _extract_host(entry: str) -> str:
    """Bir girdiden host/domain kismini cikarir (URL ise parse eder)."""
    entry = entry.strip()
    if "://" in entry:
        parsed = urlparse(entry)
        return (parsed.hostname or "").lower()
    # yol veya port varsa kirp
    entry = entry.split("/")[0]
    entry = entry.split(":")[0]
    return entry.lower()


@dataclass
class ScopeRule:
    """Tek bir kapsam kurali."""

    raw: str
    kind: str          # "domain" | "wildcard" | "ip" | "cidr"
    value: object      # kind'a gore: str veya ip_network/ip_address

    def matches(self, target: str) -> bool:
        target = target.strip().lower()
        if not target:
            return False

        # Hedef bir IP mi?
        target_ip = None
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            pass

        if self.kind == "cidr":
            if target_ip is not None:
                return target_ip in self.value
            return False

        if self.kind == "ip":
            if target_ip is not None:
                return target_ip == self.value
            return False

        # domain / wildcard kurallari yalnizca hostname hedeflerine uyar
        if target_ip is not None:
            return False

        if self.kind == "domain":
            # apex + tum subdomainler
            return target == self.value or target.endswith("." + self.value)

        if self.kind == "wildcard":
            # yalnizca subdomainler, apex haric
            return target.endswith("." + self.value)

        return False


def _parse_entry(entry: str) -> ScopeRule | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None

    # CIDR
    if "/" in entry and not entry.startswith("*") and "://" not in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ScopeRule(raw=entry, kind="cidr", value=net)
        except ValueError:
            pass  # URL olabilir, devam et

    wildcard = False
    if entry.startswith("*."):
        wildcard = True
        entry_host = entry[2:]
    elif entry.startswith("."):
        wildcard = True
        entry_host = entry[1:]
    else:
        entry_host = entry

    host = _extract_host(entry_host)
    if not host:
        return None

    # Tek IP mi?
    try:
        ip = ipaddress.ip_address(host)
        return ScopeRule(raw=entry, kind="ip", value=ip)
    except ValueError:
        pass

    kind = "wildcard" if wildcard else "domain"
    return ScopeRule(raw=entry, kind=kind, value=host)


@dataclass
class Scope:
    include: list[ScopeRule] = field(default_factory=list)
    exclude: list[ScopeRule] = field(default_factory=list)

    # ---- yukleyiciler ----
    @classmethod
    def from_lists(cls, include: list[str], exclude: list[str] | None = None) -> "Scope":
        inc = [r for r in (_parse_entry(e) for e in include) if r]
        exc = [r for r in (_parse_entry(e) for e in (exclude or [])) if r]
        return cls(include=inc, exclude=exc)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """
        Basit scope dosyasi. Satir basi bir girdi.
        '!' ile baslayan satirlar out-of-scope olarak islenir.
        Alternatif: 'IN:' / 'OUT:' basliklari altinda gruplama.
        """
        include: list[str] = []
        exclude: list[str] = []
        mode = "in"
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            low = s.lower()
            if low in ("in:", "[in]", "in-scope:", "[in-scope]"):
                mode = "in"
                continue
            if low in ("out:", "[out]", "out-of-scope:", "[out-of-scope]"):
                mode = "out"
                continue
            if s.startswith("!"):
                exclude.append(s[1:].strip())
                continue
            (include if mode == "in" else exclude).append(s)
        return cls.from_lists(include, exclude)

    # ---- sorgular ----
    def is_excluded(self, target: str) -> bool:
        return any(r.matches(target) for r in self.exclude)

    def is_included(self, target: str) -> bool:
        return any(r.matches(target) for r in self.include)

    def in_scope(self, target: str) -> bool:
        """out-of-scope in-scope'u ezer; include bos ise fail-closed."""
        host = _extract_host(target) if ("://" in target or "/" in target) else target
        if not self.include:
            return False
        if self.is_excluded(host):
            return False
        return self.is_included(host)

    def filter(self, targets: list[str]) -> list[str]:
        """Kapsam icindeki hedefleri dondurur, digerlerini sessizce atar."""
        return [t for t in targets if self.in_scope(t)]

    def partition(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """(kapsam_ici, kapsam_disi) olarak ikiye ayirir."""
        inside, outside = [], []
        for t in targets:
            (inside if self.in_scope(t) else outside).append(t)
        return inside, outside

    def summary(self) -> str:
        inc = ", ".join(r.raw for r in self.include) or "(bos)"
        exc = ", ".join(r.raw for r in self.exclude) or "(yok)"
        return f"in-scope: {inc}\nout-of-scope: {exc}"
