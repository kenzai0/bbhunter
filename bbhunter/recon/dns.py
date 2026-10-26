"""
DNS cozumleme. dnspython varsa onu kullanir (CNAME, custom resolver, wildcard
tespiti icin daha iyi); yoksa standart socket cozumleyicisine duser.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

try:
    import dns.resolver  # type: ignore
    _HAVE_DNSPYTHON = True
except ImportError:
    _HAVE_DNSPYTHON = False


@dataclass
class DnsRecord:
    name: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: str | None = None

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa or self.cname)


def _resolve_socket(name: str) -> DnsRecord:
    rec = DnsRecord(name=name)
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, UnicodeError, OSError):
        return rec
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if family == socket.AF_INET and ip not in rec.a:
            rec.a.append(ip)
        elif family == socket.AF_INET6 and ip not in rec.aaaa:
            rec.aaaa.append(ip)
    return rec


def _resolve_dnspython(name: str, resolver) -> DnsRecord:
    rec = DnsRecord(name=name)
    for rtype, bucket in (("A", rec.a), ("AAAA", rec.aaaa)):
        try:
            ans = resolver.resolve(name, rtype)
            for r in ans:
                bucket.append(r.to_text())
        except Exception:
            pass
    try:
        ans = resolver.resolve(name, "CNAME")
        rec.cname = str(ans[0].target).rstrip(".") if ans else None
    except Exception:
        pass
    return rec


class Resolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 3.0):
        self._resolver = None
        if _HAVE_DNSPYTHON:
            self._resolver = dns.resolver.Resolver(configure=True)
            self._resolver.lifetime = timeout
            self._resolver.timeout = timeout
            if nameservers:
                self._resolver.nameservers = nameservers

    def resolve(self, name: str) -> DnsRecord:
        name = name.strip(".").lower()
        if self._resolver is not None:
            return _resolve_dnspython(name, self._resolver)
        return _resolve_socket(name)

    def detect_wildcard(self, domain: str) -> set[str]:
        """
        Wildcard DNS tespiti: rastgele, var olmasi imkansiz subdomainler cozuluyorsa
        bu domain wildcard'dir. Doneni (wildcard IP seti) brute sonuclarindan
        elemek icin kullaniriz.
        """
        import random
        import string

        wildcard_ips: set[str] = set()
        for _ in range(3):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            rec = self.resolve(f"{rand}.{domain}")
            wildcard_ips.update(rec.a)
            wildcard_ips.update(rec.aaaa)
        return wildcard_ips
