"""
Subdomain enumeration:
  1) Pasif  - crt.sh Certificate Transparency loglarindan.
  2) Aktif  - wordlist tabanli DNS brute-force (wildcard filtreli).

Tum sonuclar Scope motorundan gecer; yalnizca kapsam ici subdomainler doner.
"""

from __future__ import annotations

from ..scope import Scope
from ..util import dedup_keep_order, good, info, parallel_map, warn
from .. import sources
from .dns import Resolver


def passive_crtsh(domain: str) -> list[str]:
    """crt.sh uzerinden pasif subdomain toplama."""
    info(f"crt.sh pasif tarama: {domain}")
    data = sources.fetch_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if not data:
        warn("crt.sh yanit vermedi veya bos dondu")
        return []
    found: set[str] = set()
    for row in data:
        name_value = row.get("name_value", "") if isinstance(row, dict) else ""
        for sub in name_value.splitlines():
            sub = sub.strip().lstrip("*.").lower()
            if sub.endswith(domain):
                found.add(sub)
    return sorted(found)


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        # yerlesik kucuk liste (yaygin subdomainler)
        return BUILTIN_SUBS
    from pathlib import Path

    words = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip().lower()
        if s and not s.startswith("#"):
            words.append(s)
    return words


def brute_force(
    domain: str,
    resolver: Resolver,
    wordlist: list[str],
    threads: int = 40,
) -> list[str]:
    """Wordlist ile DNS brute-force; wildcard IP'lerini eler."""
    info(f"DNS brute-force: {domain} ({len(wordlist)} aday)")
    wildcard_ips = resolver.detect_wildcard(domain)
    if wildcard_ips:
        warn(f"Wildcard DNS tespit edildi ({len(wildcard_ips)} IP) - filtreleniyor")

    candidates = [f"{w}.{domain}" for w in wordlist]

    def _check(host: str) -> str | None:
        rec = resolver.resolve(host)
        if not rec.resolves:
            return None
        ips = set(rec.a) | set(rec.aaaa)
        # tum IP'ler wildcard ise gercek bir kayit degil
        if ips and ips.issubset(wildcard_ips):
            return None
        return host

    found = [h for h in parallel_map(_check, candidates, threads=threads) if h]
    return sorted(set(found))


def enumerate_subdomains(
    domain: str,
    scope: Scope,
    resolver: Resolver,
    *,
    wordlist: list[str] | None = None,
    do_passive: bool = True,
    do_brute: bool = True,
    threads: int = 40,
) -> list[str]:
    results: list[str] = [domain]
    if do_passive:
        results += passive_crtsh(domain)
    if do_brute:
        results += brute_force(domain, resolver, wordlist or BUILTIN_SUBS, threads=threads)

    results = dedup_keep_order(results)
    in_scope = scope.filter(results)
    dropped = len(results) - len(in_scope)
    if dropped:
        warn(f"{dropped} subdomain kapsam disi oldugu icin elendi")
    good(f"{len(in_scope)} kapsam ici subdomain bulundu: {domain}")
    return in_scope


# Yerlesik kucuk wordlist - genis tarama icin --wordlist ile harici liste ver.
BUILTIN_SUBS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns3", "blog", "dev", "www2", "admin", "forum", "news", "vpn", "api",
    "staging", "stage", "app", "apps", "secure", "shop", "store", "portal",
    "beta", "demo", "cdn", "assets", "static", "media", "img", "images", "video",
    "download", "downloads", "support", "help", "docs", "wiki", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "status", "monitor", "grafana",
    "kibana", "prometheus", "db", "database", "mysql", "postgres", "redis",
    "mongo", "backup", "old", "new", "mobile", "web", "internal", "intranet",
    "corp", "office", "remote", "ssh", "sftp", "proxy", "gateway", "router",
    "dashboard", "panel", "manage", "console", "auth", "login", "sso", "oauth",
    "accounts", "account", "billing", "pay", "payment", "payments", "checkout",
    "cart", "orders", "customer", "client", "clients", "partner", "partners",
    "vendor", "crm", "erp", "hr", "finance", "legal", "marketing", "sales",
    "analytics", "stats", "metrics", "logs", "log", "elastic", "search",
    "cache", "queue", "worker", "job", "jobs", "cron", "scheduler", "ws",
    "websocket", "socket", "stream", "live", "chat", "mail2", "email", "mx",
    "mx1", "mx2", "relay", "spf", "dkim", "dmarc", "cloud", "aws", "azure",
    "gcp", "k8s", "kubernetes", "docker", "registry", "artifactory", "nexus",
    "sonar", "test1", "test2", "qa", "uat", "sandbox", "preprod", "prod",
    "production", "edge", "origin", "lb", "node1", "node2", "srv", "server",
    "host", "vm", "s3", "storage", "files", "file", "upload", "uploads",
]
