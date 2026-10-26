"""
Subdomain takeover tespiti (non-destructive).

Her subdomain icin:
  1) CNAME zinciri cozulur.
  2) CNAME bilinen bir ucuncu-parti servise (GitHub Pages, S3, Heroku, Azure,
     Shopify, Fastly...) isaret ediyor mu bakilir.
  3) Host'un yaniti o servisin "burada kaynak yok / sahipsiz" IMZASIYLA eslesirse
     takeover ADAYI olarak isaretlenir.
  4) CNAME bir servise isaret edip hedef NXDOMAIN ise (dangling) manuel inceleme
     adayi olarak isaretlenir.

Bu modul subdomain'i GERCEKTEN ELE GECIRMEZ; yalnizca kanit (CNAME + imza)
toplar. Dogrulama/iddia (claim) adimi, programin kurallarina gore arastirmaciya
birakilir. Not: CNAME tespiti icin dnspython onerilir (`pip install dnspython`);
yoksa yalnizca govde-imzasina dayali tespit calisir.

Imza kaynagi felsefesi: can-i-take-over-xyz (EdOverflow) projesindeki yaygin
servisler. Servisler zamanla degisir; bir aday her zaman ELLE dogrulanmalidir.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..http_client import HttpClient, OutOfScopeError
from ..util import good, info, parallel_map, warn
from .dns import Resolver


@dataclass
class TakeoverFinding:
    host: str
    service: str
    cname: str = ""
    confidence: str = "medium"   # high | medium | low
    reason: str = ""
    evidence: str = ""

    @property
    def severity(self) -> str:
        return {"high": "high", "medium": "medium", "low": "low"}.get(self.confidence, "low")


# Her kayit: servis adi, CNAME desenleri, yanit imzalari, govde-imzasi tek
# basina yeterli mi (fingerprint_only), notlar.
SERVICES: list[dict] = [
    {"service": "GitHub Pages", "cnames": ["github.io", "githubusercontent.com"],
     "fingerprints": ["There isn't a GitHub Pages site here.",
                      "For root URLs (like http://example.com/) you must provide an index.html file"],
     "fingerprint_only": True},
    {"service": "AWS S3", "cnames": ["s3.amazonaws.com", "s3-website", ".s3.", "s3.dualstack",
                                     "s3-accesspoint"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
     "fingerprint_only": True},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "fingerprint_only": False},
    {"service": "Shopify", "cnames": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable"],
     "fingerprint_only": False},
    {"service": "Fastly", "cnames": ["fastly.net"],
     "fingerprints": ["Fastly error: unknown domain"],
     "fingerprint_only": False},
    {"service": "Pantheon", "cnames": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek."],
     "fingerprint_only": True},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address.",
                      "There's nothing here."],
     "fingerprint_only": False},
    {"service": "WordPress.com", "cnames": ["wordpress.com"],
     "fingerprints": ["Do you want to register"],
     "fingerprint_only": False},
    {"service": "Ghost", "cnames": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here, or never was"],
     "fingerprint_only": True},
    {"service": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprints": ["project not found"],
     "fingerprint_only": True},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"],
     "fingerprints": ["Repository not found"],
     "fingerprint_only": True},
    {"service": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed"],
     "fingerprint_only": False},
    {"service": "Readme.io", "cnames": ["readme.io"],
     "fingerprints": ["Project doesnt exist... yet!"],
     "fingerprint_only": True},
    {"service": "Unbounce", "cnames": ["unbouncepages.com"],
     "fingerprints": ["The requested URL was not found on this server."],
     "fingerprint_only": False},
    {"service": "Help Scout", "cnames": ["helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company:"],
     "fingerprint_only": True},
    {"service": "Cargo Collective", "cnames": ["cargocollective.com"],
     "fingerprints": ["If you're moving your domain away from Cargo"],
     "fingerprint_only": True},
    {"service": "Microsoft Azure", "cnames": ["azurewebsites.net", "cloudapp.net",
                                              "trafficmanager.net", "blob.core.windows.net",
                                              "azureedge.net", "azure-api.net"],
     "fingerprints": ["404 Web Site not found"],
     "fingerprint_only": False, "note": "Azure cogu zaman edge-case; mutlaka elle dogrula"},
]


# AWS tarafindan rastgele/hesaba ozel uretilen, saldirgan tarafindan YENIDEN
# ALINAMAYAN altyapi. Bunlara sarkan (dangling) CNAME bir hijyen sorunu olabilir
# ama subdomain takeover DEGILDIR -> aday olarak isaretleme.
_NON_TAKEOVERABLE_CNAME = (
    "elb.amazonaws.com",          # Elastic Load Balancer
    "execute-api",                # API Gateway (d-xxx.execute-api...)
    "elasticbeanstalk.com",       # Elastic Beanstalk (bolgeye gore degisir; ihtiyatli)
    "awsglobalaccelerator.com",
    "compute.amazonaws.com",      # EC2
    "compute-1.amazonaws.com",
    "rds.amazonaws.com",
    "cache.amazonaws.com",
    "vpce.amazonaws.com",
)


def _is_non_takeoverable(cname: str) -> bool:
    c = (cname or "").lower()
    return any(m in c for m in _NON_TAKEOVERABLE_CNAME)


def _match_service_by_cname(cname: str) -> dict | None:
    c = cname.lower()
    if _is_non_takeoverable(c):
        return None
    for svc in SERVICES:
        if any(pat in c for pat in svc["cnames"]):
            return svc
    return None


def _fetch_text(client: HttpClient, host: str) -> str:
    for scheme in ("https", "http"):
        try:
            resp = client.get(f"{scheme}://{host}")
        except OutOfScopeError:
            return ""
        if resp is not None:
            return resp.text
    return ""


def check_host(client: HttpClient, resolver: Resolver, host: str) -> TakeoverFinding | None:
    rec = resolver.resolve(host)
    cname = (rec.cname or "").rstrip(".")
    body = _fetch_text(client, host)
    body_low = body.lower()

    # 1) CNAME bir servise isaret ediyor mu?
    svc = _match_service_by_cname(cname) if cname else None

    # 2) Govde imzasi eslesmesi (servisten bagimsiz tara)
    for service in SERVICES:
        for fp in service["fingerprints"]:
            if fp.lower() in body_low:
                cname_match = bool(svc and svc["service"] == service["service"])
                if cname_match:
                    return TakeoverFinding(
                        host=host, service=service["service"], cname=cname,
                        confidence="high",
                        reason="CNAME servise isaret ediyor + sahipsiz-kaynak imzasi eslesti",
                        evidence=fp,
                    )
                if service.get("fingerprint_only"):
                    return TakeoverFinding(
                        host=host, service=service["service"], cname=cname,
                        confidence="medium",
                        reason="Sahipsiz-kaynak imzasi eslesti (CNAME dogrulanamadi)",
                        evidence=fp,
                    )

    # 3) CNAME servise isaret ediyor ama hedef cozulmuyor -> dangling
    if svc and cname:
        target_rec = resolver.resolve(cname)
        if not target_rec.resolves:
            return TakeoverFinding(
                host=host, service=svc["service"], cname=cname,
                confidence="medium",
                reason="CNAME servise isaret ediyor ama hedef cozulmuyor (dangling)",
                evidence=f"CNAME -> {cname} (NXDOMAIN/bos)",
            )

    return None


def detect(
    client: HttpClient, resolver: Resolver, hosts: list[str], *, threads: int = 20
) -> list[TakeoverFinding]:
    info(f"Subdomain takeover taramasi: {len(hosts)} host")
    results: list[TakeoverFinding] = []

    def _one(host: str) -> TakeoverFinding | None:
        try:
            return check_host(client, resolver, host)
        except Exception:
            return None

    for f in parallel_map(_one, hosts, threads=threads):
        if f:
            warn(f"[TAKEOVER-{f.confidence.upper()}] {f.host} -> {f.service} "
                 f"({f.reason})")
            results.append(f)
    if not results:
        good("Takeover adayi bulunamadi.")
    return results
