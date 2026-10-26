"""
Teknoloji parmak izi: HTTP basliklarindan, cerezlerden ve govde imzalarindan
calisan teknolojileri (sunucu, framework, CMS, CDN) tahmin eder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..http_client import HttpClient, OutOfScopeError
from ..util import good, info, parallel_map


@dataclass
class Fingerprint:
    url: str
    technologies: list[str] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""


# (teknoloji adi, baslik adi regex, deger regex)  -> baslik imzalari
_HEADER_SIGS = [
    ("nginx", "server", r"nginx"),
    ("Apache", "server", r"apache"),
    ("IIS", "server", r"iis|microsoft-iis"),
    ("LiteSpeed", "server", r"litespeed"),
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("Akamai", "server", r"akamai"),
    ("AWS CloudFront", "via", r"cloudfront"),
    ("AWS CloudFront", "x-amz-cf-id", r".+"),
    ("Varnish", "via", r"varnish"),
    ("PHP", "x-powered-by", r"php"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("ASP.NET", "x-aspnet-version", r".+"),
    ("Express", "x-powered-by", r"express"),
    ("Next.js", "x-powered-by", r"next\.js"),
    ("Django", "x-frame-options", r""),  # zayif; govdeyle dogrulanir
]

# (teknoloji, govde regex)  -> HTML imzalari
_BODY_SIGS = [
    ("WordPress", rb"wp-content|wp-includes|/wp-json/"),
    ("Drupal", rb"Drupal\.settings|/sites/default/files|drupal\.js"),
    ("Joomla", rb"/media/jui/|com_content|Joomla!"),
    ("Magento", rb"Mage\.Cookies|/skin/frontend/|magento"),
    ("Shopify", rb"cdn\.shopify\.com|Shopify\.theme"),
    ("React", rb"__REACT_DEVTOOLS|data-reactroot|react-dom"),
    ("Vue.js", rb"data-v-[0-9a-f]{8}|__vue__|vue\.runtime"),
    ("Angular", rb"ng-version|ng-app|angular\.js"),
    ("Laravel", rb"laravel_session|XSRF-TOKEN"),
    ("jQuery", rb"jquery(\.min)?\.js|jQuery v"),
    ("Bootstrap", rb"bootstrap(\.min)?\.css|bootstrap(\.min)?\.js"),
    ("Google Analytics", rb"google-analytics\.com/analytics|gtag\(|GoogleAnalyticsObject"),
]


def fingerprint_response(url: str, headers: dict, body: bytes) -> Fingerprint:
    fp = Fingerprint(url=url)
    low_headers = {k.lower(): (v or "") for k, v in headers.items()}
    fp.server = low_headers.get("server", "")
    fp.powered_by = low_headers.get("x-powered-by", "")

    techs: set[str] = set()
    for tech, header, pattern in _HEADER_SIGS:
        val = low_headers.get(header)
        if val is None:
            continue
        if pattern == "" or re.search(pattern, val, re.I):
            techs.add(tech)

    for tech, pattern in _BODY_SIGS:
        if re.search(pattern, body or b"", re.I):
            techs.add(tech)

    # Set-Cookie ipuclari
    cookies = low_headers.get("set-cookie", "")
    if "laravel_session" in cookies.lower():
        techs.add("Laravel")
    if re.search(r"phpsessid", cookies, re.I):
        techs.add("PHP")
    if re.search(r"jsessionid", cookies, re.I):
        techs.add("Java")
    if re.search(r"asp\.net_sessionid|\.aspxauth", cookies, re.I):
        techs.add("ASP.NET")

    fp.technologies = sorted(techs)
    return fp


def fingerprint(client: HttpClient, urls: list[str], threads: int = 20) -> list[Fingerprint]:
    info(f"Teknoloji parmak izi: {len(urls)} URL")
    results: list[Fingerprint] = []

    def _one(url: str) -> Fingerprint | None:
        try:
            resp = client.get(url)
        except OutOfScopeError:
            return None
        if resp is None:
            return None
        return fingerprint_response(url, resp.headers, resp.body)

    for fp in parallel_map(_one, urls, threads=threads):
        if fp and fp.technologies:
            good(f"{fp.url} -> {', '.join(fp.technologies)}")
            results.append(fp)
    return results
