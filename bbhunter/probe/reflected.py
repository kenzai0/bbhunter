"""
Reflected-parametre guvenli problari (XSS / open-redirect adaylari + SSRF
aday siniflandirmasi). Hepsi non-destructive: zararsiz isaretciler enjekte
eder, sonucu gozlemler; calisan payload uretmez, veri degistirmez.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..http_client import HttpClient, OutOfScopeError
from ..util import dedup_keep_order, good, info, parallel_map, warn

# XSS baglami icin gozlenecek ozel karakterler. Bunlar tek baslarina exploit
# DEGILDIR; yalnizca "encode'lanmadan geri donuyor mu?" sinyali verir.
_SPECIAL_CHARS = ["<", ">", '"', "'", "(", ")", "{", "}", ";", "`"]

# Open-redirect icin zararsiz, cozulmeyen ornek hedef (RFC 2606 .example TLD).
_REDIRECT_CANARY_HOST = "bbhunter-redirect-probe.example"
_REDIRECT_CANARY = f"https://{_REDIRECT_CANARY_HOST}/"

# Heuristik: bu isimli parametreler genelde URL/yonlendirme alir.
_REDIRECT_PARAM_HINTS = {
    "url", "uri", "redirect", "redirect_url", "redirecturl", "redir", "next",
    "return", "returnurl", "return_url", "returnto", "return_to", "goto",
    "dest", "destination", "continue", "forward", "callback", "cb", "to",
    "out", "view", "u", "link", "target", "rurl", "checkout_url", "image_url",
}
# Heuristik: bu isimli/degerli parametreler SSRF icin manuel inceleme adayidir.
_SSRF_PARAM_HINTS = {
    "url", "uri", "u", "link", "src", "source", "dest", "target", "host",
    "domain", "site", "page", "feed", "rss", "webhook", "callback", "api",
    "endpoint", "proxy", "fetch", "load", "path", "file", "document", "data",
    "reference", "ref", "img", "image", "imageurl", "image_url", "avatar",
    "upload", "download", "resource", "server", "port", "ip",
}


@dataclass
class ReflectionFinding:
    url: str
    param: str
    reflected: bool = False
    reflected_chars: list = field(default_factory=list)  # encode'lanmadan donen ozel karakterler
    severity: str = "info"

    @property
    def is_candidate(self) -> bool:
        # Ozel karakter(ler) encode'lanmadan donuyorsa XSS adayidir.
        return self.reflected and bool(self.reflected_chars)


@dataclass
class RedirectFinding:
    url: str
    param: str
    location: str
    kind: str  # "header" | "meta" | "javascript"
    severity: str = "medium"


@dataclass
class SsrfCandidate:
    url: str
    param: str
    reason: str
    severity: str = "info"


# --------------------------------------------------------------------------
# Yardimcilar
# --------------------------------------------------------------------------
def _canary() -> str:
    return "bbhr" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    new_query = urlencode(new_pairs, safe="/:?&=")
    return urlunparse(parts._replace(query=new_query))


def _param_targets(urls: list[str]) -> list[tuple[str, list[str]]]:
    """
    URL listesini (url, param_isimleri) ikililerine cevirir ve
    (host, path, sirali-param-seti) bazinda tekillestirir; boylece binlerce
    benzer arsiv URL'si ayni parametreyi tekrar tekrar test etmez.
    """
    seen: set = set()
    out: list[tuple[str, list[str]]] = []
    for u in urls:
        parts = urlparse(u)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not pairs:
            continue
        names = sorted({k for k, _ in pairs})
        sig = (parts.netloc, parts.path, tuple(names))
        if sig in seen:
            continue
        seen.add(sig)
        out.append((u, [k for k, _ in pairs]))
    return out


# --------------------------------------------------------------------------
# Reflection (XSS adayi)
# --------------------------------------------------------------------------
def test_reflection_single(client: HttpClient, url: str, param: str) -> ReflectionFinding:
    f = ReflectionFinding(url=url, param=param)
    canary = _canary()

    try:
        resp = client.get(_set_param(url, param, canary))
    except OutOfScopeError:
        return f
    if resp is None:
        return f

    body = resp.body or b""
    if canary.encode() not in body:
        return f  # yansima yok
    f.reflected = True

    # Ikinci asama: canary + ozel karakterler. Hangi karakterler encode'lanmadan
    # geri donuyor? (Bu bir exploit degil; yalnizca baglam sinyali.)
    probe_val = canary + "".join(_SPECIAL_CHARS)
    try:
        resp2 = client.get(_set_param(url, param, probe_val))
    except OutOfScopeError:
        return f
    if resp2 is None:
        return f

    body2 = resp2.body or b""
    survived = []
    for ch in _SPECIAL_CHARS:
        # canary + karakter ikilisi ham olarak goruluyorsa karakter encode'lanmamis
        if (canary + ch).encode() in body2:
            survived.append(ch)
    f.reflected_chars = survived

    # Siddet: tehlikeli karakterler (< > ") survive ediyorsa daha yuksek sinyal.
    dangerous = {"<", ">", '"'}
    if dangerous.intersection(survived):
        f.severity = "medium"
    elif survived:
        f.severity = "low"
    else:
        f.severity = "info"
    return f


def test_reflection(
    client: HttpClient, urls: list[str], *, threads: int = 20
) -> list[ReflectionFinding]:
    targets = _param_targets(urls)
    jobs = [(u, p) for (u, params) in targets for p in dedup_keep_order(params)]
    info(f"Reflection probu: {len(targets)} benzersiz endpoint, {len(jobs)} parametre")

    def _one(job) -> ReflectionFinding:
        url, param = job
        return test_reflection_single(client, url, param)

    results: list[ReflectionFinding] = []
    for f in parallel_map(_one, jobs, threads=threads):
        if f.reflected:
            if f.is_candidate:
                good(f"[{f.severity.upper()}] XSS adayi: {f.param} yansiyor "
                     f"(encode'suz: {''.join(f.reflected_chars)}) @ {f.url}")
            else:
                good(f"[INFO] {f.param} yansiyor (ozel karakterler encode'lu) @ {f.url}")
            results.append(f)
    return results


# --------------------------------------------------------------------------
# Open redirect adayi
# --------------------------------------------------------------------------
def _find_meta_or_js_redirect(body: bytes) -> str | None:
    import re
    m = re.search(rb"""http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)""", body, re.I)
    if m:
        return m.group(1).decode("utf-8", "replace")
    m = re.search(rb"""(?:location\.(?:href|replace|assign)\s*[=(]\s*)["']([^"']+)["']""", body, re.I)
    if m:
        return m.group(1).decode("utf-8", "replace")
    return None


def test_open_redirect_single(client: HttpClient, url: str, param: str) -> RedirectFinding | None:
    try:
        resp = client.get(_set_param(url, param, _REDIRECT_CANARY), allow_redirects=False)
    except OutOfScopeError:
        return None
    if resp is None:
        return None

    # 1) Location basligi
    loc = next((v for k, v in resp.headers.items() if k.lower() == "location"), "")
    if _REDIRECT_CANARY_HOST in loc:
        return RedirectFinding(url=url, param=param, location=loc, kind="header")

    # 2) meta refresh / JS yonlendirme
    body_loc = _find_meta_or_js_redirect(resp.body or b"")
    if body_loc and _REDIRECT_CANARY_HOST in body_loc:
        kind = "meta" if "refresh" in (resp.text[:2000].lower()) else "javascript"
        return RedirectFinding(url=url, param=param, location=body_loc, kind=kind)
    return None


def test_open_redirect(
    client: HttpClient, urls: list[str], *, threads: int = 20, only_hinted: bool = True
) -> list[RedirectFinding]:
    targets = _param_targets(urls)
    jobs = []
    for u, params in targets:
        for p in dedup_keep_order(params):
            if only_hinted and p.lower() not in _REDIRECT_PARAM_HINTS:
                continue
            jobs.append((u, p))
    info(f"Open-redirect probu: {len(jobs)} parametre")

    def _one(job) -> RedirectFinding | None:
        url, param = job
        return test_open_redirect_single(client, url, param)

    results: list[RedirectFinding] = []
    for rf in parallel_map(_one, jobs, threads=threads):
        if rf:
            good(f"[MEDIUM] Open-redirect adayi: {rf.param} -> {rf.location} "
                 f"({rf.kind}) @ {rf.url}")
            results.append(rf)
    return results


# --------------------------------------------------------------------------
# SSRF aday siniflandirmasi (PASIF - aktif test yok)
# --------------------------------------------------------------------------
def classify_ssrf_candidates(urls: list[str]) -> list[SsrfCandidate]:
    """
    URL/host alan gorunen parametreleri MANUEL inceleme icin isaretler.
    Aktif SSRF testi yapmaz (OOB listener gerektirir ve risklidir).
    """
    info("SSRF aday siniflandirmasi (pasif)")
    targets = _param_targets(urls)
    out: list[SsrfCandidate] = []
    seen: set = set()
    for u, _ in targets:
        parts = urlparse(u)
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            lname = name.lower()
            reason = None
            if lname in _SSRF_PARAM_HINTS:
                reason = f"parametre ismi '{name}' URL/host alabilir"
            elif value.startswith(("http://", "https://", "//")):
                reason = f"deger URL gibi gorunuyor ({value[:40]})"
            if reason:
                sig = (parts.netloc, parts.path, lname)
                if sig in seen:
                    continue
                seen.add(sig)
                out.append(SsrfCandidate(url=u, param=name, reason=reason))
    for c in out:
        warn(f"[SSRF-ADAY] {c.param}: {c.reason} @ {c.url}  (manuel dogrula)")
    return out
