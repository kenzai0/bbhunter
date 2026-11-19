"""
Erisim kontrolu (IDOR / yetki atlatma) karsilastirmasi.

Fikir (Burp "Autorize" mantigi): Bir istegi SAHIBI olan test hesabinin
oturumuyla ve diger KENDI test hesaplarinin (ya da oturumsuz) oturumlariyla
tekrar gonderir; yanitlari karsilastirir. Baska bir hesabin oturumuyla da ayni
veri donuyorsa bu bir IDOR / yetki atlatma ADAYIDIR.

GUVENLIK VE KURALLAR:
  - Yalnizca SENIN olusturdugun test hesaplarini kullan. Gercek kullanicilarin
    oturumlarini ya da verilerini asla kullanma.
  - Istekler scope motorundan gecer; kapsam disi hostlar engellenir.
  - Varsayilan olarak yalnizca guvenli metotlar (GET/HEAD/OPTIONS) gonderilir.
    Durum degistiren istekler (POST/PUT/PATCH/DELETE) icin --allow-unsafe gerekir;
    bunlari yalnizca kendi test hesaplarinin verisi uzerinde ve programin
    izin verdigi olcude kullan.

Girdi:
  - Ham HTTP istek dosyalari (Burp: sag tik > "Copy to file" ya da
    "Save item"in ham istegi). Bir dosyada '======' satiriyla ayrilmis birden
    cok istek olabilir.
  - Kimlik dosyalari: her satiri bir header olan duz metin
    (orn. "Cookie: session=..." veya "Authorization: Bearer ...").
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from .http_client import HttpClient, OutOfScopeError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Kimlik degistirilirken orijinal istekten SILINECEK header'lar
AUTH_HEADERS = {"cookie", "authorization", "x-csrf-token", "x-xsrf-token",
                "x-auth-token", "x-api-key"}
# Istek tekrarlanirken anlamsiz/zararli olan header'lar
_DROP_HEADERS = {"content-length", "host", "connection", "accept-encoding",
                 "if-none-match", "if-modified-since"}
_SEP = "======"


@dataclass
class RawRequest:
    method: str
    url: str
    headers: dict
    body: bytes = b""
    source: str = ""


@dataclass
class Identity:
    name: str
    headers: dict = field(default_factory=dict)   # bos ise oturumsuz (anonim)


@dataclass
class Attempt:
    identity: str
    status: int | None
    length: int
    similarity: float          # sahibin yanitina benzerlik (0-1)
    markers_found: list = field(default_factory=list)
    verdict: str = ""          # owner | enforced | bypass? | check | error


@dataclass
class AuthzResult:
    request: RawRequest
    attempts: list = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return any(a.verdict == "bypass?" for a in self.attempts)


# ---------------- ayristirma ----------------

def parse_raw_request(text: str, scheme: str = "https", source: str = "") -> RawRequest:
    text = text.replace("\r\n", "\n").lstrip("\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"Gecersiz istek satiri: {lines[0]!r} ({source})")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip()] = v.strip()
    if target.startswith(("http://", "https://")):
        url = target
    else:
        host = next((v for k, v in headers.items() if k.lower() == "host"), "")
        if not host:
            raise ValueError(f"Host header'i yok ({source})")
        url = f"{scheme}://{host}{target}"
    return RawRequest(method, url, headers, body.rstrip("\n").encode("utf-8"), source)


def load_requests(paths: list[str], scheme: str = "https") -> list[RawRequest]:
    out: list[RawRequest] = []
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        files += sorted(x for x in pp.iterdir() if x.is_file()) if pp.is_dir() else [pp]
    for f in files:
        txt = f.read_text(encoding="utf-8-sig", errors="replace")
        for i, chunk in enumerate(c for c in txt.split(_SEP) if c.strip()):
            out.append(parse_raw_request(chunk, scheme, source=f"{f.name}#{i + 1}"))
    return out


def load_identity(spec: str) -> Identity:
    """'ad:dosya' -> Identity. 'anon' (dosyasiz) oturumsuz kimliktir."""
    name, _, path = spec.partition(":")
    name = name.strip()
    if not name:
        raise ValueError(f"Kimlik adi bos: {spec!r}")
    ident = Identity(name)
    if path.strip():
        for ln in Path(path.strip()).read_text(encoding="utf-8-sig").splitlines():
            if ":" in ln and not ln.lstrip().startswith("#"):
                k, _, v = ln.partition(":")
                ident.headers[k.strip()] = v.strip()
    return ident


# ---------------- karsilastirma ----------------

def similarity(a: bytes, b: bytes, limit: int = 50_000) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:limit], b[:limit], autojunk=False).quick_ratio()


def _looks_denied(status: int | None, body: bytes) -> bool:
    if status in (401, 403, 404):
        return True
    if status in (301, 302, 303, 307, 308):
        return True     # cogunlukla giris sayfasina yonlendirme
    low = body[:4000].lower()
    return any(w in low for w in (b"unauthorized", b"forbidden", b"access denied",
                                   b"not authorized", b"please log in", b"sign in"))


def judge(owner_status, owner_body, status, body, threshold=0.9) -> tuple[str, float]:
    if status is None:
        return "error", 0.0
    sim = similarity(owner_body, body)
    if owner_status is None or owner_status >= 400:
        return "check", sim          # sahibi bile erisemiyorsa karsilastirma anlamsiz
    if _looks_denied(status, body):
        return "enforced", sim
    if status == owner_status and sim >= threshold:
        return "bypass?", sim
    return "check", sim


def _headers_for(req: RawRequest, ident: Identity) -> dict:
    h = {k: v for k, v in req.headers.items()
         if k.lower() not in _DROP_HEADERS and k.lower() not in AUTH_HEADERS}
    h.update(ident.headers)
    return h


def run(client: HttpClient, requests_: list[RawRequest], identities: list[Identity], *,
        markers: dict | None = None, allow_unsafe: bool = False,
        threshold: float = 0.9) -> list[AuthzResult]:
    """identities[0] istegin SAHIBIDIR; digerleri onunla karsilastirilir."""
    if len(identities) < 2:
        raise ValueError("En az iki kimlik gerekli (sahip + en az bir baska hesap/anon)")
    markers = markers or {}
    results: list[AuthzResult] = []
    for req in requests_:
        res = AuthzResult(req)
        if req.method not in SAFE_METHODS and not allow_unsafe:
            res.attempts.append(Attempt("-", None, 0, 0.0, verdict="skipped-unsafe"))
            results.append(res)
            continue
        owner_status, owner_body = None, b""
        for i, ident in enumerate(identities):
            try:
                r = client.request(req.method, req.url, headers=_headers_for(req, ident),
                                   data=req.body or None, allow_redirects=False)
            except OutOfScopeError:
                res.attempts.append(Attempt(ident.name, None, 0, 0.0, verdict="out-of-scope"))
                break
            status = r.status if r else None
            body = r.body if r else b""
            found = [m for m in markers.get(identities[0].name, []) if m.encode() in body]
            if i == 0:
                owner_status, owner_body = status, body
                res.attempts.append(Attempt(ident.name, status, len(body), 1.0, found, "owner"))
                continue
            verdict, sim = judge(owner_status, owner_body, status, body, threshold)
            if found and verdict != "enforced":
                verdict = "bypass?"   # sahibin verisi baskasinin yanitinda gorundu
            res.attempts.append(Attempt(ident.name, status, len(body), sim, found, verdict))
        results.append(res)
    return results


def write_markdown(results: list[AuthzResult], path) -> str:
    lines = ["# Erisim Kontrolu Karsilastirmasi", "",
             "> `bypass?` yalnizca bir ADAYDIR. Yanitlari Burp'te yan yana koy ve diger "
             "hesabin GERCEKTEN sahibin verisini gordugunu dogrula (ayni sayfa sablonu "
             "ya da herkese acik veri yanlis alarm uretir).", ""]
    sus = [r for r in results if r.suspicious]
    lines.append(f"Toplam istek: {len(results)} | Supheli: {len(sus)}")
    lines.append("")
    for r in sorted(results, key=lambda x: not x.suspicious):
        mark = "🔴 " if r.suspicious else ""
        lines.append(f"## {mark}{r.request.method} {r.request.url}")
        lines.append(f"_kaynak: {r.request.source}_")
        lines.append("")
        lines.append("| Kimlik | Durum | Boyut | Benzerlik | Isaretci | Karar |")
        lines.append("|---|---|---|---|---|---|")
        for a in r.attempts:
            lines.append(f"| {a.identity} | {a.status if a.status is not None else '-'} | "
                         f"{a.length} | {a.similarity:.2f} | "
                         f"{', '.join(a.markers_found) or '-'} | {a.verdict} |")
        lines.append("")
    text = "\n".join(lines) + "\n"
    Path(path).write_text(text, encoding="utf-8")
    return text
