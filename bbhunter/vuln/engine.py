"""
Template tabanli zafiyet tarama motoru (nuclei felsefesine benzer, basitlestirilmis).

Template = JSON. Her template bir veya daha fazla istek tanimlar ve her istek
icin matcher'lar (status / word / regex / header) belirtir. Matcher'lar
eslesirse bir Finding uretilir.

TASARIM ILKESI - NON-DESTRUCTIVE:
Motor yalnizca GET/HEAD/OPTIONS ve zararsiz POST'lara izin verir; dosya silme,
veri degistirme gibi yikici istekler template seviyesinde yasaktir. Amac
"var mi/yok mu" tespiti; somurme (exploitation) degil.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..http_client import HttpClient, OutOfScopeError
from ..util import dedup_keep_order, good, info, parallel_map, warn

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class VulnFinding:
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str
    evidence: str = ""
    reference: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Matcher degerlendirme
# --------------------------------------------------------------------------
def _get_part(resp, part: str) -> bytes:
    if part == "body":
        return resp.body or b""
    if part == "header":
        return ("\n".join(f"{k}: {v}" for k, v in resp.headers.items())).encode()
    if part == "status":
        return str(resp.status).encode()
    # "all"
    hdr = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return (hdr + "\n\n").encode() + (resp.body or b"")


def _eval_matcher(resp, matcher: dict) -> bool:
    mtype = matcher.get("type")
    neg = matcher.get("negative", False)

    def _res(val: bool) -> bool:
        return (not val) if neg else val

    if mtype == "status":
        return _res(resp.status in matcher.get("values", []))

    if mtype == "word":
        part = _get_part(resp, matcher.get("part", "body"))
        words = [w.encode() for w in matcher.get("words", [])]
        cond = matcher.get("condition", "or")
        low = matcher.get("case_insensitive", False)
        hay = part.lower() if low else part
        needles = [w.lower() if low else w for w in words]
        if cond == "and":
            return _res(all(w in hay for w in needles))
        return _res(any(w in hay for w in needles))

    if mtype == "regex":
        part = _get_part(resp, matcher.get("part", "body"))
        flags = re.I if matcher.get("case_insensitive") else 0
        patterns = matcher.get("patterns") or [matcher.get("pattern", "")]
        cond = matcher.get("condition", "or")
        checks = [re.search(p.encode(), part, flags) is not None for p in patterns if p]
        if cond == "and":
            return _res(all(checks))
        return _res(any(checks))

    if mtype == "header":
        name = matcher.get("name", "").lower()
        val = next((v for k, v in resp.headers.items() if k.lower() == name), None)
        if val is None:
            return _res(False)
        if "regex" in matcher:
            return _res(re.search(matcher["regex"], val, re.I) is not None)
        if "value" in matcher:
            return _res(matcher["value"].lower() in val.lower())
        return _res(True)  # sadece varligi

    return False


def _evidence(resp, request: dict) -> str:
    snippet = ""
    body = resp.body or b""
    if body:
        snippet = body[:200].decode("utf-8", "replace").replace("\n", " ")
    return f"status={resp.status} len={resp.length} :: {snippet}"


# --------------------------------------------------------------------------
# Template yukleme
# --------------------------------------------------------------------------
def load_templates(paths: list[str | Path] | None = None) -> list[dict]:
    """Verilen dizin(ler)deki .json template'leri + yerlesikleri yukler."""
    from .templates import BUILTIN_TEMPLATES

    from . import nuclei

    templates = list(BUILTIN_TEMPLATES)
    for p in paths or []:
        p = Path(p)
        if p.is_dir():
            files = list(p.glob("*.json"))
            yaml_files = list(p.rglob("*.yaml")) + list(p.rglob("*.yml"))
        else:
            files = [p] if p.suffix.lower() == ".json" else []
            yaml_files = [p] if p.suffix.lower() in (".yaml", ".yml") else []

        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    templates.extend(data)
                else:
                    templates.append(data)
            except (ValueError, OSError) as e:
                warn(f"Template yuklenemedi {f}: {e}")

        # Nuclei YAML template'leri (varsa) cevirip ekle
        if yaml_files:
            converted, skipped = nuclei.import_path(yaml_files)
            templates.extend(converted)
            for tid, reason in skipped[:10]:
                warn(f"Nuclei atlandi [{tid}]: {reason}")
    # yikici metotlu template'leri reddet
    safe = []
    for t in templates:
        if all(r.get("method", "GET").upper() in _SAFE_METHODS | {"POST"}
               for r in t.get("requests", [])):
            safe.append(t)
        else:
            warn(f"Guvensiz metot iceren template atlandi: {t.get('id')}")
    return safe


# --------------------------------------------------------------------------
# Calistirma
# --------------------------------------------------------------------------
def _run_template(client: HttpClient, base_url: str, tmpl: dict) -> list[VulnFinding]:
    findings: list[VulnFinding] = []
    base = base_url.rstrip("/")

    for req in tmpl.get("requests", []):
        method = req.get("method", "GET").upper()
        if method not in _SAFE_METHODS | {"POST"}:
            continue
        path = req.get("path", "/")
        url = base + (path if path.startswith("/") else "/" + path)
        headers = req.get("headers") or None
        body = req.get("body")

        try:
            resp = client.request(
                method, url,
                headers=headers,
                data=body.encode() if isinstance(body, str) else body,
                allow_redirects=req.get("follow_redirects", False),
            )
        except OutOfScopeError:
            return findings
        if resp is None:
            continue

        matchers = req.get("matchers", [])
        cond = req.get("matchers_condition", "and")
        results = [_eval_matcher(resp, m) for m in matchers]
        matched = all(results) if cond == "and" else any(results)

        if matched:
            findings.append(
                VulnFinding(
                    template_id=tmpl.get("id", "?"),
                    name=tmpl.get("name", tmpl.get("id", "?")),
                    severity=tmpl.get("severity", "info"),
                    url=base_url,
                    matched_at=url,
                    evidence=_evidence(resp, req),
                    reference=tmpl.get("reference", []),
                )
            )
            if req.get("stop_at_first_match", True):
                break
    return findings


def scan(
    client: HttpClient,
    targets: list[str],
    templates: list[dict],
    *,
    min_severity: str = "info",
    threads: int = 20,
) -> list[VulnFinding]:
    targets = dedup_keep_order(targets)
    min_level = SEVERITIES.get(min_severity, 0)
    active = [t for t in templates if SEVERITIES.get(t.get("severity", "info"), 0) >= min_level]
    info(f"Zafiyet taramasi: {len(targets)} hedef x {len(active)} template")

    jobs = [(url, t) for url in targets for t in active]

    def _one(job) -> list[VulnFinding]:
        url, tmpl = job
        return _run_template(client, url, tmpl)

    results: list[VulnFinding] = []
    for batch in parallel_map(_one, jobs, threads=threads):
        for f in batch:
            tag = f.severity.upper()
            good(f"[{tag}] {f.name} @ {f.matched_at}")
            results.append(f)
    results.sort(key=lambda f: -SEVERITIES.get(f.severity, 0))
    return results
