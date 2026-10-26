"""
Nuclei (YAML) template'lerini bbhunter engine formatina (JSON/dict) cevirir.

Birincil yol PyYAML'dir (tam dogruluk). Kurulu degilse, Nuclei HTTP
template'lerinin YAYGIN alt kumesini isleyen yerlesik bir mini-parser devreye
girer ve PyYAML onerir (mini-parser block-scalar/yorum gibi uc durumlarda
kayiplidir; guvenlik template'lerinde tam dogruluk icin PyYAML sart).

Desteklenen Nuclei ozellikleri:
  - info: name, severity, reference, tags
  - http/requests: method, path ({{BaseURL}} govde-goreli yapilir), headers, body
  - matchers: status, word, regex (part: body/header/all; condition; negative)
  - matchers-condition

Desteklenmeyen (template atlanir veya ilgili matcher duser) - sebep raporlanir:
  - dsl matcher'lari, extractors, payloads/fuzzing, raw istekler,
    cok-adimli (req-condition) akislar, yikici metotlar (GET/POST/HEAD/OPTIONS disi)
"""

from __future__ import annotations

from pathlib import Path

from ..util import dedup_keep_order, info, warn

try:
    import yaml  # PyYAML
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

_SAFE_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
_VALID_SEV = {"info", "low", "medium", "high", "critical", "unknown"}


class SkipTemplate(Exception):
    """Bir template desteklenmeyen bir ozellik iCerdiginde atlanir."""


# --------------------------------------------------------------------------
# YAML yukleme
# --------------------------------------------------------------------------
def load_yaml(text: str) -> dict:
    if _HAVE_YAML:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise SkipTemplate("YAML kok bir map degil")
        return data
    return _mini_yaml(text)


# --------------------------------------------------------------------------
# Nuclei -> engine donusumu
# --------------------------------------------------------------------------
def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _base_relative(path: str) -> str:
    """'{{BaseURL}}/foo?x=1' -> '/foo?x=1'. BasePath vb. desteklenmez."""
    p = path.strip()
    for marker in ("{{BaseURL}}", "{{RootURL}}", "{{Hostname}}"):
        if marker in p:
            p = p.replace(marker, "")
    if "{{" in p:
        # cozulemeyen baska interpolasyon (payload/degisken)
        raise SkipTemplate(f"desteklenmeyen interpolasyon: {path}")
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def _convert_matcher(m: dict) -> dict:
    mtype = (m.get("type") or "").lower()
    neg = bool(m.get("negative", False))
    part = m.get("part", "body")
    ci = bool(m.get("case-insensitive", False))

    if mtype == "status":
        return {"type": "status", "values": [int(s) for s in _as_list(m.get("status"))],
                "negative": neg}

    if mtype == "word":
        words = [str(w) for w in _as_list(m.get("words"))]
        return {"type": "word", "part": part, "words": words,
                "condition": m.get("condition", "or"),
                "case_insensitive": ci, "negative": neg}

    if mtype == "regex":
        patterns = [str(r) for r in _as_list(m.get("regex"))]
        return {"type": "regex", "part": part, "patterns": patterns,
                "condition": m.get("condition", "or"),
                "case_insensitive": ci, "negative": neg}

    if mtype in ("dsl", "binary", "xpath"):
        raise SkipTemplate(f"desteklenmeyen matcher tipi: {mtype}")

    raise SkipTemplate(f"bilinmeyen matcher tipi: {mtype}")


def _convert_request(req: dict) -> list[dict]:
    """Bir Nuclei istegini (coklu path olabilir) engine isteklerine cevirir."""
    if "raw" in req:
        raise SkipTemplate("raw istek desteklenmiyor")
    if req.get("payloads") or req.get("attack") or req.get("fuzzing"):
        raise SkipTemplate("payload/fuzzing desteklenmiyor")

    method = (req.get("method") or "GET").upper()
    if method not in _SAFE_METHODS:
        raise SkipTemplate(f"guvensiz/desteklenmeyen metot: {method}")

    raw_matchers = req.get("matchers")
    if not raw_matchers:
        raise SkipTemplate("matcher yok")
    matchers = []
    for m in raw_matchers:
        try:
            matchers.append(_convert_matcher(m))
        except SkipTemplate:
            continue  # desteklenmeyen matcher'i atla, digerleriyle devam et
    if not matchers:
        raise SkipTemplate("desteklenen matcher kalmadi")

    mcond = req.get("matchers-condition", "or")
    headers = req.get("headers") if isinstance(req.get("headers"), dict) else None
    body = req.get("body")

    paths = _as_list(req.get("path")) or ["{{BaseURL}}"]
    out = []
    for raw_path in paths:
        try:
            rel = _base_relative(str(raw_path))
        except SkipTemplate:
            continue
        out.append({
            "method": method,
            "path": rel,
            "headers": headers,
            "body": body,
            "matchers_condition": mcond,
            "matchers": matchers,
            "stop_at_first_match": True,
        })
    if not out:
        raise SkipTemplate("cevrilebilir path yok")
    return out


def convert_template(nt: dict) -> dict:
    """Nuclei template dict -> engine template dict. Desteklenmezse SkipTemplate."""
    tid = nt.get("id") or "nuclei-unknown"
    inf = nt.get("info") or {}
    sev = str(inf.get("severity", "info")).lower()
    if sev not in _VALID_SEV:
        sev = "info"
    if sev == "unknown":
        sev = "info"

    refs = _as_list(inf.get("reference"))
    # Nuclei bazen requests, yeni surumlerde http kullanir
    nuclei_reqs = nt.get("http") or nt.get("requests")
    if not nuclei_reqs:
        raise SkipTemplate("http/requests bolumu yok (dns/tcp/headless vb. desteklenmiyor)")
    if len(nuclei_reqs) > 1:
        # cok-adimli akislari (req-condition) guvenli sekilde cevirmiyoruz;
        # yine de her istegi bagimsiz imza olarak ekleriz.
        pass

    engine_requests: list[dict] = []
    for req in nuclei_reqs:
        if req.get("req-condition"):
            raise SkipTemplate("req-condition (cok-adimli) desteklenmiyor")
        engine_requests.extend(_convert_request(req))

    if not engine_requests:
        raise SkipTemplate("cevrilebilir istek yok")

    return {
        "id": tid,
        "name": inf.get("name", tid),
        "severity": sev,
        "reference": [str(r) for r in refs],
        "tags": inf.get("tags", ""),
        "source": "nuclei",
        "requests": engine_requests,
    }


# --------------------------------------------------------------------------
# Toplu ice aktarma
# --------------------------------------------------------------------------
def import_file(path: Path) -> tuple[list[dict], list[tuple[str, str]]]:
    """Tek YAML dosyasi -> (engine_template'ler, atlananlar[(id/dosya, sebep)])."""
    converted: list[dict] = []
    skipped: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        return [], [(str(path), f"okunamadi: {e}")]

    # Bir dosyada birden fazla YAML belgesi olabilir (---)
    docs = []
    if _HAVE_YAML:
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except Exception as e:
            return [], [(str(path), f"YAML hatasi: {e}")]
    else:
        try:
            docs = [_mini_yaml(text)]
        except Exception as e:
            return [], [(str(path), f"mini-parser hatasi: {e}")]

    for doc in docs:
        tid = doc.get("id", path.name)
        try:
            converted.append(convert_template(doc))
        except SkipTemplate as e:
            skipped.append((str(tid), str(e)))
        except Exception as e:  # beklenmeyen bicim
            skipped.append((str(tid), f"beklenmeyen: {e}"))
    return converted, skipped


def import_path(paths: list[str | Path]) -> tuple[list[dict], list[tuple[str, str]]]:
    """Dosya veya dizin(ler)den (ozyinelemeli) Nuclei YAML template'leri ice aktarir."""
    if not _HAVE_YAML:
        warn("PyYAML bulunamadi - sinirli mini-parser kullaniliyor. "
             "Tam dogruluk icin: pip install pyyaml")
    all_tmpls: list[dict] = []
    all_skips: list[tuple[str, str]] = []
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files += sorted(p.rglob("*.yaml")) + sorted(p.rglob("*.yml"))
        elif p.exists():
            files.append(p)
        else:
            all_skips.append((str(p), "yol bulunamadi"))
    info(f"Nuclei ice aktarma: {len(files)} YAML dosyasi")
    for f in files:
        tmpls, skips = import_file(f)
        all_tmpls += tmpls
        all_skips += skips
    # id bazinda tekillestir
    seen: set = set()
    uniq = []
    for t in all_tmpls:
        if t["id"] in seen:
            continue
        seen.add(t["id"])
        uniq.append(t)
    info(f"Cevrildi: {len(uniq)} template, atlandi: {len(all_skips)}")
    return uniq, all_skips


# --------------------------------------------------------------------------
# Mini YAML parser (yedek) - Nuclei HTTP template alt kumesi
# --------------------------------------------------------------------------
class _Line:
    __slots__ = ("indent", "content")

    def __init__(self, indent: int, content: str):
        self.indent = indent
        self.content = content


def _strip_inline_comment(s: str) -> str:
    out, in_s, in_d = [], False, False
    i = 0
    while i < len(s):
        c = s[i]
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == "#" and not in_s and not in_d and (i == 0 or s[i - 1] in " \t"):
            break
        out.append(c)
        i += 1
    return "".join(out).rstrip()


def _tokenize(text: str) -> list[_Line]:
    lines = []
    for raw in text.splitlines():
        if raw.strip() in ("---", "..."):
            continue
        no_tab = raw.replace("\t", "  ")
        stripped = no_tab.lstrip(" ")
        indent = len(no_tab) - len(stripped)
        content = _strip_inline_comment(stripped)
        if not content:
            continue
        lines.append(_Line(indent, content))
    return lines


def _scalar(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    if s.lstrip("-").isdigit():
        try:
            return int(s)
        except ValueError:
            pass
    return s


def _split_kv(content: str):
    """
    Bir satiri (key, value) olarak boler ancak YAML kurali geregi key'i yalnizca
    ':' + bosluk (ya da satir sonu) belirler. 'https://x' gibi degerler map
    olarak yanlis yorumlanmaz. Map satiri degilse None doner.
    """
    in_s = in_d = False
    for idx, c in enumerate(content):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == ":" and not in_s and not in_d:
            nxt = content[idx + 1:idx + 2]
            if nxt == "" or nxt == " ":
                return content[:idx].strip(), content[idx + 1:].strip()
    return None


def _parse_node(lines: list[_Line], i: int):
    indent = lines[i].indent
    if lines[i].content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_map(lines: list[_Line], i: int, indent: int):
    result: dict = {}
    while i < len(lines) and lines[i].indent == indent and not lines[i].content.startswith("- "):
        kv = _split_kv(lines[i].content)
        if kv is None:
            i += 1
            continue
        raw_key, rest = kv
        key = _scalar(raw_key)
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            text, i = _collect_block(lines, i + 1, indent, rest[0])
            result[key] = text
        elif rest == "":
            if i + 1 < len(lines) and lines[i + 1].indent > indent:
                child, i = _parse_node(lines, i + 1)
                result[key] = child
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _scalar(rest)
            i += 1
    return result, i


def _parse_list(lines: list[_Line], i: int, indent: int):
    items = []
    while i < len(lines) and lines[i].indent == indent and lines[i].content.startswith("- "):
        after = lines[i].content[2:].strip()
        if after == "":
            child, i = _parse_node(lines, i + 1)
            items.append(child)
        elif _split_kv(after) is not None:
            # satir ici map girdisi: "- key: val" + bu ogeye ait tum derin satirlar
            sub = [_Line(indent + 2, after)]
            j = i + 1
            while j < len(lines) and lines[j].indent > indent:
                sub.append(_Line(lines[j].indent, lines[j].content))
                j += 1
            m, _ = _parse_map(sub, 0, indent + 2)
            items.append(m)
            i = j
        else:
            items.append(_scalar(after))
            i += 1
    return items, i


def _collect_block(lines: list[_Line], i: int, parent_indent: int, style: str):
    collected = []
    while i < len(lines) and lines[i].indent > parent_indent:
        collected.append(lines[i].content)
        i += 1
    sep = "\n" if style == "|" else " "
    return sep.join(collected), i


def _mini_yaml(text: str) -> dict:
    lines = _tokenize(text)
    if not lines:
        return {}
    val, _ = _parse_node(lines, 0)
    if not isinstance(val, dict):
        raise SkipTemplate("kok bir map degil")
    return val
