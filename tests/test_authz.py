from __future__ import annotations

import pytest

from bbhunter import authz
from bbhunter.config import Config
from bbhunter.http_client import HttpClient
from bbhunter.scope import Scope


def _client():
    cfg = Config()
    cfg.rate_limit = 0
    cfg.timeout = 5
    return HttpClient(cfg, Scope.from_lists(["127.0.0.1"]))


# ---------- saf ayristirma / karar ----------

def test_parse_raw_request_builds_url_from_host_header():
    raw = "GET /account?id=7 HTTP/1.1\nHost: app.example.com\nCookie: s=1\n\n"
    req = authz.parse_raw_request(raw, scheme="https")
    assert req.method == "GET"
    assert req.url == "https://app.example.com/account?id=7"
    assert req.headers["Cookie"] == "s=1"


def test_parse_raw_request_keeps_absolute_url_and_body():
    raw = "POST https://app.example.com/x HTTP/1.1\nHost: app.example.com\n\na=1&b=2"
    req = authz.parse_raw_request(raw)
    assert req.url == "https://app.example.com/x"
    assert req.body == b"a=1&b=2"


def test_parse_raw_request_rejects_garbage():
    with pytest.raises(ValueError):
        authz.parse_raw_request("notarequest\n\n")


def test_load_identity_anon_has_no_headers(tmp_path):
    assert authz.load_identity("anon").headers == {}
    f = tmp_path / "o.txt"
    f.write_text("Cookie: session=abc\n# yorum\nAuthorization: Bearer t\n", encoding="utf-8")
    ident = authz.load_identity(f"owner:{f}")
    assert ident.name == "owner"
    assert ident.headers == {"Cookie": "session=abc", "Authorization": "Bearer t"}


def test_judge_marks_bypass_when_same_status_and_similar():
    verdict, sim = authz.judge(200, b"secret data here", 200, b"secret data here")
    assert verdict == "bypass?" and sim == 1.0


def test_judge_marks_enforced_on_403():
    verdict, _ = authz.judge(200, b"secret", 403, b"forbidden")
    assert verdict == "enforced"


def test_judge_check_when_owner_itself_denied():
    verdict, _ = authz.judge(403, b"forbidden", 403, b"forbidden")
    assert verdict == "check"


# ---------- uctan uca (yerel sahte sunucu) ----------

def _owner_only(self):
    # Sahip cerezi varsa sahibin verisi; yoksa reddet.
    cookie = self.headers.get("Cookie", "")
    if "session=owner" in cookie:
        return b"owner private email owner@example.com balance 4242"
    self.send_response  # noqa - sadece body donduruyoruz; status 200 sabit
    return b"forbidden: access denied"


def test_enforced_access_control_is_not_flagged(server):
    base, routes, seen = server
    # Her kimlik icin ayni path ama cerezden farkli yanit:
    def body(self):
        return _owner_only(self)
    # enforced: yetkisizde "access denied" gorunur -> _looks_denied true
    routes["/me"] = (200, {}, body)
    reqs = [authz.parse_raw_request(
        f"GET /me HTTP/1.1\nHost: 127.0.0.1\nCookie: session=owner\n\n", scheme="http")]
    reqs[0].url = base + "/me"
    owner = authz.Identity("owner", {"Cookie": "session=owner"})
    other = authz.Identity("other", {"Cookie": "session=other"})
    res = authz.run(_client(), reqs, [owner, other])
    assert len(res) == 1
    verdicts = {a.identity: a.verdict for a in res[0].attempts}
    assert verdicts["owner"] == "owner"
    assert verdicts["other"] == "enforced"
    assert not res[0].suspicious


def test_idor_bypass_is_flagged(server):
    base, routes, seen = server
    # Zafiyetli: cerez ne olursa olsun ayni veriyi dondurur.
    secret = b"owner private email owner@example.com balance 4242"
    routes["/leak"] = (200, {}, lambda self: secret)
    req = authz.parse_raw_request(
        "GET /leak HTTP/1.1\nHost: 127.0.0.1\nCookie: session=owner\n\n", scheme="http")
    req.url = base + "/leak"
    owner = authz.Identity("owner", {"Cookie": "session=owner"})
    other = authz.Identity("other", {"Cookie": "session=other"})
    res = authz.run(_client(), [req], [owner, other],
                    markers={"owner": ["owner@example.com"]})
    assert res[0].suspicious
    other_attempt = next(a for a in res[0].attempts if a.identity == "other")
    assert other_attempt.verdict == "bypass?"
    assert "owner@example.com" in other_attempt.markers_found


def test_unsafe_method_skipped_without_flag(server):
    base, routes, seen = server
    routes["/del"] = (200, {}, b"ok")
    req = authz.parse_raw_request(
        "DELETE /del HTTP/1.1\nHost: 127.0.0.1\n\n", scheme="http")
    req.url = base + "/del"
    res = authz.run(_client(), [req],
                    [authz.Identity("owner"), authz.Identity("other")])
    assert res[0].attempts[0].verdict == "skipped-unsafe"
    # hicbir DELETE istegi gitmedi
    assert not any(m == "DELETE" for m, _, _ in seen)


def test_run_requires_two_identities():
    with pytest.raises(ValueError):
        authz.run(_client(), [], [authz.Identity("solo")])
