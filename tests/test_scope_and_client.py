from __future__ import annotations

import pytest

from bbhunter.config import Config
from bbhunter.http_client import HttpClient, OutOfScopeError
from bbhunter.scope import Scope


def _client(*include, exclude=()):
    cfg = Config()
    cfg.rate_limit = 0
    cfg.timeout = 5
    return HttpClient(cfg, Scope.from_lists(list(include), list(exclude)))


# ---------- scope motoru ----------

def test_scope_is_fail_closed_when_empty():
    assert not Scope.from_lists([]).in_scope("example.com")


def test_domain_includes_apex_and_subdomains_wildcard_excludes_apex():
    s = Scope.from_lists(["example.com", "*.other.com"])
    assert s.in_scope("example.com") and s.in_scope("a.b.example.com")
    assert s.in_scope("x.other.com") and not s.in_scope("other.com")
    assert not s.in_scope("notexample.com")


def test_exclude_wins_over_include():
    s = Scope.from_lists(["example.com"], ["admin.example.com"])
    assert not s.in_scope("admin.example.com")
    assert not s.in_scope("x.admin.example.com")
    assert s.in_scope("www.example.com")


def test_scope_file_with_bom_and_sections(tmp_path):
    p = tmp_path / "p.scope"
    p.write_text("﻿# yorum\nexample.com\n!blog.example.com\nOUT:\nshop.example.com\n",
                 encoding="utf-8")
    s = Scope.from_file(p)
    assert s.in_scope("api.example.com")
    assert not s.in_scope("blog.example.com")
    assert not s.in_scope("shop.example.com")


# ---------- HTTP client ----------

def test_out_of_scope_request_is_blocked_before_sending():
    with pytest.raises(OutOfScopeError):
        _client("127.0.0.1").get("http://evil.example/")


def test_in_scope_redirect_is_followed(server):
    base, routes, seen = server
    routes["/start"] = (302, {"Location": "/final"}, b"")
    routes["/final"] = (200, {}, b"ok")
    r = _client("127.0.0.1").get(base + "/start")
    assert r.status == 200 and r.text == "ok"
    assert r.history == [302]
    assert r.final_url == base + "/final"
    assert r.blocked_redirect == ""


def test_redirect_to_out_of_scope_host_is_not_followed(server):
    base, routes, seen = server
    routes["/start"] = (302, {"Location": "https://login.evil.example/sso"}, b"")
    r = _client("127.0.0.1").get(base + "/start")
    assert r.status == 302
    assert r.blocked_redirect == "https://login.evil.example/sso"
    assert r.final_url == base + "/start"
    assert [p for _, p, _ in seen] == ["/start"]


def test_redirect_chain_blocked_midway(server):
    base, routes, seen = server
    routes["/a"] = (301, {"Location": "/b"}, b"")
    routes["/b"] = (302, {"Location": "http://other.example/"}, b"")
    r = _client("127.0.0.1").get(base + "/a")
    assert r.status == 302 and r.history == [301]
    assert r.blocked_redirect == "http://other.example/"


def test_allow_redirects_false_returns_3xx(server):
    base, routes, seen = server
    routes["/start"] = (302, {"Location": "/final"}, b"")
    r = _client("127.0.0.1").get(base + "/start", allow_redirects=False)
    assert r.status == 302 and [p for _, p, _ in seen] == ["/start"]


def test_max_redirects_stops_loop(server):
    base, routes, seen = server
    routes["/loop"] = (302, {"Location": "/loop"}, b"")
    c = _client("127.0.0.1")
    c.config.max_redirects = 3
    r = c.get(base + "/loop")
    assert r.status == 302 and len(seen) == 4


def test_post_303_becomes_get(server):
    base, routes, seen = server
    routes["/form"] = (303, {"Location": "/done"}, b"")
    routes["/done"] = (200, {}, b"done")
    r = _client("127.0.0.1").request("POST", base + "/form", data={"a": "1"})
    assert r.text == "done"
    assert [(m, p) for m, p, _ in seen] == [("POST", "/form"), ("GET", "/done")]


def test_extra_headers_are_sent(server):
    base, routes, seen = server
    routes["/"] = (200, {}, b"x")
    c = _client("127.0.0.1")
    c.config.extra_headers = {"X-HackerOne-Research": "kenzai"}
    c.get(base + "/")
    assert seen[0][2].get("X-HackerOne-Research") == "kenzai"
