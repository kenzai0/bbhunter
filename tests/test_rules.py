from __future__ import annotations

import argparse

import pytest

from bbhunter.cli import build_config
from bbhunter.config import Config
from bbhunter.pipeline import Pipeline
from bbhunter.report.store import Store
from bbhunter.rules import ProgramRules, RuleError
from bbhunter.scope import Scope

SCOPE_TEXT = """\
@program  Acme VDP
@platform HackerOne
@rate     3   # programin siniri
@threads  4
@header   X-HackerOne-Research: kenzai
@forbid   fuzz, ports
@note     Otomatik tarama 3 req/s ile sinirli
[IN]
acme.test
"""


def _scope(tmp_path, text=SCOPE_TEXT):
    p = tmp_path / "acme.scope"
    p.write_text(text, encoding="utf-8")
    return Scope.from_file(p)


def _args(tmp_path, **kw):
    base = dict(out=str(tmp_path / "out"), threads=20, rate=10.0, timeout=5.0,
                verify_tls=False, jitter=0.0, user_agent=None, header=[])
    base.update(kw)
    return argparse.Namespace(**base)


def test_rules_parsed_from_scope_file(tmp_path):
    r = _scope(tmp_path).rules
    assert r.program == "Acme VDP" and r.platform == "hackerone"
    assert r.rate == 3 and r.threads == 4
    assert r.headers == {"X-HackerOne-Research": "kenzai"}
    assert r.forbid == {"fuzz", "ports"}
    assert r.notes == ["Otomatik tarama 3 req/s ile sinirli"]


def test_rules_lines_are_not_scope_entries(tmp_path):
    s = _scope(tmp_path)
    assert [r.raw for r in s.include] == ["acme.test"]


def test_rules_clamp_cli_rate_threads_and_add_headers(tmp_path):
    cfg = build_config(_args(tmp_path, rate=50.0, threads=40,
                             header=["X-HackerOne-Research: yanlis"]), _scope(tmp_path))
    assert cfg.rate_limit == 3 and cfg.threads == 4
    assert cfg.extra_headers["X-HackerOne-Research"] == "kenzai"


def test_rules_never_raise_a_lower_cli_rate(tmp_path):
    cfg = build_config(_args(tmp_path, rate=1.0, threads=2), _scope(tmp_path))
    assert cfg.rate_limit == 1.0 and cfg.threads == 2


def test_unlimited_cli_rate_is_clamped(tmp_path):
    cfg = build_config(_args(tmp_path, rate=0.0), _scope(tmp_path))
    assert cfg.rate_limit == 3


@pytest.mark.parametrize("line", ["@forbid nuke", "@rate fast", "@rate 0",
                                  "@header noColon", "@bogus x", "@program"])
def test_invalid_rule_lines_fail_loudly(line):
    with pytest.raises(RuleError):
        ProgramRules().parse_line(line)


def test_forbid_active_blocks_every_active_stage():
    r = ProgramRules()
    r.parse_line("@forbid active")
    for stage in ("brute", "ports", "fuzz", "probe", "vuln", "takeover", "js", "live"):
        assert not r.allows(stage)


def test_pipeline_skips_forbidden_stages_without_requests(tmp_path):
    scope = _scope(tmp_path, "@forbid probe, vuln\nacme.test\n")
    cfg = Config(out_dir=tmp_path)
    cfg.dry_run = True
    store = Store(tmp_path / "t.db")
    pipe = Pipeline(cfg, scope, store)

    def boom(*a, **k):
        raise AssertionError("yasak asamada istek atildi")
    pipe.client.request = boom

    pipe.probe(["https://acme.test/?q=1"])
    pipe.vuln(["https://acme.test/"])
    assert not store.findings()
    store.close()
