from __future__ import annotations

from bbhunter.discovery.jsanalyze import SECRET_SEVERITY, analyze_body
from bbhunter.triage import assess, triage, write_markdown

BODY_64 = "MIIEowIBAAKCAQEA" + "A" * 60


def _names(js: str) -> list[str]:
    return [n for n, _ in analyze_body("https://x.test/a.js", js.encode()).secrets]


# ---------- JS sir imzalari ----------

def test_pem_header_alone_in_library_code_is_not_a_secret():
    js = 'var t="-----BEGIN RSA PRIVATE KEY-----";if(s.indexOf(t)>-1){parse(s)}'
    assert "Private Key Block" not in _names(js)


def test_pem_header_with_key_body_is_a_secret():
    js = 'var k="-----BEGIN RSA PRIVATE KEY-----\\n' + BODY_64 + '\\n";'
    assert "Private Key Block" in _names(js)


def test_secret_severities_are_calibrated():
    assert SECRET_SEVERITY["Google API Key"] == "low"
    assert SECRET_SEVERITY["AWS Access Key"] == "high"


# ---------- triage ----------

def _f(category, name, severity="medium", target="https://a.test/", detail="", data=None):
    return {"category": category, "name": name, "severity": severity,
            "target": target, "detail": detail, "data": data or {}}


def test_google_maps_key_is_likely_na():
    assert assess(_f("secret", "Olasi sir: Google API Key")).status == "likely-na"


def test_old_header_only_private_key_finding_is_likely_na():
    v = assess(_f("secret", "Olasi sir: Private Key Block", "high",
                  detail="-----BEGIN RSA PRIVATE KEY-----"))
    assert v.status == "likely-na"


def test_private_key_with_body_is_promising():
    v = assess(_f("secret", "Olasi sir: Private Key Block", "high",
                  detail="-----BEGIN RSA PRIVATE KEY-----\\n" + BODY_64[:40]))
    assert v.status == "promising"


def test_cors_needs_verification_with_concrete_steps():
    v = assess(_f("cors-misconfig", "CORS yanlis yapilandirma (origin yansimasi + credentials)"))
    assert v.status == "verify" and v.next_steps


def test_tracking_param_ssrf_candidate_is_noise():
    v = assess(_f("ssrf-candidate", "SSRF inceleme adayi (manuel)", "info",
                  data={"param": "ref"}))
    assert v.status == "info"


def test_sso_param_ssrf_candidate_is_likely_na():
    v = assess(_f("ssrf-candidate", "SSRF inceleme adayi (manuel)", "info",
                  data={"param": "loginUrl"}))
    assert v.status == "likely-na"


def test_takeover_high_is_promising_and_open_redirect_is_likely_na():
    assert assess(_f("subdomain-takeover", "Subdomain takeover adayi (github)", "high")).status \
        == "promising"
    assert assess(_f("open-redirect", "Open-redirect adayi", "low")).status == "likely-na"


def test_triage_sorts_promising_first_and_writes_markdown(tmp_path):
    fs = [_f("tech", "Teknoloji tespiti", "info"),
          _f("open-redirect", "Open-redirect adayi", "low"),
          _f("subdomain-takeover", "Subdomain takeover adayi (s3)", "high")]
    assert [v.status for _, v in triage(fs)] == ["promising", "likely-na", "info"]
    text = write_markdown(fs, tmp_path / "t.md", program="Acme")
    assert "Guclu aday" in text and "- [ ]" in text
