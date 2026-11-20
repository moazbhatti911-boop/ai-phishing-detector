"""Tests for the explainable verdict."""
import os

from detector.verdict import analyze_url

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _read(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_known_legit_url_is_legit():
    result = analyze_url("https://www.github.com")
    assert result["label"] == "LEGIT"
    assert 0 <= result["score"] < 40
    assert result["reasons"]


def test_ip_based_phishing_url_is_phishing():
    result = analyze_url("http://185.220.101.45/paypal/login")
    assert result["label"] == "PHISHING"
    assert result["score"] >= 70
    assert any("IP address" in r for r in result["reasons"])


def test_lookalike_domain_is_phishing_with_brand_reason():
    result = analyze_url("https://paypal.com.secure-login.tk/verify")
    assert result["label"] == "PHISHING"
    assert any("paypal" in r.lower() for r in result["reasons"])


def test_phishing_html_fixture_boosts_score_and_reasons():
    html = _read("sample_phishing.html")
    without_html = analyze_url("https://secure-login.tk/verify")
    with_html = analyze_url("https://secure-login.tk/verify", html=html)
    assert with_html["score"] >= without_html["score"]
    assert with_html["label"] == "PHISHING"
    assert any("password" in r.lower() for r in with_html["reasons"])
    assert any("iframe" in r.lower() for r in with_html["reasons"])


def test_legit_html_fixture_stays_legit():
    html = _read("sample_legit.html")
    result = analyze_url("https://www.wikipedia.org", html=html)
    assert result["label"] == "LEGIT"


def test_score_is_always_in_range_and_reasons_explain():
    for url in [
        "https://www.github.com",
        "https://paypal.com.secure-login.tk/verify",
        "https://example.com/some/very/long/path?with=lots&of=query&parameters=1",
    ]:
        result = analyze_url(url)
        assert 0 <= result["score"] <= 100
        assert result["label"] in ("LEGIT", "SUSPICIOUS", "PHISHING")
        assert result["reasons"], url
