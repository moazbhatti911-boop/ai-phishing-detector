"""Tests for URL lexical features."""
from detector.url_features import extract_url_features


def test_ip_literal_detected():
    feats = extract_url_features("http://185.220.101.45/paypal/login")
    assert feats["has_ip"] == 1
    assert feats["hostname"] == "185.220.101.45"


def test_at_sign_detected():
    feats = extract_url_features("https://google.com@evil-login.ru/signin")
    assert feats["has_at"] == 1


def test_punycode_detected():
    feats = extract_url_features("https://xn--pypal-4ve.com/login")
    assert feats["is_punycode"] == 1


def test_suspicious_tld_detected():
    feats = extract_url_features("https://paypal.com.secure-login.tk/verify")
    assert feats["suspicious_tld"] == 1
    assert feats["tld"] == "tk"


def test_legit_domain_is_clean():
    feats = extract_url_features("https://www.github.com")
    assert feats["has_ip"] == 0
    assert feats["has_at"] == 0
    assert feats["is_punycode"] == 0
    assert feats["suspicious_tld"] == 0
    assert feats["has_https"] == 1
    assert feats["registrable_domain"] == "github.com"


def test_subdomain_count():
    feats = extract_url_features("https://a.b.c.d.example.com/path")
    assert feats["subdomain_count"] == 4


def test_url_without_scheme_gets_one():
    feats = extract_url_features("www.example.com/login")
    assert feats["hostname"] == "www.example.com"


def test_entropy_is_positive_for_mixed_host():
    feats = extract_url_features("https://x7q9z2-m4k8.example.com/")
    assert feats["entropy"] > 1.0
    plain = extract_url_features("https://aaa.example.com/")
    assert plain["entropy"] < feats["entropy"]
