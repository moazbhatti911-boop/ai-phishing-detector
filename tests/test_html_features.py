"""Tests for HTML features, using the offline sample fixtures."""
import os

from detector.html_features import extract_html_features

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _read(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_phishing_fixture_has_password_form_and_hidden_iframe():
    feats = extract_html_features(
        _read("sample_phishing.html"), "https://secure-login.tk/verify"
    )
    assert feats["has_password_form"] == 1
    assert feats["password_input_count"] == 1
    assert feats["hidden_iframe_count"] == 1
    assert feats["iframe_count"] == 1


def test_phishing_fixture_external_resources_and_favicon():
    feats = extract_html_features(
        _read("sample_phishing.html"), "https://secure-login.tk/verify"
    )
    assert feats["external_resource_ratio"] > 0.7
    assert feats["favicon_mismatch"] == 1


def test_legit_fixture_is_clean():
    feats = extract_html_features(
        _read("sample_legit.html"), "https://example-university.test/"
    )
    assert feats["has_password_form"] == 0
    assert feats["password_input_count"] == 0
    assert feats["hidden_iframe_count"] == 0
    assert feats["external_resource_ratio"] == 0.0
    assert feats["favicon_mismatch"] == 0


def test_empty_html_is_safe():
    feats = extract_html_features("", "https://example.com/")
    assert feats["has_password_form"] == 0
    assert feats["external_resource_ratio"] == 0.0
