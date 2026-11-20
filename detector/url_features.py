"""Lexical features extracted from a URL.

Only the URL string itself is used here, so these features work even when
the page cannot be fetched.
"""
from __future__ import annotations

import math
from urllib.parse import urlparse

# Top-level domains that show up far more often in phishing than in
# legitimate sites. A suspicious TLD alone never decides the verdict.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
    "buzz", "work", "live", "click", "link", "fit", "rest", "bar", "party",
    "review", "country", "kim", "bid", "loan", "men", "zip", "mov", "mom",
    "quest", "cam", "casa", "monster", "cyou", "bond", "lol", "lat",
    "autos", "pics", "homes", "icu", "wang", "win", "pro", "science",
    "ninja", "world", "sbs",
}

# Two-label public suffixes, so "example.co.uk" is treated as one domain.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "com.au", "co.in", "com.br", "co.jp", "co.nz",
    "com.mx", "co.za", "org.uk", "net.au",
}

FEATURE_NAMES = [
    "url_length", "host_length", "dot_count", "hyphen_count", "digit_count",
    "digit_ratio", "has_at", "has_ip", "is_punycode", "subdomain_count",
    "path_length", "query_length", "suspicious_tld", "entropy", "has_https",
    "slash_count", "host_digit_count", "double_slash_in_path",
    "longest_label",
]


def normalize_url(url: str) -> str:
    """Trim the URL and add a scheme when the user left it out."""
    url = (url or "").strip()
    if not url:
        raise ValueError("empty URL")
    if "://" not in url:
        url = "http://" + url
    return url


def _is_ip(host: str) -> bool:
    """True for an IPv4 literal (or an IPv6 literal with ':')."""
    parts = host.split(".")
    if len(parts) == 4 and all(
        p.isdigit() and p != "" and 0 <= int(p) <= 255 for p in parts
    ):
        return True
    return ":" in host


def _entropy(text: str) -> float:
    """Shannon entropy of the text (0.0 for empty / single-character text)."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registrable_domain(host: str) -> str:
    """The registrable domain of a host, e.g. 'example.co.uk'.

    Returns the host itself for IP literals.
    """
    host = host.lower().strip(".")
    if _is_ip(host):
        return host
    for suffix in MULTI_LABEL_SUFFIXES:
        if host.endswith("." + suffix):
            rest = host[: -len(suffix) - 1]
            if "." in rest:
                return rest.split(".")[-1] + "." + suffix
            return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def extract_url_features(url: str) -> dict:
    """Extract lexical features from one URL."""
    url = normalize_url(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    digits = sum(ch.isdigit() for ch in url)
    host_digits = sum(ch.isdigit() for ch in host)
    subdomains = 0
    if host and not _is_ip(host):
        reg = registrable_domain(host)
        subdomains = max(0, host.count(".") - reg.count("."))
    labels = [p for p in host.split(".") if p]
    longest_label = max((len(p) for p in labels), default=0)
    tld = host.split(".")[-1] if "." in host else ""
    return {
        "url_length": len(url),
        "host_length": len(host),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "digit_count": digits,
        "digit_ratio": round(digits / len(url), 3) if url else 0.0,
        "has_at": 1 if "@" in url else 0,
        "has_ip": 1 if _is_ip(host) else 0,
        "is_punycode": 1 if "xn--" in host else 0,
        "subdomain_count": subdomains,
        "path_length": len(path),
        "query_length": len(query),
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "entropy": round(_entropy(host), 3),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "slash_count": url.count("/"),
        "host_digit_count": host_digits,
        "double_slash_in_path": 1 if "//" in path else 0,
        "longest_label": longest_label,
        "hostname": host,
        "registrable_domain": registrable_domain(host),
        "tld": tld,
    }


def feature_vector(features: dict) -> list:
    """The numeric feature vector, in a fixed order, for the ML model."""
    return [float(features[name]) for name in FEATURE_NAMES]
