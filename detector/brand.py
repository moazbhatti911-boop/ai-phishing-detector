"""Brand-impersonation check against a small built-in brand list.

A domain is flagged when it is not the brand's official domain but either
contains the brand name (e.g. paypal.com.secure-login.tk) or is a close
lookalike of it (e.g. paypa1.com, g00gle.com).
"""
from __future__ import annotations

import difflib
from urllib.parse import urlparse

from .url_features import registrable_domain

# Brand -> its official domains. Keep this list small and well known.
BRANDS = {
    "google": {"google.com", "google.co.uk", "google.co.in"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "github": {"github.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "whatsapp": {"whatsapp.com"},
    "binance": {"binance.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "ebay": {"ebay.com"},
    "spotify": {"spotify.com"},
    "zoom": {"zoom.us"},
    "slack": {"slack.com"},
}

# Minimum string similarity for a lookalike domain (0.0-1.0).
SIMILARITY_THRESHOLD = 0.65


def _base_name(domain: str) -> str:
    """The first label of a registrable domain, e.g. 'paypa1'."""
    parts = domain.split(".")
    return parts[0] if parts else domain


def check_brand_impersonation(url_or_host: str) -> dict:
    """Check whether a URL/host impersonates a well-known brand."""
    host = (url_or_host or "").lower().strip()
    if "://" in host:
        host = (urlparse(host).hostname or "").lower()
    if not host:
        return {"brand": None, "similarity": 0.0, "is_impersonation": False, "reason": ""}

    reg = registrable_domain(host)
    base = _base_name(reg)
    best = {"brand": None, "similarity": 0.0, "is_impersonation": False, "reason": ""}

    for brand, official in BRANDS.items():
        if reg in official:
            return {"brand": brand, "similarity": 1.0, "is_impersonation": False, "reason": ""}
        # Brand name hidden in a subdomain, e.g. paypal.login-verify.ru
        if brand in host:
            return {
                "brand": brand,
                "similarity": 0.95,
                "is_impersonation": True,
                "reason": f"Domain uses the brand name '{brand}' but is not {sorted(official)[0]}",
            }
        sim = difflib.SequenceMatcher(None, base, brand).ratio()
        if sim >= SIMILARITY_THRESHOLD and sim > best["similarity"]:
            best = {
                "brand": brand,
                "similarity": round(sim, 2),
                "is_impersonation": True,
                "reason": f"Domain '{reg}' looks like an imitation of '{brand}' (similarity {sim:.0%})",
            }
    return best
