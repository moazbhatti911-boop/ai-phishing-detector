"""Explainable verdict: ML score + rule boosts -> 0-100 score and label.

Every point of the score can be traced back to an entry in the reasons
list, so the verdict is explainable rather than a black-box number.
"""
from __future__ import annotations

from .url_features import extract_url_features
from .html_features import extract_html_features
from .brand import check_brand_impersonation
from .model import get_model

# Score bands.
PHISHING_AT = 70
SUSPICIOUS_AT = 40
# Rule points are capped so no single trick can max out the score alone.
MAX_RULE_POINTS = 45


def analyze_url(url: str, html: str | None = None) -> dict:
    """Analyze one URL and return an explainable verdict."""
    url_feats = extract_url_features(url)
    model = get_model()
    ml_prob = model.phishing_probability(url_feats)
    reasons: list[str] = []
    rule_points = 0

    def add(points: int, reason: str) -> None:
        nonlocal rule_points
        rule_points += points
        reasons.append(reason)

    if url_feats["has_ip"]:
        add(25, "The URL uses an IP address instead of a domain name, a common phishing trick.")
    if url_feats["has_at"]:
        add(15, "The URL contains '@', which can hide the real destination.")
    if url_feats["is_punycode"]:
        add(15, "The domain uses punycode (xn--), often used to fake lookalike letters.")
    if url_feats["suspicious_tld"]:
        add(10, f"The top-level domain '.{url_feats['tld']}' is frequently abused in phishing.")
    if url_feats["subdomain_count"] >= 4:
        add(10, f"Unusually many subdomains ({url_feats['subdomain_count']}).")
    if url_feats["url_length"] > 75:
        add(5, "The URL is unusually long.")
    if url_feats["digit_ratio"] > 0.3:
        add(5, "The URL contains an unusually high share of digits.")

    brand = check_brand_impersonation(url)
    if brand["is_impersonation"]:
        add(25, brand["reason"] + ".")

    html_feats = None
    if html:
        html_feats = extract_html_features(html, url)
        if html_feats["has_password_form"]:
            add(10, "The page asks for a password.")
        if html_feats["hidden_iframe_count"]:
            add(10, f"The page contains {html_feats['hidden_iframe_count']} hidden iframe(s).")
        if html_feats["external_resource_ratio"] > 0.7:
            add(5, "Most of the page's resources load from other domains.")
        if html_feats["favicon_mismatch"]:
            add(5, "The page's favicon comes from a different domain than the page itself.")

    if ml_prob >= 0.7:
        reasons.append(
            f"The machine-learning model flags this URL as phishing-like "
            f"(confidence {ml_prob:.0%})."
        )
    elif ml_prob <= 0.3:
        reasons.append(
            f"The model finds this URL similar to known legitimate URLs "
            f"(confidence {1 - ml_prob:.0%})."
        )

    rule_points = min(rule_points, MAX_RULE_POINTS)
    score = int(round(min(100, ml_prob * 100 * 0.6 + rule_points)))
    if score >= PHISHING_AT:
        label = "PHISHING"
    elif score >= SUSPICIOUS_AT:
        label = "SUSPICIOUS"
    else:
        label = "LEGIT"
    if not reasons:
        reasons.append("No suspicious signals found; the URL looks ordinary.")

    return {
        "url": url,
        "score": score,
        "label": label,
        "ml_probability": round(ml_prob, 3),
        "reasons": reasons,
        "url_features": url_feats,
        "html_features": html_feats,
        "brand": brand,
    }
