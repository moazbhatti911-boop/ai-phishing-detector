"""Features extracted from a fetched page's HTML.

Only runs when the user submits a URL and the page could be fetched.
A page that cannot be fetched is analyzed from its URL features alone.
"""
from __future__ import annotations

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

LOGIN_KEYWORDS = (
    "login", "sign in", "password", "verify", "account", "security check",
)


def _is_external(page_host: str, other_host: str) -> bool:
    if not page_host or not other_host:
        return False
    return other_host != page_host and not other_host.endswith("." + page_host)


def extract_html_features(html: str, url: str = "") -> dict:
    """Extract phishing-relevant signals from one page's HTML."""
    soup = BeautifulSoup(html or "", "html.parser")
    page_host = (urlparse(url).hostname or "").lower() if url else ""

    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", {"type": "password"})

    iframes = soup.find_all("iframe")
    hidden_iframes = 0
    for frame in iframes:
        style = (frame.get("style") or "").replace(" ", "").lower()
        if (
            frame.get("hidden") is not None
            or "display:none" in style
            or "visibility:hidden" in style
            or str(frame.get("width")) in ("0", "1")
            or str(frame.get("height")) in ("0", "1")
        ):
            hidden_iframes += 1

    # How much of the page is pulled in from other domains?
    external_resources = 0
    total_resources = 0
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href")):
        for el in soup.find_all(tag):
            src = el.get(attr)
            if not src:
                continue
            total_resources += 1
            abs_url = urljoin(url, src) if url else src
            host = (urlparse(abs_url).hostname or "").lower()
            if _is_external(page_host, host):
                external_resources += 1

    # Does the favicon come from the same domain as the page?
    favicon_mismatch = 0
    icon = soup.find("link", rel=lambda r: r and "icon" in str(r).lower())
    if icon and icon.get("href") and page_host:
        fav_host = (
            urlparse(urljoin(url, icon["href"])).hostname or ""
        ).lower()
        if _is_external(page_host, fav_host):
            favicon_mismatch = 1

    links = soup.find_all("a", href=True)
    external_links = 0
    for a in links:
        host = (urlparse(urljoin(url, a["href"])).hostname or "").lower()
        if _is_external(page_host, host):
            external_links += 1

    text = soup.get_text(" ", strip=True).lower()
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    return {
        "has_password_form": 1 if password_inputs else 0,
        "form_count": len(forms),
        "password_input_count": len(password_inputs),
        "iframe_count": len(iframes),
        "hidden_iframe_count": hidden_iframes,
        "external_resource_ratio": (
            round(external_resources / total_resources, 3)
            if total_resources
            else 0.0
        ),
        "favicon_mismatch": favicon_mismatch,
        "external_link_count": external_links,
        "total_link_count": len(links),
        "has_login_keywords": (
            1 if any(k in text for k in LOGIN_KEYWORDS) else 0
        ),
        "title": title,
        "text_length": len(text),
    }
