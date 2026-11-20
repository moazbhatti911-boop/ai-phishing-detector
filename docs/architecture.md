# Architecture

## What it is

A lab-only, defensive phishing detector. It analyzes one URL at a time —
only URLs the user submits (or the bundled samples) — and returns an
explainable verdict: a 0-100 score, a label (LEGIT / SUSPICIOUS /
PHISHING), and the plain-language reasons behind it.

## Components

```
URL (user submits)
   │
   ▼
detector/url_features.py   lexical features: length, dots, hyphens,
                           digits, @, IP-literal host, punycode,
                           suspicious TLD, subdomain count, entropy
   │
   ▼
detector/brand.py          brand-impersonation check against a small
                           built-in list (google, microsoft, paypal,
                           github, apple, amazon, ...)
   │
   ▼
detector/model.py          RandomForest (scikit-learn), trained at
                           runtime from data/training_urls.csv
   │
   ├─► detector/html_features.py  (only when the page was fetched)
   │                              password forms, hidden iframes,
   │                              external-resource ratio, favicon
   │
   ▼
detector/verdict.py        ML score + rule boosts -> 0-100 score,
                           label, reasons list
   │
   ▼
server/ (FastAPI)          /analyze, /analyze/{id}, /history, /stats
                           SQLite storage (analyses table)
   │
   ├─► dashboard/app.py   Streamlit: paste a URL, see the verdict
   └─► cli/main.py        argparse: analyze / history / stats
```

## Data flow

1. The user submits a URL (dashboard, CLI, or API).
2. The server fetches the page HTML with a 5-second timeout. When the
   fetch fails (offline host, timeout, non-HTML), analysis continues
   from the URL features alone.
3. URL features + brand check + ML probability + HTML features are
   combined into a score and a reasons list.
4. The analysis is stored in SQLite and returned to the caller.

## Scope

- 127.0.0.1 only. No mass scanning, no crawling, no real victims.
- The score is a hint: always verify a suspicious URL yourself before
  acting (check the real domain in the browser, never enter credentials
  on a page you do not trust).
