# AI-Based Phishing Detection System

A lab-only, defensive phishing detector in Python. Paste a URL and it
returns an explainable verdict — a 0-100 score, a label (LEGIT /
SUSPICIOUS / PHISHING), and the plain-language reasons behind it. The
detector combines lexical URL features, a brand-impersonation check,
HTML signals from the submitted page, and a scikit-learn RandomForest
model trained on the bundled labeled examples.

> **Lab-only scope.** Analyze only URLs you submit yourself, or the
> bundled samples. The server binds to `127.0.0.1` and never scans
> anything on its own. There is no mass scanning and no real victims
> here. The score is a hint — always verify a suspicious URL yourself
> before acting (check the real domain in the browser, never enter
> credentials on a page you do not trust).

## What it does

- **URL lexical features** — length, dot/hyphen/digit counts, `@` sign,
  IP-literal host, punycode, suspicious TLD, subdomain count, entropy.
- **Brand-impersonation check** — flags lookalike domains (paypa1.com,
  g00gle.com) and brand names hidden in subdomains
  (paypal.com.secure-login.tk) against a small built-in brand list.
- **HTML features** — password forms, hidden iframes,
  external-resource ratio, favicon mismatch (only when the submitted
  page can be fetched; otherwise the URL is judged from its URL
  features alone).
- **ML model** — RandomForest trained at runtime from
  `data/training_urls.csv` (~100 labeled examples).
- **Explainable verdict** — every point of the score traces back to an
  entry in the reasons list.
- **Interfaces** — FastAPI server, Streamlit dashboard, argparse CLI,
  SQLite storage.

## Requirements

- Python 3.10 or newer (`python --version`)
- Git (`git --version`)

## Installation

### Windows

```powershell
git clone https://github.com/<your-username>/ai-phishing-detector.git
cd ai-phishing-detector
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

Check the install:

```powershell
python -c "import fastapi, sklearn, streamlit, bs4; print('ok')"
```

### Kali Linux

```bash
git clone https://github.com/<your-username>/ai-phishing-detector.git
cd ai-phishing-detector
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Check the install:

```bash
python3 -c "import fastapi, sklearn, streamlit, bs4; print('ok')"
```

> Never use `venv\Scripts\activate` in Kali — that path is Windows only.

## Generate Keys

Copy the example env file and put your own API key in it:

```bash
# Kali
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

```powershell
# Windows
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Paste the printed value as `PHISH_API_KEY` in `.env`. Never commit
`.env` and never paste the key into chat.

## Running on Kali Linux

Run each command from inside the project folder, with the venv active
(`cd /home/luffy/ai-phishing-detector` then `source venv/bin/activate`).

Terminal 1 — server:

```bash
uvicorn server.main:app --reload --port 8004
```

Check it: open http://127.0.0.1:8004/health — it should return
`{"status": "ok"}`. Do not close this terminal.

Terminal 2 — dashboard:

```bash
streamlit run dashboard/app.py
```

Open http://127.0.0.1:8504, paste a URL, and read the verdict.

CLI (in a third terminal, venv active):

```bash
python3 -m cli.main analyze https://www.github.com
python3 -m cli.main history
python3 -m cli.main stats
```

## Running on Windows

Same steps with Windows commands. From inside the project folder, with
the venv active (`venv\Scripts\activate`):

Terminal 1 — server:

```powershell
uvicorn server.main:app --reload --port 8004
```

Check http://127.0.0.1:8004/health — it should return `{"status": "ok"}`.

Terminal 2 — dashboard:

```powershell
streamlit run dashboard/app.py
```

Open http://127.0.0.1:8504.

CLI:

```powershell
python -m cli.main analyze https://www.github.com
python -m cli.main history
python -m cli.main stats
```

## How detection works

1. **URL features** are extracted from the submitted URL (length,
   digits, `@`, IP host, punycode, TLD, subdomains, entropy).
2. **Brand check** compares the domain with a built-in list of
   well-known brands and flags lookalikes and brand-in-subdomain
   tricks.
3. **ML model** (RandomForest, trained at runtime from
   `data/training_urls.csv`) returns a phishing probability.
4. **HTML features** are added when the submitted page can be fetched
   (5-second timeout); a failed fetch falls back to URL features only.
5. **Verdict**: `score = min(100, round(ml_probability * 100 * 0.6 + rule_points))`,
   where rule points (capped at 45) come from the signals above.

| Score | Label | Meaning |
| --- | --- | --- |
| 70-100 | PHISHING | Strong phishing signals — do not trust it |
| 40-69 | SUSPICIOUS | Something looks off — verify before acting |
| 0-39 | LEGIT | No suspicious signals found |

## API

Base URL: `http://127.0.0.1:8004`. All endpoints except `/health`
require the `X-API-Key` header.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | `{"status": "ok"}` |
| POST | `/analyze` | Analyze one URL: `{"url": "..."}` |
| GET | `/analyze/{id}` | Fetch one stored analysis |
| GET | `/history?limit=50` | Newest analyses first |
| GET | `/stats` | Counts by verdict label, plus total |

## CLI examples

```bash
python3 -m cli.main analyze https://paypal.com.secure-login.tk/verify
python3 -m cli.main analyze https://www.github.com
python3 -m cli.main history --limit 10
python3 -m cli.main stats
```

When the server is not running, `analyze` falls back to a local
offline analysis and says so.

## Tests

Run from inside the project folder:

```bash
pytest -q
```

## Project Structure

```
ai-phishing-detector/
├── detector/            URL + HTML features, brand check, model, verdict
├── data/                training_urls.csv (~100 labeled examples)
├── server/              FastAPI server (127.0.0.1:8004), SQLite storage
├── dashboard/           Streamlit dashboard (127.0.0.1:8504)
├── cli/                 argparse CLI (analyze / history / stats)
├── shared/              Pydantic schemas
├── samples/             sample URLs + offline HTML fixtures
├── tests/               pytest tests
├── docs/                architecture, model, API notes
├── requirements.txt
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

## Security

- Lab-only: analyze only URLs you submit yourself or the bundled
  samples. Do not point this at other people's links, and never use
  it to test real victims.
- The server listens on `127.0.0.1` only; all endpoints except
  `/health` require the `X-API-Key` header.
- The API key lives in `.env` and is git-ignored — never commit it,
  never paste it into chat, never hard-code it.
- The score is a hint, not proof: always read the reasons and verify
  a suspicious URL yourself before acting.
