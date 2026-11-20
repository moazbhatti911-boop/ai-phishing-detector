# API

Base URL: `http://127.0.0.1:8004`

All endpoints except `GET /health` require the `X-API-Key` header
with the key from `.env` (`PHISH_API_KEY`).

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | `{"status": "ok"}` — no key needed |
| POST | `/analyze` | Analyze one URL |
| GET | `/analyze/{id}` | Fetch one stored analysis |
| GET | `/history?limit=50` | Newest analyses first |
| GET | `/stats` | Counts by verdict label, plus total |

## POST /analyze

Request:

```json
{ "url": "https://paypal.com.secure-login.tk/verify" }
```

Response:

```json
{
  "id": 1,
  "url": "https://paypal.com.secure-login.tk/verify",
  "label": "PHISHING",
  "score": 89,
  "ml_probability": 0.92,
  "reasons": [
    "The top-level domain '.tk' is frequently abused in phishing.",
    "Domain uses the brand name 'paypal' but is not paypal.com.",
    "The machine-learning model flags this URL as phishing-like (confidence 92%)."
  ],
  "created_at": "2026-11-20T13:00:00+00:00"
}
```

Errors: `401` for a missing or wrong API key, `404` for an unknown
analysis id, `422` for a missing/empty `url`.

## GET /stats

```json
{ "total": 12, "phishing": 4, "suspicious": 3, "legit": 5 }
```
