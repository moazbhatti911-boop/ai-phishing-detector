"""Streamlit dashboard for the AI-Based Phishing Detection System.

Paste a URL, see the verdict, the 0-100 score and the reasons behind it,
then browse the analysis history. Talks to the FastAPI server.
"""
import os

import httpx
import streamlit as st

SERVER_URL = os.getenv("PHISH_SERVER_URL", "http://127.0.0.1:8004")
API_KEY = os.getenv("PHISH_API_KEY", "")

LABEL_COLORS = {"PHISHING": "red", "SUSPICIOUS": "orange", "LEGIT": "green"}


def _headers() -> dict:
    return {"X-API-Key": API_KEY} if API_KEY else {}


def _analyze(url: str) -> dict | None:
    try:
        with httpx.Client(timeout=15.0, trust_env=False) as client:
            resp = client.post(
                f"{SERVER_URL}/analyze", json={"url": url}, headers=_headers()
            )
        if resp.status_code == 401:
            st.error("Server rejected the API key. Check PHISH_API_KEY in .env.")
            return None
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        st.error(f"Cannot reach the server at {SERVER_URL}. Is it running?")
        return None
    except Exception as exc:  # noqa: BLE001 - show the user what happened
        st.error(f"Analysis failed: {exc}")
        return None


def _history() -> list:
    try:
        with httpx.Client(timeout=10.0, trust_env=False) as client:
            resp = client.get(f"{SERVER_URL}/history", headers=_headers())
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


st.set_page_config(page_title="Phishing Detector", page_icon="🎣")
st.title("🎣 AI-Based Phishing Detection System")
st.caption("Paste a URL you want checked. Lab use only — the score is a hint, always verify before acting.")

url = st.text_input("URL to analyze", placeholder="https://example.com/login")
if st.button("Analyze"):
    if not url.strip():
        st.warning("Paste a URL first.")
    else:
        with st.spinner("Analyzing..."):
            result = _analyze(url.strip())
        if result:
            color = LABEL_COLORS.get(result["label"], "gray")
            st.markdown(f"### Verdict: :{color}[{result['label']}]")
            st.progress(result["score"] / 100)
            st.write(f"**Score:** {result['score']}/100")
            st.write(f"**ML phishing probability:** {result['ml_probability']:.0%}")
            st.subheader("Why?")
            for reason in result["reasons"]:
                st.write(f"- {reason}")

st.subheader("History")
rows = _history()
if rows:
    st.table(
        [
            {"ID": r["id"], "URL": r["url"], "Verdict": r["label"], "Score": r["score"]}
            for r in rows
        ]
    )
else:
    st.write("No analyses yet — analyze a URL above.")
