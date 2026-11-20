"""CLI for the AI-Based Phishing Detection System.

Talks to the FastAPI server; when the server cannot be reached, the
`analyze` command falls back to a local (offline) analysis.
"""
import argparse
import os
import sys

import httpx

SERVER_URL = os.getenv("PHISH_SERVER_URL", "http://127.0.0.1:8004")
API_KEY = os.getenv("PHISH_API_KEY", "")


def _headers() -> dict:
    return {"X-API-Key": API_KEY} if API_KEY else {}


def _print_result(result: dict, local: bool = False) -> None:
    tag = " (local analysis — server unreachable)" if local else ""
    print(f"URL:     {result['url']}")
    print(f"Verdict: {result['label']}  ({result['score']}/100){tag}")
    print(f"ML prob: {result['ml_probability']:.0%}")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        with httpx.Client(timeout=15.0, trust_env=False) as client:
            resp = client.post(
                f"{SERVER_URL}/analyze",
                json={"url": args.url},
                headers=_headers(),
            )
        if resp.status_code == 401:
            print("Server rejected the API key. Check PHISH_API_KEY in .env.")
            return 1
        resp.raise_for_status()
        _print_result(resp.json())
        return 0
    except httpx.ConnectError:
        print(f"Server at {SERVER_URL} is unreachable — analyzing locally.")
        from detector.verdict import analyze_url

        result = analyze_url(args.url)
        _print_result(
            {
                "url": args.url,
                "label": result["label"],
                "score": result["score"],
                "ml_probability": result["ml_probability"],
                "reasons": result["reasons"],
            },
            local=True,
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI should show the error
        print(f"Analysis failed: {exc}")
        return 1


def cmd_history(args: argparse.Namespace) -> int:
    try:
        with httpx.Client(timeout=10.0, trust_env=False) as client:
            resp = client.get(
                f"{SERVER_URL}/history",
                params={"limit": args.limit},
                headers=_headers(),
            )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - CLI should show the error
        print(f"Could not fetch history: {exc}")
        return 1
    rows = resp.json()
    if not rows:
        print("No analyses yet.")
        return 0
    print(f"{'ID':<5}{'Verdict':<12}{'Score':<7}URL")
    for r in rows:
        print(f"{r['id']:<5}{r['label']:<12}{r['score']:<7}{r['url']}")
    return 0


def cmd_stats(_args: argparse.Namespace) -> int:
    try:
        with httpx.Client(timeout=10.0, trust_env=False) as client:
            resp = client.get(f"{SERVER_URL}/stats", headers=_headers())
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - CLI should show the error
        print(f"Could not fetch stats: {exc}")
        return 1
    stats = resp.json()
    print(f"Total:      {stats['total']}")
    print(f"PHISHING:   {stats['phishing']}")
    print(f"SUSPICIOUS: {stats['suspicious']}")
    print(f"LEGIT:      {stats['legit']}")
    return 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phish",
        description="AI-Based Phishing Detection System — CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze one URL")
    p_analyze.add_argument("url", help="The URL to analyze")
    p_analyze.set_defaults(func=cmd_analyze)

    p_history = sub.add_parser("history", help="Show recent analyses")
    p_history.add_argument("--limit", type=int, default=20)
    p_history.set_defaults(func=cmd_history)

    p_stats = sub.add_parser("stats", help="Show verdict counts")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
