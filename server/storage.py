"""SQLite storage for analyses."""
import json
import sqlite3
from datetime import datetime, timezone

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    label TEXT NOT NULL,
    score INTEGER NOT NULL,
    ml_probability REAL NOT NULL,
    reasons TEXT NOT NULL,
    features TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | None = None) -> None:
    """Create the analyses table if it does not exist yet."""
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def insert_analysis(
    url: str,
    label: str,
    score: int,
    ml_probability: float,
    reasons: list,
    features: dict,
    db_path: str | None = None,
) -> tuple[int, str]:
    """Store one analysis; returns (id, created_at)."""
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO analyses "
            "(url, label, score, ml_probability, reasons, features, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                url,
                label,
                score,
                ml_probability,
                json.dumps(reasons),
                json.dumps(features),
                created_at,
            ),
        )
        return cur.lastrowid, created_at


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["reasons"] = json.loads(d["reasons"])
    d["features"] = json.loads(d["features"])
    return d


def get_analysis(analysis_id: int, db_path: str | None = None) -> dict | None:
    """Fetch one analysis by id, or None when it does not exist."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_analyses(limit: int = 50, db_path: str | None = None) -> list[dict]:
    """Newest analyses first."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats(db_path: str | None = None) -> dict:
    """Counts by verdict label, plus the total."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT label, COUNT(*) AS n FROM analyses GROUP BY label"
        ).fetchall()
    counts = {r["label"]: r["n"] for r in rows}
    total = sum(counts.values())
    return {
        "total": total,
        "phishing": counts.get("PHISHING", 0),
        "suspicious": counts.get("SUSPICIOUS", 0),
        "legit": counts.get("LEGIT", 0),
    }
