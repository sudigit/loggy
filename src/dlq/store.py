"""
Dead-letter queue. Anything the deterministic parser can't handle lands
here instead of being dropped (requirement: no information loss). A
separate offline batch job (src/selfheal/review_dlq.py) periodically
reviews it -- never inline, never per-event.
"""
import importlib.util
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

# Import config directly to avoid package shadowing issue (src.config vs src/config/)
_project_root = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("config", _project_root / "src" / "config.py")
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)

_lock = threading.Lock()


def _conn():
    conn = sqlite3.connect(config.DLQ_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dlq (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            channel TEXT,
            source_hint TEXT,
            raw_snippet TEXT,
            error TEXT,
            ts TEXT,
            status TEXT DEFAULT 'pending'
        )
        """
    )
    return conn


def add(event_id: str, channel: str, source_hint: str, raw_snippet: str, error: str):
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT INTO dlq (event_id, channel, source_hint, raw_snippet, error, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, channel, source_hint, raw_snippet[:2000], error,
             datetime.now(timezone.utc).isoformat()),
        )


def pending_grouped_by_channel() -> dict:
    with _lock, _conn() as conn:
        rows = conn.execute(
            "SELECT id, event_id, channel, source_hint, raw_snippet, error, ts "
            "FROM dlq WHERE status = 'pending' ORDER BY ts"
        ).fetchall()
    grouped = {}
    for r in rows:
        grouped.setdefault(r[2], []).append(
            {"id": r[0], "event_id": r[1], "channel": r[2], "source_hint": r[3],
             "raw_snippet": r[4], "error": r[5], "ts": r[6]}
        )
    return grouped


def mark_status(ids: list, status: str):
    with _lock, _conn() as conn:
        conn.executemany("UPDATE dlq SET status = ? WHERE id = ?", [(status, i) for i in ids])


def list_recent(limit: int = 50) -> list:
    with _lock, _conn() as conn:
        rows = conn.execute(
            "SELECT id, event_id, channel, source_hint, raw_snippet, error, ts, status "
            "FROM dlq ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    cols = ["id", "event_id", "channel", "source_hint", "raw_snippet", "error", "ts", "status"]
    return [dict(zip(cols, r)) for r in rows]
