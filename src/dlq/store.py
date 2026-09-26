"""
Dead-letter queue. Anything the deterministic parser can't handle lands here
instead of being dropped (requirement: no information loss).

Each row keeps the traceability link to the archived original (raw_ref +
raw_sha256), the failure reason, and a structural cluster id so the self-heal
loop can propose one parser per *kind* of unknown event.

Row lifecycle:  pending -> replayed   (a promoted parser re-parsed it from the raw archive)
                pending -> dismissed  (operator decided it's noise)
Proposals live in their own table and never change DLQ rows by themselves.
"""
import json
import sqlite3
import threading
from datetime import datetime, timezone

from src import config
from src.dlq import signature

_lock = threading.RLock()
_initialized = False

_DLQ_COLUMNS = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "event_id": "TEXT",
    "channel": "TEXT",
    "source_hint": "TEXT",
    "raw_snippet": "TEXT",
    "error": "TEXT",
    "reason": "TEXT",
    "parser_id": "TEXT",
    "cluster_id": "TEXT",
    "cluster_label": "TEXT",
    "format_guess": "TEXT",
    "raw_ref": "TEXT",
    "raw_sha256": "TEXT",
    "ingest_time": "TEXT",
    "ts": "TEXT",
    "status": "TEXT DEFAULT 'pending'",
}
SNIPPET_LIMIT = 4000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init(conn):
    cols = ", ".join(f"{k} {v}" for k, v in _DLQ_COLUMNS.items())
    conn.execute(f"CREATE TABLE IF NOT EXISTS dlq ({cols})")
    existing = {r[1] for r in conn.execute("PRAGMA table_info(dlq)")}
    for name, decl in _DLQ_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE dlq ADD COLUMN {name} {decl.replace('PRIMARY KEY AUTOINCREMENT', '')}")
    # rows left in legacy intermediate states go back to pending so they're visible again
    conn.execute("UPDATE dlq SET status='pending' WHERE status IN "
                 "('processing', 'reviewed_pending_promotion') OR status IS NULL")
    for row_id, channel, snippet in conn.execute(
            "SELECT id, channel, raw_snippet FROM dlq WHERE cluster_id IS NULL").fetchall():
        cid, label, fmt = signature.compute(snippet or "", channel or "")
        conn.execute("UPDATE dlq SET cluster_id=?, cluster_label=?, format_guess=?, reason=COALESCE(reason, 'legacy') "
                     "WHERE id=?", (cid, label, fmt, row_id))
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlq_status_cluster ON dlq(status, cluster_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_id TEXT, channel TEXT, cluster_label TEXT,
            created_at TEXT, updated_at TEXT,
            filename TEXT, yaml TEXT, generator TEXT,
            sample_count INTEGER, pending_at_creation INTEGER,
            match_rate REAL, validation TEXT, awareness TEXT,
            status TEXT DEFAULT 'open', note TEXT
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_prop_cluster ON proposals(cluster_id, status)")


def _conn():
    global _initialized
    conn = sqlite3.connect(config.DLQ_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    if not _initialized:
        with _lock:
            if not _initialized:
                conn.execute("PRAGMA journal_mode=WAL")
                _init(conn)
                conn.commit()
                _initialized = True
    return conn


def _run(sql: str, params=(), many=False, fetch=None):
    with _lock:
        conn = _conn()
        try:
            cur = conn.executemany(sql, params) if many else conn.execute(sql, params)
            result = None
            if fetch == "all":
                result = [dict(r) for r in cur.fetchall()]
            elif fetch == "one":
                r = cur.fetchone()
                result = dict(r) if r else None
            elif fetch == "lastrowid":
                result = cur.lastrowid
            conn.commit()
            return result
        finally:
            conn.close()


# ---------------------------------------------------------------- DLQ rows
def add(event_id: str, channel: str, source_hint: str, raw_snippet: str, error: str,
        reason: str = "unknown", parser_id: str = None, raw_ref: str = None,
        raw_sha256: str = None, ingest_time: str = None):
    cluster_id, label, fmt = signature.compute(raw_snippet, channel)
    _run(
        "INSERT INTO dlq (event_id, channel, source_hint, raw_snippet, error, reason, parser_id, "
        "cluster_id, cluster_label, format_guess, raw_ref, raw_sha256, ingest_time, ts, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
        (event_id, channel, source_hint, raw_snippet[:SNIPPET_LIMIT], error, reason, parser_id,
         cluster_id, label, fmt, raw_ref, raw_sha256, ingest_time, _now()),
    )


def pending_clusters() -> list:
    rows = _run(
        "SELECT cluster_id, channel, MAX(cluster_label) AS label, MAX(format_guess) AS format_guess, "
        "COUNT(*) AS count, MIN(ts) AS first_ts, MAX(ts) AS last_ts, "
        "GROUP_CONCAT(DISTINCT reason) AS reasons, GROUP_CONCAT(DISTINCT parser_id) AS parser_ids "
        "FROM dlq WHERE status='pending' GROUP BY cluster_id, channel ORDER BY count DESC",
        fetch="all")
    for r in rows:
        r["reasons"] = (r["reasons"] or "").split(",") if r["reasons"] else []
        r["parser_ids"] = (r["parser_ids"] or "").split(",") if r["parser_ids"] else []
        r["samples"] = [e["raw_snippet"] for e in cluster_entries(r["cluster_id"], limit=3)]
    return rows


def cluster_entries(cluster_id: str, limit: int = 50, status: str = "pending") -> list:
    return _run("SELECT * FROM dlq WHERE cluster_id=? AND status=? ORDER BY id DESC LIMIT ?",
                (cluster_id, status, limit), fetch="all")


def pending_since(cluster_id: str, since_iso: str) -> dict:
    return _run("SELECT COUNT(*) AS n, MIN(ts) AS first_ts FROM dlq WHERE cluster_id=? AND status='pending' "
                "AND ts > ?", (cluster_id, since_iso), fetch="one")


def pending_count() -> int:
    return _run("SELECT COUNT(*) AS n FROM dlq WHERE status='pending'", fetch="one")["n"]


def mark_status(ids: list, status: str):
    _run("UPDATE dlq SET status=? WHERE id=?", [(status, i) for i in ids], many=True)


def mark_cluster(cluster_id: str, status: str) -> int:
    rows = cluster_entries(cluster_id, limit=1_000_000)
    mark_status([r["id"] for r in rows], status)
    return len(rows)


def list_recent(limit: int = 50, status: str = None) -> list:
    if status:
        return _run("SELECT * FROM dlq WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit),
                    fetch="all")
    return _run("SELECT * FROM dlq ORDER BY id DESC LIMIT ?", (limit,), fetch="all")


def get_by_event_id(event_id: str):
    return _run("SELECT * FROM dlq WHERE event_id=? ORDER BY id DESC LIMIT 1", (event_id,), fetch="one")


def status_counts() -> dict:
    rows = _run("SELECT status, COUNT(*) AS n FROM dlq GROUP BY status", fetch="all")
    return {r["status"]: r["n"] for r in rows}


# ---------------------------------------------------------------- proposals
def add_proposal(p: dict) -> int:
    # an older open proposal for the same cluster is superseded by this one
    _run("UPDATE proposals SET status='superseded', updated_at=? WHERE cluster_id=? AND status='open'",
         (_now(), p["cluster_id"]))
    return _run(
        "INSERT INTO proposals (cluster_id, channel, cluster_label, created_at, updated_at, filename, yaml, "
        "generator, sample_count, pending_at_creation, match_rate, validation, awareness, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
        (p["cluster_id"], p["channel"], p.get("cluster_label"), _now(), _now(), p["filename"],
         p["yaml"], p["generator"], p["sample_count"], p["pending_at_creation"], p.get("match_rate"),
         json.dumps(p.get("validation")), json.dumps(p.get("awareness"))),
        fetch="lastrowid")


def _decode(p):
    if p:
        p["validation"] = json.loads(p["validation"]) if p.get("validation") else None
        p["awareness"] = json.loads(p["awareness"]) if p.get("awareness") else None
    return p


def get_proposal(proposal_id: int):
    return _decode(_run("SELECT * FROM proposals WHERE id=?", (proposal_id,), fetch="one"))


def latest_proposal(cluster_id: str):
    return _decode(_run("SELECT * FROM proposals WHERE cluster_id=? ORDER BY id DESC LIMIT 1",
                        (cluster_id,), fetch="one"))


def list_proposals(status: str = None, limit: int = 50) -> list:
    if status:
        rows = _run("SELECT * FROM proposals WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit),
                    fetch="all")
    else:
        rows = _run("SELECT * FROM proposals ORDER BY id DESC LIMIT ?", (limit,), fetch="all")
    return [_decode(r) for r in rows]


def update_proposal(proposal_id: int, **fields):
    fields["updated_at"] = _now()
    for k in ("validation", "awareness"):
        if k in fields and not isinstance(fields[k], str):
            fields[k] = json.dumps(fields[k])
    sets = ", ".join(f"{k}=?" for k in fields)
    _run(f"UPDATE proposals SET {sets} WHERE id=?", (*fields.values(), proposal_id))
