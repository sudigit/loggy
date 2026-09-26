"""
In-process metrics + a small ring buffer of recent normalized events.
Feeds /metrics and the live console UI. (A production deployment would
export the same counters to Prometheus.)
"""
import threading
import time
from collections import defaultdict, deque

from src import config

_lock = threading.Lock()
_counters = defaultdict(int)
_per_source = defaultdict(lambda: defaultdict(int))
_source_last_seen = {}
_started_at = time.time()

# Per-second history for the throughput sparkline (last 120 s).
_HISTORY_SECONDS = 120
_history = deque(maxlen=_HISTORY_SECONDS)  # (second, ingested, parsed, dlq)
_cur_second = int(time.time())
_cur_bucket = [0, 0, 0]
_BUCKET_INDEX = {"ingested": 0, "parsed": 1, "dlq": 2}

_recent_events = deque(maxlen=config.RECENT_EVENTS_BUFFER)
_recent_index = {}


def _roll(now_sec: int):
    global _cur_second, _cur_bucket
    if now_sec == _cur_second:
        return
    _history.append((_cur_second, *_cur_bucket))
    # fill empty seconds so the sparkline has no gaps
    gap = min(now_sec - _cur_second - 1, _HISTORY_SECONDS)
    for i in range(gap):
        _history.append((_cur_second + i + 1, 0, 0, 0))
    _cur_second = now_sec
    _cur_bucket = [0, 0, 0]


def incr(key: str, n: int = 1):
    with _lock:
        _counters[key] += n
        if key in _BUCKET_INDEX:
            _roll(int(time.time()))
            _cur_bucket[_BUCKET_INDEX[key]] += n


def incr_source(source_id: str, key: str, n: int = 1):
    with _lock:
        _per_source[source_id][key] += n
        _source_last_seen[source_id] = time.time()


def record_event(ocsf: dict):
    """Keeps the latest N normalized events in memory for the explorer UI."""
    with _lock:
        if len(_recent_events) == _recent_events.maxlen:
            old = _recent_events[0]
            _recent_index.pop(old["metadata"]["uid"], None)
        _recent_events.append(ocsf)
        _recent_index[ocsf["metadata"]["uid"]] = ocsf


def recent_events(n: int = 50, source_id: str = None, class_uid: int = None) -> list:
    with _lock:
        items = list(_recent_events)
    out = []
    for ev in reversed(items):
        if source_id and ev["metadata"].get("source_id") != source_id:
            continue
        if class_uid and ev.get("class_uid") != class_uid:
            continue
        out.append(ev)
        if len(out) >= n:
            break
    return out


def get_recent_event(uid: str):
    with _lock:
        return _recent_index.get(uid)


def history() -> list:
    with _lock:
        _roll(int(time.time()))
        return [{"t": s, "ingested": i, "parsed": p, "dlq": d} for s, i, p, d in _history]


def snapshot() -> dict:
    with _lock:
        _roll(int(time.time()))
        ingested = _counters.get("ingested", 0)
        parsed = _counters.get("parsed", 0)
        dlq = _counters.get("dlq", 0)
        uptime = max(time.time() - _started_at, 0.001)
        recent = list(_history)[-10:]
        per_source = {
            k: {**dict(v), "last_seen": _source_last_seen.get(k)} for k, v in _per_source.items()
        }
        counters = dict(_counters)

    buffer_mode, backlog_size = "direct", 0
    try:
        from src.buffer import redis_buffer
        buffer_mode = redis_buffer.get_buffer_mode()
        backlog_size = redis_buffer.get_backlog_size()
    except Exception:  # noqa: BLE001
        pass

    raw_store_mode = "local"
    try:
        from src.core import raw_store
        raw_store_mode = raw_store.get_store_mode()
    except Exception:  # noqa: BLE001
        pass

    current_eps = round(sum(r[1] for r in recent) / max(len(recent), 1), 2)
    return {
        "uptime_seconds": round(uptime, 1),
        "total_ingested": ingested,
        "total_parsed": parsed,
        "total_dlq": dlq,
        "total_buffered": counters.get("buffered", 0),
        "total_replayed": counters.get("replayed", 0),
        "schema_violations": counters.get("schema_violation", 0),
        "buffer_mode": buffer_mode,
        "buffer_backlog": backlog_size,
        "raw_store_mode": raw_store_mode,
        "sinks": list(config.SINKS),
        "parse_success_rate_pct": round((parsed / ingested * 100), 2) if ingested else None,
        "events_per_second": current_eps,
        "avg_events_per_second": round(ingested / uptime, 2),
        "per_source": per_source,
    }
