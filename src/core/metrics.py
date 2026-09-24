import threading
import time
from collections import defaultdict

_lock = threading.Lock()
_counters = defaultdict(int)
_per_source = defaultdict(lambda: defaultdict(int))
_started_at = time.time()


def incr(key: str, n: int = 1):
    with _lock:
        _counters[key] += n


def incr_source(source_id: str, key: str, n: int = 1):
    with _lock:
        _per_source[source_id][key] += n


def snapshot() -> dict:
    with _lock:
        ingested = _counters.get("ingested", 0)
        parsed = _counters.get("parsed", 0)
        dlq = _counters.get("dlq", 0)
        uptime = max(time.time() - _started_at, 0.001)
        return {
            "uptime_seconds": round(uptime, 1),
            "total_ingested": ingested,
            "total_parsed": parsed,
            "total_dlq": dlq,
            "parse_success_rate_pct": round((parsed / ingested * 100), 2) if ingested else None,
            "events_per_second": round(ingested / uptime, 2),
            "per_source": {k: dict(v) for k, v in _per_source.items()},
        }
