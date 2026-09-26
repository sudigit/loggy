"""
Continuous DLQ watcher -- keeps self-heal suggestions flowing without anyone
running a batch job.

Every `tick` seconds it looks at each pending DLQ *cluster* (one kind of
unknown event on one channel) and decides:

  waiting_min   fewer than `min_samples` events      -> never propose (would overfit)
  waiting       below `count` and younger than `max_wait`
  ready         >= count  OR  (>= min_samples and oldest event waited >= max_wait)
                -> generate a proposal (inference / local LLM), validate it, store it
  proposed      an open proposal exists and no meaningful new data since
  refresh       an open proposal exists but enough NEW samples arrived
                (>= count/2 new, or any new after max_wait) -> re-propose

Only proposals are produced. Promotion to live traffic is always a human action.
"""
import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone

from src import config
from src.dlq import store as dlq_store

logger = logging.getLogger("ulpf.dlq_processor")


def _age_seconds(iso: str) -> float:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except (TypeError, ValueError):
        return 0.0


class DLQProcessor:
    def __init__(self, tick_seconds: float = None, min_samples: int = None,
                 count_threshold: int = None, time_threshold_sec: int = None):
        self.tick_seconds = tick_seconds or config.DLQ_TICK_SECONDS
        self.min_samples = min_samples or config.DLQ_MIN_SAMPLES
        self.count_threshold = count_threshold or config.DLQ_COUNT_THRESHOLD
        self.time_threshold_sec = time_threshold_sec or config.DLQ_TIME_THRESHOLD
        self._stop = threading.Event()
        self._thread = None
        self._cycle_lock = threading.Lock()
        self.last_tick = None
        self.last_cycle_ms = None
        self.cycles = 0
        self.activity = deque(maxlen=60)
        self._busy_cluster = None

    # ------------------------------------------------------------ lifecycle
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="dlq-processor")
        self._thread.start()
        self._log("info", f"DLQ watcher started (tick {self.tick_seconds}s, min {self.min_samples}, "
                          f"count {self.count_threshold}, max wait {self.time_threshold_sec}s)")

    def stop(self):
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 - the watcher must never die
                logger.exception("DLQ watcher tick failed")
                self._log("error", f"tick failed: {e}")
            self._stop.wait(self.tick_seconds)

    def _log(self, level: str, msg: str, **extra):
        self.activity.appendleft({"ts": datetime.now(timezone.utc).isoformat(), "level": level,
                                  "message": msg, **extra})
        getattr(logger, "error" if level == "error" else "info")(f"[dlq-watcher] {msg}")

    # ------------------------------------------------------------ decisions
    def evaluate(self, cluster: dict) -> dict:
        count = cluster["count"]
        age = _age_seconds(cluster["first_ts"])
        latest = dlq_store.latest_proposal(cluster["cluster_id"])
        open_prop = latest if latest and latest["status"] == "open" else None
        state, eta = "waiting", None

        if open_prop:
            new = count - (open_prop["pending_at_creation"] or 0)
            since = _age_seconds(open_prop["created_at"])
            if new >= max(1, self.count_threshold // 2) or (new > 0 and since >= self.time_threshold_sec):
                state = "refresh"
            else:
                state = "proposed"
        else:
            if latest and latest["status"] in ("promoted", "dismissed"):
                # events that still fail after a promotion / dismissal only count
                # once they are NEW since that decision -- no re-proposal loop
                since = dlq_store.pending_since(cluster["cluster_id"], latest["updated_at"])
                count, age = since["n"], _age_seconds(since["first_ts"]) if since["first_ts"] else 0.0
            if count < self.min_samples:
                state = "waiting_min"
            elif count >= self.count_threshold or age >= self.time_threshold_sec:
                state = "ready"
            else:
                eta = max(0.0, self.time_threshold_sec - age)
        return {
            "state": state,
            "count": cluster["count"],
            "counted": count,
            "age_seconds": round(age, 1),
            "eta_seconds": round(eta, 1) if eta is not None else None,
            "needed_for_count": max(0, self.count_threshold - count) if state != "proposed" else 0,
            "needed_for_min": max(0, self.min_samples - count),
            "proposal_id": open_prop["id"] if open_prop else None,
            "latest_proposal_status": latest["status"] if latest else None,
        }

    def tick(self, force_cluster: str = None) -> list:
        """One pass over all pending clusters. Returns the proposals created."""
        from src.selfheal import service
        created = []
        with self._cycle_lock:
            t0 = time.time()
            for cluster in dlq_store.pending_clusters():
                cid = cluster["cluster_id"]
                decision = self.evaluate(cluster)
                forced = force_cluster in (cid, "*")
                if not forced and decision["state"] not in ("ready", "refresh"):
                    continue
                self._busy_cluster = cid
                try:
                    proposal = service.generate_proposal(cid)
                    created.append(proposal)
                    self._log("proposal",
                              f"{'Refreshed' if decision['state'] == 'refresh' else 'New'} proposal #{proposal['id']} "
                              f"for {cluster['label']} -> {proposal['filename']} "
                              f"({int((proposal['match_rate'] or 0) * 100)}% of samples, {proposal['generator']})",
                              cluster_id=cid, proposal_id=proposal["id"])
                except Exception as e:  # noqa: BLE001
                    logger.exception(f"proposal generation failed for {cid}")
                    self._log("error", f"proposal for {cluster['label']} failed: {e}", cluster_id=cid)
                finally:
                    self._busy_cluster = None
            self.cycles += 1
            self.last_tick = datetime.now(timezone.utc)
            self.last_cycle_ms = round((time.time() - t0) * 1000, 1)
        return created

    # ------------------------------------------------------------ monitoring
    def status(self) -> dict:
        clusters = []
        for c in dlq_store.pending_clusters():
            clusters.append({**c, **self.evaluate(c), "busy": c["cluster_id"] == self._busy_cluster})
        next_tick = None
        if self.last_tick and self.running:
            elapsed = (datetime.now(timezone.utc) - self.last_tick).total_seconds()
            next_tick = round(max(0.0, self.tick_seconds - elapsed), 1)
        return {
            "running": self.running,
            "enabled": config.SELFHEAL_ENABLED,
            "settings": {
                "tick_seconds": self.tick_seconds,
                "min_samples": self.min_samples,
                "count_threshold": self.count_threshold,
                "time_threshold_sec": self.time_threshold_sec,
            },
            "cycles": self.cycles,
            "last_tick": self.last_tick.isoformat() if self.last_tick else None,
            "last_cycle_ms": self.last_cycle_ms,
            "next_tick_in": next_tick,
            "pending_events": sum(c["count"] for c in clusters),
            "clusters": clusters,
            "activity": list(self.activity)[:25],
            "dlq_status_counts": dlq_store.status_counts(),
        }

    def update_settings(self, **kw):
        for key in ("tick_seconds", "min_samples", "count_threshold", "time_threshold_sec"):
            if kw.get(key) is not None:
                val = float(kw[key]) if key == "tick_seconds" else int(kw[key])
                if val <= 0:
                    raise ValueError(f"{key} must be positive")
                setattr(self, key, val)
        self._log("info", f"settings updated: tick {self.tick_seconds}s, min {self.min_samples}, "
                          f"count {self.count_threshold}, max wait {self.time_threshold_sec}s")


_processor = None
_lock = threading.Lock()


def get_processor() -> DLQProcessor:
    global _processor
    if _processor is None:
        with _lock:
            if _processor is None:
                _processor = DLQProcessor()
    return _processor
