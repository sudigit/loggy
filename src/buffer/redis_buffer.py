"""
Redis Streams durable buffering layer for ULPF.

Decouples ingestion listeners (Syslog, HTTP, File) from parsing workers:
  - Ingestion path calls `push_to_stream()` -> performs XADD (sub-millisecond, zero drops).
  - Background worker pool consumes from consumer group -> parses, writes OCSF/DLQ, calls XACK.
  - Automatically falls back to synchronous in-process mode if Redis is not running or unreachable.
"""
import logging
import threading
import time
from typing import Optional

from src import config
from src.core import metrics

logger = logging.getLogger("ulpf.buffer")

_redis_client = None
_buffer_mode = "direct"  # "redis" or "direct"
_resolved = False        # connection is attempted ONCE -- a dead Redis is never retried per event
_stop_workers = False


def get_redis_client():
    global _redis_client, _buffer_mode, _resolved
    if _resolved:
        return _redis_client
    _resolved = True

    if config.BUFFER_TYPE == "direct":
        _buffer_mode = "direct"
        return None

    try:
        import redis
        client = redis.Redis.from_url(config.REDIS_URL, decode_responses=False,
                                      socket_timeout=2.0, socket_connect_timeout=1.0)
        client.ping()
        _redis_client = client
        _buffer_mode = "redis"
        return _redis_client
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[buffer] Redis unavailable ({e}). Falling back to direct in-process buffer.")
        _buffer_mode = "direct"
        return None


def init_buffer() -> str:
    """Initializes the Redis stream and consumer group if Redis is available."""
    global _buffer_mode
    client = get_redis_client()
    if client is None:
        _buffer_mode = "direct"
        return "direct"

    stream_name = config.STREAM_NAME
    group_name = config.CONSUMER_GROUP

    try:
        # Create consumer group if not already present
        client.xgroup_create(stream_name, group_name, id="0", mkstream=True)
        logger.info(f"[buffer] Created consumer group '{group_name}' on stream '{stream_name}'")
    except Exception as e:
        # BUSYGROUP Consumer Group name already exists is expected on restarts
        if "BUSYGROUP" not in str(e):
            logger.warning(f"[buffer] Could not initialize consumer group: {e}")

    _buffer_mode = "redis"
    return "redis"


def get_buffer_mode() -> str:
    return _buffer_mode


def push_to_stream(event_id: str, raw_bytes: bytes, channel: str,
                   source_hint: Optional[str], ingest_time_iso: str, raw_info: dict = None) -> bool:
    """Fast-path publish into Redis Stream."""
    client = get_redis_client()
    if client is None or _buffer_mode != "redis":
        return False

    payload = {
        b"event_id": event_id.encode("utf-8"),
        b"raw": raw_bytes,
        b"channel": channel.encode("utf-8"),
        b"source_hint": (source_hint or "").encode("utf-8"),
        b"ingest_time": ingest_time_iso.encode("utf-8"),
        b"raw_ref": (raw_info or {}).get("raw_ref", "").encode("utf-8"),
        b"raw_sha256": (raw_info or {}).get("sha256", "").encode("utf-8"),
    }
    try:
        client.xadd(config.STREAM_NAME, payload)
        metrics.incr("buffered")
        return True
    except Exception as e:
        logger.error(f"[buffer] Failed to push to Redis stream: {e}. Falling back to direct.")
        return False


def get_backlog_size() -> int:
    """Returns number of items pending in stream."""
    client = get_redis_client()
    if client is None or _buffer_mode != "redis":
        return 0
    try:
        return client.xlen(config.STREAM_NAME)
    except Exception:
        return 0


def _worker_loop(worker_name: str):
    """Background worker consuming from Redis Stream and running parsing pipeline."""
    from src.pipeline import execute_event_processing

    client = get_redis_client()
    if client is None:
        return

    stream_name = config.STREAM_NAME
    group_name = config.CONSUMER_GROUP

    logger.info(f"[buffer] Worker {worker_name} started listening to stream '{stream_name}'")

    while not _stop_workers:
        try:
            # Read batch of messages from stream using consumer group
            messages = client.xreadgroup(
                groupname=group_name,
                consumername=worker_name,
                streams={stream_name: ">"},
                count=config.STREAM_BATCH_SIZE,
                block=1000,
            )

            if not messages:
                continue

            for stream_entry in messages:
                _, entries = stream_entry
                for msg_id, data in entries:
                    try:
                        event_id = data[b"event_id"].decode("utf-8")
                        raw_bytes = data[b"raw"]
                        channel = data[b"channel"].decode("utf-8")
                        hint_raw = data.get(b"source_hint", b"").decode("utf-8")
                        source_hint = hint_raw if hint_raw else None
                        ingest_time_iso = data[b"ingest_time"].decode("utf-8")
                        raw_info = {
                            "raw_ref": data.get(b"raw_ref", b"").decode("utf-8") or None,
                            "sha256": data.get(b"raw_sha256", b"").decode("utf-8") or None,
                            "size_bytes": len(raw_bytes),
                        }

                        # Execute core parser + schema mapping + output writer / dlq
                        execute_event_processing(
                            event_id=event_id,
                            raw_bytes=raw_bytes,
                            channel=channel,
                            source_hint=source_hint,
                            ingest_time_iso=ingest_time_iso,
                            raw_info=raw_info,
                        )

                        # Acknowledge processed message
                        client.xack(stream_name, group_name, msg_id)
                    except Exception as inner_e:
                        logger.error(f"[buffer] Error processing stream message {msg_id}: {inner_e}")
                        # Even on error, ACK so we do not poison-pill the stream; error is in DLQ
                        client.xack(stream_name, group_name, msg_id)

        except Exception as e:
            if not _stop_workers:
                logger.error(f"[buffer] Worker {worker_name} stream read error: {e}")
                time.sleep(1.0)


def start_workers(num_workers: int = None):
    """Starts background consumer worker threads."""
    global _stop_workers
    _stop_workers = False

    if get_redis_client() is None or _buffer_mode != "redis":
        logger.info("[buffer] Running in direct mode, background Redis workers not needed.")
        return []

    count = num_workers or config.STREAM_WORKER_COUNT
    threads = []
    for i in range(count):
        worker_id = f"worker-{i+1}"
        t = threading.Thread(target=_worker_loop, args=(worker_id,), daemon=True)
        t.start()
        threads.append(t)
    logger.info(f"[buffer] Spawned {count} Redis Stream consumer workers.")
    return threads


def stop_workers():
    global _stop_workers
    _stop_workers = True
