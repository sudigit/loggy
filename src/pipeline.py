"""
Pipeline coordinator for ULPF.

  1. Mint UUID + UTC ingest timestamp.
  2. Store raw bytes verbatim + SHA-256 (forensic preservation) -> raw_ref.
  3. Buffer into Redis Streams (if available) for decoupled high-throughput processing,
     or process inline in direct mode.
  4. Parse -> normalize -> enrich -> validate; write to sinks, or quarantine in the DLQ.
     Every outcome (normalized record or DLQ row) carries raw_ref + raw_sha256.
"""
import threading

from src.core import ids, metrics, raw_store
from src.dlq import store as dlq_store
from src.output import sinks

_engine = None
_engine_lock = threading.Lock()


def get_engine():
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                from src.parser.engine import ParserEngine
                _engine = ParserEngine()
    return _engine


def execute_event_processing(event_id: str, raw_bytes: bytes, channel: str,
                             source_hint: str = None, ingest_time_iso: str = None,
                             raw_info: dict = None, replay: bool = False) -> dict:
    """Deterministic parse + normalize + route. With replay=True (DLQ re-drive
    after a parser is promoted) failures are reported but NOT re-added to the DLQ."""
    from src.parser.engine import ParseError

    text = raw_bytes.decode("utf-8", errors="replace")
    ingest_time_iso = ingest_time_iso or ids.utc_now_iso()
    raw_info = raw_info or {}

    try:
        ocsf_event, parser_config = get_engine().process(
            text, channel, event_id, ingest_time_iso, raw_info=raw_info)
    except ParseError as e:
        if not replay:
            dlq_store.add(event_id, channel, source_hint, text, error=str(e), reason=e.reason,
                          parser_id=e.parser_id, raw_ref=raw_info.get("raw_ref"),
                          raw_sha256=raw_info.get("sha256"), ingest_time=ingest_time_iso)
            metrics.incr("dlq")
            metrics.incr(e.reason)
            metrics.incr_source(e.parser_id or f"unknown@{channel}", "dlq")
        return {"event_id": event_id, "status": "dlq", "reason": e.reason, "detail": e.detail,
                "parser_id": e.parser_id}

    sinks.emit(ocsf_event)
    metrics.record_event(ocsf_event)
    metrics.incr("parsed")
    if replay:
        metrics.incr("replayed")
    metrics.incr_source(parser_config["source_id"], "parsed")
    return {"event_id": event_id, "status": "parsed", "source_id": parser_config["source_id"],
            "class_uid": ocsf_event["class_uid"]}


def process_event(raw_bytes: bytes, channel: str, source_hint: str = None) -> dict:
    """
    Entrypoint called by all ingestion listeners (syslog, HTTP, file watcher).
    Guarantees raw forensic capture, then routes to Redis Stream or direct processing.
    """
    event_id = ids.new_event_id()
    ingest_time_iso = ids.utc_now_iso()
    provisional_source = source_hint or channel.split(":")[-1]

    # Step 1: preserve the original verbatim + hashed before anything touches it
    raw_info = raw_store.save(event_id, provisional_source, raw_bytes,
                              meta={"channel": channel, "ingest_time": ingest_time_iso,
                                    "source_hint": source_hint})
    metrics.incr("ingested")
    metrics.incr_source(provisional_source, "ingested")

    # Step 2: durable buffer (Redis Streams)
    from src.buffer import redis_buffer
    if redis_buffer.get_buffer_mode() == "redis":
        pushed = redis_buffer.push_to_stream(
            event_id=event_id, raw_bytes=raw_bytes, channel=channel, source_hint=source_hint,
            ingest_time_iso=ingest_time_iso, raw_info=raw_info,
        )
        if pushed:
            return {"event_id": event_id, "status": "buffered", "channel": channel,
                    "raw_ref": raw_info["raw_ref"]}

    # Step 3: direct execution fallback
    result = execute_event_processing(
        event_id=event_id, raw_bytes=raw_bytes, channel=channel, source_hint=source_hint,
        ingest_time_iso=ingest_time_iso, raw_info=raw_info,
    )
    result["raw_ref"] = raw_info["raw_ref"]
    return result


def replay_dlq_entry(entry: dict) -> dict:
    """Re-drives one quarantined event from its ARCHIVED ORIGINAL (not the DLQ
    snippet, which may be truncated) through the current parsers."""
    raw_ref = entry.get("raw_ref")
    if raw_ref:
        try:
            raw_bytes = raw_store.read_ref(raw_ref)
        except Exception:  # noqa: BLE001
            raw_bytes = entry["raw_snippet"].encode("utf-8")
    else:
        raw_bytes = entry["raw_snippet"].encode("utf-8")
    raw_info = {"raw_ref": raw_ref, "sha256": entry.get("raw_sha256"), "size_bytes": len(raw_bytes)}
    return execute_event_processing(
        event_id=entry["event_id"], raw_bytes=raw_bytes, channel=entry["channel"],
        source_hint=entry.get("source_hint"), ingest_time_iso=entry.get("ingest_time") or entry.get("ts"),
        raw_info=raw_info, replay=True,
    )
