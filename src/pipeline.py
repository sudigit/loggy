"""
Pipeline coordinator for ULPF.

Manages event ingestion flow:
  1. Mint UUID and UTC timestamp.
  2. Store raw bytes verbatim + SHA-256 hash in raw_store (forensic compliance).
  3. Buffer event into Redis Stream (if enabled/available) for decoupled high-throughput processing.
  4. If direct mode or Redis unavailable, executes parsing and normalization inline.
"""
from src import config
from src.core import ids, raw_store, metrics
from src.dlq import store as dlq_store
from src.output import writer

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        from src.parser.engine import ParserEngine
        _engine = ParserEngine()
    return _engine


def execute_event_processing(event_id: str, raw_bytes: bytes, channel: str,
                             source_hint: str = None, ingest_time_iso: str = None) -> dict:
    """Core deterministic parsing, schema normalization, and routing to writer/DLQ."""
    text = raw_bytes.decode("utf-8", errors="replace")
    ingest_time_iso = ingest_time_iso or ids.utc_now_iso()
    provisional_source = source_hint or channel.split(":")[-1]

    engine = get_engine()
    parser_config = engine.select(text, channel)
    if parser_config is None:
        dlq_store.add(event_id, channel, source_hint, text, error="no_parser_match")
        metrics.incr("dlq")
        metrics.incr_source(provisional_source, "dlq")
        return {"event_id": event_id, "status": "dlq", "reason": "no_parser_match"}

    try:
        tokens = engine.tokenize(text, parser_config)
        ocsf = engine.normalize(tokens, parser_config, event_id, ingest_time_iso)
    except Exception as e:  # noqa: BLE001 - any parse failure goes to DLQ, never crashes the pipeline
        dlq_store.add(event_id, channel, source_hint, text, error=str(e))
        metrics.incr("dlq")
        metrics.incr_source(provisional_source, "dlq")
        return {"event_id": event_id, "status": "dlq", "reason": str(e)}

    writer.write(ocsf)
    metrics.incr("parsed")
    metrics.incr_source(parser_config["source_id"], "parsed")
    return {"event_id": event_id, "status": "parsed", "source_id": parser_config["source_id"]}


def process_event(raw_bytes: bytes, channel: str, source_hint: str = None) -> dict:
    """
    Entrypoint called by all ingestion listeners (syslog, HTTP, file watcher).
    Guarantees raw forensic capture, then routes to Redis Stream or direct processing.
    """
    event_id = ids.new_event_id()
    ingest_time_iso = ids.utc_now_iso()
    provisional_source = source_hint or channel.split(":")[-1]

    # Step 1: Preserve original verbatim and hashed before anything touches it
    raw_store.save(event_id, provisional_source, raw_bytes,
                   meta={"channel": channel, "ingest_time": ingest_time_iso})
    metrics.incr("ingested")
    metrics.incr_source(provisional_source, "ingested")

    # Step 2: Try durable buffer (Redis Streams)
    from src.buffer import redis_buffer
    if redis_buffer.get_buffer_mode() == "redis":
        pushed = redis_buffer.push_to_stream(
            event_id=event_id,
            raw_bytes=raw_bytes,
            channel=channel,
            source_hint=source_hint,
            ingest_time_iso=ingest_time_iso,
        )
        if pushed:
            return {"event_id": event_id, "status": "buffered", "channel": channel}

    # Step 3: Direct execution fallback
    return execute_event_processing(
        event_id=event_id,
        raw_bytes=raw_bytes,
        channel=channel,
        source_hint=source_hint,
        ingest_time_iso=ingest_time_iso,
    )
