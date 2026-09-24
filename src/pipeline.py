"""
This is the one function every ingestion channel (syslog, HTTP, file
watcher) calls. It is deliberately synchronous and single-process in this
prototype -- the full architecture replaces the direct call below with a
durable buffer (Redis Streams / Kafka) between ingestion and this stage so
it can scale horizontally and survive a crash mid-batch. Swapping that in
later does not change anything below this line.
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


def process_event(raw_bytes: bytes, channel: str, source_hint: str = None):
    text = raw_bytes.decode("utf-8", errors="replace")
    event_id = ids.new_event_id()
    ingest_time_iso = ids.utc_now_iso()

    # Step 1: preserve the original, verbatim and hashed, before anything
    # else touches it. Whatever happens downstream, this copy is the truth.
    provisional_source = source_hint or channel.split(":")[-1]
    raw_store.save(event_id, provisional_source, raw_bytes,
                    meta={"channel": channel, "ingest_time": ingest_time_iso})
    metrics.incr("ingested")
    metrics.incr_source(provisional_source, "ingested")

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
