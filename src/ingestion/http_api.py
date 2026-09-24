"""
HTTP surface for the framework:
  POST /ingest        -- push a log event in (used for JSON sources like Suricata,
                          and generally for any source that prefers HTTP over syslog)
  GET  /health         -- liveness
  GET  /metrics         -- EPS, parse success rate, per-source breakdown
  GET  /dlq             -- recent dead-lettered events (for the demo / debugging)
  GET  /events/recent    -- last N normalized records for a given source
"""
import json

from flask import Flask, request, jsonify

from src import config
from src.core import metrics
from src.dlq import store as dlq_store
from src.pipeline import process_event

app = Flask(__name__)


@app.post("/ingest")
def ingest():
    body = request.get_json(force=True, silent=True) or {}
    channel = body.get("channel", "http")
    source_hint = body.get("source_hint")
    raw = body.get("raw")
    if raw is None:
        return jsonify({"error": "missing 'raw' field"}), 400
    raw_bytes = json.dumps(raw).encode("utf-8") if isinstance(raw, (dict, list)) else str(raw).encode("utf-8")
    result = process_event(raw_bytes, channel=channel, source_hint=source_hint)
    return jsonify(result)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/metrics")
def metrics_endpoint():
    return jsonify(metrics.snapshot())


@app.get("/dlq")
def dlq_recent():
    return jsonify(dlq_store.list_recent(limit=int(request.args.get("n", 50))))


@app.get("/events/recent")
def events_recent():
    source = request.args.get("source")
    n = int(request.args.get("n", 10))
    if not source:
        return jsonify({"error": "source query param required"}), 400
    results = []
    folder = config.NORMALIZED_DIR / source
    if folder.exists():
        files = sorted(folder.glob("*.jsonl"))
        if files:
            with open(files[-1]) as f:
                lines = f.readlines()[-n:]
            results = [json.loads(l) for l in lines]
    return jsonify(results)


def run(port: int = None):
    app.run(host="0.0.0.0", port=port or config.HTTP_API_PORT, threaded=True)
