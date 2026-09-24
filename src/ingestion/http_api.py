"""
HTTP surface for the framework:
  GET  /                  -- visual metrics dashboard
  GET  /dashboard         -- visual metrics dashboard
  GET  /selfheal          -- interactive DLQ & AI self-healing studio
  GET  /api/dlq/pending   -- pending unparsed events grouped by channel
  POST /api/selfheal/propose -- generate AI proposal YAML for a channel
  POST /api/selfheal/promote -- regression-test & promote proposed YAML
  POST /ingest            -- push a log event in (used for JSON sources like Suricata)
  GET  /health            -- liveness
  GET  /metrics           -- EPS, parse success rate, buffer backlog, storage mode
  GET  /dlq               -- recent dead-lettered events (raw list)
  GET  /events/recent     -- last N normalized records for a given source
  GET  /events/stream     -- last N normalized records across all sources
"""
import json
from pathlib import Path

from flask import Flask, request, jsonify, render_template

from src import config
from src.core import metrics
from src.dlq import store as dlq_store
from src.pipeline import process_event
from src.selfheal import service as selfheal_service

template_dir = Path(__file__).resolve().parent / "templates"
app = Flask(__name__, template_folder=str(template_dir))


@app.get("/")
@app.get("/dashboard")
def dashboard_view():
    return render_template("dashboard.html")


@app.get("/selfheal")
def selfheal_view():
    return render_template("selfheal.html")


@app.get("/api/dlq/pending")
def api_dlq_pending():
    return jsonify(selfheal_service.get_pending_summary())


@app.post("/api/selfheal/propose")
def api_selfheal_propose():
    data = request.get_json(force=True, silent=True) or {}
    channel = data.get("channel")
    if not channel:
        return jsonify({"error": "channel parameter required"}), 400
    proposal = selfheal_service.generate_proposal_for_channel(channel)
    return jsonify(proposal)


@app.post("/api/selfheal/promote")
def api_selfheal_promote():
    data = request.get_json(force=True, silent=True) or {}
    filename = data.get("filename")
    yaml_content = data.get("yaml")
    if not filename or not yaml_content:
        return jsonify({"success": False, "error": "Missing filename or yaml content"}), 400

    success, message = selfheal_service.promote_proposal_yaml(filename, yaml_content)
    return jsonify({"success": success, "message": message if success else None, "error": message if not success else None})


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


@app.get("/events/stream")
def events_stream():
    """Returns the most recent N normalized records across all registered sources."""
    limit = int(request.args.get("n", 15))
    all_events = []
    if config.NORMALIZED_DIR.exists():
        for source_dir in config.NORMALIZED_DIR.iterdir():
            if source_dir.is_dir():
                files = sorted(source_dir.glob("*.jsonl"))
                if files:
                    try:
                        with open(files[-1]) as f:
                            lines = f.readlines()[-limit:]
                        for line in lines:
                            if line.strip():
                                all_events.append(json.loads(line))
                    except Exception:
                        pass
    # Sort descending by ISO timestamp
    all_events.sort(key=lambda x: x.get("time", ""), reverse=True)
    return jsonify(all_events[:limit])


def run(port: int = None):
    app.run(host="0.0.0.0", port=port or config.HTTP_API_PORT, threaded=True)
