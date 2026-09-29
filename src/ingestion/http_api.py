"""
HTTP surface for ULPF.

Console (single-page UI, no external assets -- works air-gapped)
  GET  /  /dashboard  /events  /selfheal  /parsers

Ingestion
  POST /ingest                         {"raw": <str|obj>, "channel": "http", "source_hint": ...}
                                       or {"events": [ ... same objects ... ]} for batches

Observability
  GET  /health   /metrics   /metrics/history   /api/schema

Normalized events + traceability
  GET  /events/recent?source=&class_uid=&n=
  GET  /events/stream?n=
  GET  /events/<uid>                   normalized record (or DLQ row) for an event id
  GET  /events/<uid>/raw               archived original + stored vs recomputed SHA-256

Dead-letter queue + self-heal
  GET  /dlq?n=&status=                 raw DLQ rows
  GET  /api/dlq/clusters/<cid>         events in one cluster
  POST /api/dlq/clusters/<cid>/dismiss
  POST /api/dlq/replay                 {"cluster_id": optional} re-drive from raw archive
  GET  /api/selfheal/status            watcher state, thresholds, clusters, activity feed
  POST /api/selfheal/settings          {"tick_seconds", "min_samples", "count_threshold", "time_threshold_sec"}
  POST /api/selfheal/run               {"cluster_id": optional} propose now (ignores thresholds)
  GET  /api/selfheal/proposals?status=
  GET  /api/selfheal/proposals/<id>
  POST /api/selfheal/proposals/<id>/validate   {"yaml"}  dry-run an edited proposal
  POST /api/selfheal/proposals/<id>/promote    {"yaml", "approved_by"}
  POST /api/selfheal/proposals/<id>/dismiss

Parser registry
  GET  /api/parsers
  GET  /api/parsers/<source_id>/yaml
  POST /api/parsers/<source_id>/rollback
"""
import json
from pathlib import Path

import yaml
from flask import Flask, jsonify, render_template, request

from src import config
from src.core import metrics, raw_store
from src.dlq import store as dlq_store
from src.pipeline import get_engine, process_event
from src.selfheal import service as selfheal
from src.selfheal.dlq_processor import get_processor

template_dir = Path(__file__).resolve().parent / "templates"
app = Flask(__name__, template_folder=str(template_dir))
app.json.sort_keys = False


def _body() -> dict:
    return request.get_json(force=True, silent=True) or {}


# ------------------------------------------------------------------ console
@app.get("/")
@app.get("/dashboard")
@app.get("/events")
@app.get("/selfheal")
@app.get("/parsers")
def console_view():
    return render_template("console.html")


# ------------------------------------------------------------------ ingestion
def _ingest_one(item: dict) -> dict:
    raw = item.get("raw")
    if raw is None:
        return {"error": "missing 'raw' field"}
    raw_bytes = json.dumps(raw).encode("utf-8") if isinstance(raw, (dict, list)) else str(raw).encode("utf-8")
    return process_event(raw_bytes, channel=item.get("channel", "http"), source_hint=item.get("source_hint"))


@app.post("/ingest")
def ingest():
    body = _body()
    if isinstance(body.get("events"), list):
        return jsonify({"results": [_ingest_one(e) for e in body["events"] if isinstance(e, dict)]})
    result = _ingest_one(body)
    return (jsonify(result), 400) if "error" in result else jsonify(result)


# ------------------------------------------------------------------ observability
@app.get("/health")
def health():
    return jsonify({"status": "ok", "parsers": len(get_engine().configs),
                    "selfheal_running": get_processor().running})


@app.get("/metrics")
def metrics_endpoint():
    snap = metrics.snapshot()
    snap["dlq_pending"] = dlq_store.pending_count()
    snap["parsers_loaded"] = len(get_engine().configs)
    snap["selfheal_running"] = get_processor().running
    return jsonify(snap)


@app.get("/metrics/history")
def metrics_history():
    return jsonify(metrics.history())


@app.get("/api/schema")
def schema():
    return app.response_class(config.SCHEMA_PATH.read_text(encoding="utf-8"), mimetype="application/json")


@app.get("/api/storage")
def storage():
    """Where raw and normalized copies live, so the UI can label them."""
    return jsonify({
        "raw_store": raw_store.get_store_mode(),
        "raw_bucket": config.MINIO_BUCKET,
        "sinks": config.SINKS,
        "normalized_bucket": config.MINIO_NORMALIZED_BUCKET,
    })


# ------------------------------------------------------------------ events
def _read_jsonl_tail(folder: Path, n: int) -> list:
    files = sorted(folder.glob("*.jsonl"))
    if not files:
        return []
    with open(files[-1], encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    return [json.loads(line) for line in lines if line.strip()]


@app.get("/events/recent")
def events_recent():
    source = request.args.get("source")
    n = int(request.args.get("n", 25))
    class_uid = request.args.get("class_uid", type=int)
    events = metrics.recent_events(n=n, source_id=source, class_uid=class_uid)
    if not events and source:  # after a restart the in-memory ring is empty -> read the lake
        events = list(reversed(_read_jsonl_tail(config.NORMALIZED_DIR / source, n)))
    return jsonify(events)


@app.get("/events/stream")
def events_stream():
    return jsonify(metrics.recent_events(n=int(request.args.get("n", 15))))


def _find_event(uid: str):
    ev = metrics.get_recent_event(uid)
    if ev:
        return ev
    for folder in config.NORMALIZED_DIR.iterdir() if config.NORMALIZED_DIR.exists() else []:
        for f in sorted(folder.glob("*.jsonl"), reverse=True)[:3]:
            with open(f, encoding="utf-8") as fh:
                for line in fh:
                    if uid in line:
                        return json.loads(line)
    return None


@app.get("/events/<uid>")
def event_detail(uid):
    ev = _find_event(uid)
    if ev:
        return jsonify({"status": "normalized", "event": ev})
    row = dlq_store.get_by_event_id(uid)
    if row:
        return jsonify({"status": "dlq", "dlq": row})
    return jsonify({"error": "event not found"}), 404


@app.get("/events/<uid>/raw")
def event_raw(uid):
    ev = _find_event(uid)
    raw_ref = (ev or {}).get("metadata", {}).get("raw_ref")
    if not raw_ref:
        row = dlq_store.get_by_event_id(uid)
        raw_ref = (row or {}).get("raw_ref") or raw_store.find_ref(uid)
    if not raw_ref:
        return jsonify({"error": "no raw reference for this event"}), 404
    try:
        v = raw_store.verify(raw_ref)
    except FileNotFoundError:
        return jsonify({"error": f"raw object missing for {raw_ref}"}), 404
    raw = v.pop("raw_bytes")
    v["raw_text"] = raw.decode("utf-8", errors="replace")
    v["normalized_sha256"] = (ev or {}).get("metadata", {}).get("raw_sha256")
    v["normalized_link_ok"] = v["normalized_sha256"] in (None, v["computed_sha256"])
    return jsonify(v)


# ------------------------------------------------------------------ DLQ
@app.get("/dlq")
def dlq_recent():
    return jsonify(dlq_store.list_recent(limit=int(request.args.get("n", 50)), status=request.args.get("status")))


@app.get("/api/dlq/pending")
def api_dlq_pending():
    return jsonify(dlq_store.pending_clusters())


@app.get("/api/dlq/clusters/<cluster_id>")
def api_cluster(cluster_id):
    return jsonify(dlq_store.cluster_entries(cluster_id, limit=int(request.args.get("n", 25))))


@app.post("/api/dlq/clusters/<cluster_id>/dismiss")
def api_cluster_dismiss(cluster_id):
    return jsonify(selfheal.dismiss_cluster(cluster_id))


@app.post("/api/dlq/replay")
def api_replay():
    cid = _body().get("cluster_id")
    return jsonify(selfheal.replay_cluster(cid) if cid else selfheal.replay_all_pending())


# ------------------------------------------------------------------ self-heal
@app.get("/api/selfheal/status")
def api_selfheal_status():
    return jsonify(get_processor().status())


@app.post("/api/selfheal/settings")
def api_selfheal_settings():
    try:
        get_processor().update_settings(**_body())
    except (ValueError, TypeError) as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": True, "settings": get_processor().status()["settings"]})


@app.post("/api/selfheal/run")
def api_selfheal_run():
    cid = _body().get("cluster_id") or "*"
    created = get_processor().tick(force_cluster=cid)
    return jsonify({"created": [{"id": p["id"], "filename": p["filename"]} for p in created]})


@app.post("/api/selfheal/propose")  # legacy single-cluster endpoint
def api_selfheal_propose():
    body = _body()
    cid = body.get("cluster_id")
    if not cid and body.get("channel"):
        cid = next((c["cluster_id"] for c in dlq_store.pending_clusters() if c["channel"] == body["channel"]), None)
    if not cid:
        return jsonify({"error": "cluster_id required"}), 400
    try:
        return jsonify(selfheal.generate_proposal(cid))
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.get("/api/selfheal/proposals")
def api_proposals():
    return jsonify(dlq_store.list_proposals(status=request.args.get("status"),
                                            limit=int(request.args.get("n", 50))))


@app.get("/api/selfheal/proposals/<int:pid>")
def api_proposal(pid):
    p = dlq_store.get_proposal(pid)
    return (jsonify(p), 200) if p else (jsonify({"error": "not found"}), 404)


@app.post("/api/selfheal/proposals/<int:pid>/validate")
def api_proposal_validate(pid):
    p = dlq_store.get_proposal(pid)
    if not p:
        return jsonify({"error": "not found"}), 404
    try:
        cfg_dict = yaml.safe_load(_body().get("yaml") or p["yaml"])
    except yaml.YAMLError as e:
        return jsonify({"valid_config": False, "error": f"YAML syntax error: {e}"})
    if not isinstance(cfg_dict, dict):
        return jsonify({"valid_config": False, "error": "YAML must be a mapping"})
    entries = dlq_store.cluster_entries(p["cluster_id"], limit=config.DLQ_SAMPLES_FOR_PROPOSAL)
    samples = selfheal._load_samples(entries)
    return jsonify(selfheal.validate_candidate(cfg_dict, samples, p["channel"], entries))


@app.post("/api/selfheal/proposals/<int:pid>/promote")
@app.post("/api/selfheal/promote")  # legacy: {"proposal_id", "yaml"}
def api_proposal_promote(pid=None):
    body = _body()
    pid = pid or body.get("proposal_id")
    if not pid:
        return jsonify({"success": False, "error": "proposal_id required"}), 400
    result = selfheal.promote(int(pid), yaml_text=body.get("yaml"), approved_by=body.get("approved_by") or "console")
    return jsonify(result)


@app.post("/api/selfheal/proposals/<int:pid>/dismiss")
def api_proposal_dismiss(pid):
    return jsonify(selfheal.dismiss_proposal(pid))


# ------------------------------------------------------------------ parsers
@app.get("/api/parsers")
def api_parsers():
    return jsonify(selfheal.list_parsers())


@app.get("/api/parsers/<source_id>/yaml")
def api_parser_yaml(source_id):
    cfg = get_engine().get(source_id)
    if not cfg or not cfg.get("_path"):
        return jsonify({"error": "not found"}), 404
    return app.response_class(Path(cfg["_path"]).read_text(encoding="utf-8"), mimetype="text/plain")


@app.post("/api/parsers/reload")
def api_parsers_reload():
    """Plug-and-play onboarding: drop a YAML into src/parser/configs/ and reload -- no restart.
    The regression corpus is run first; a set of configs that breaks it is refused."""
    from src.parser.engine import ParserEngine
    from src.selfheal import regression
    candidate = ParserEngine()
    reg = regression.run(candidate)
    if not reg["passed"]:
        return jsonify({"success": False, "error": "regression corpus failed; live parsers unchanged",
                        "regression": reg}), 409
    get_engine().reload()
    return jsonify({"success": True, "parsers": [c["source_id"] for c in get_engine().configs],
                    "regression": reg})


@app.post("/api/parsers/<source_id>/rollback")
def api_parser_rollback(source_id):
    return jsonify(selfheal.rollback(source_id))


def run(port: int = None):
    app.run(host="0.0.0.0", port=port or config.HTTP_API_PORT, threaded=True, use_reloader=False)
