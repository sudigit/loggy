"""
Self-heal service: DLQ cluster -> proposed parser -> validation -> human-gated
promotion -> DLQ replay from the raw archive. Also parser versioning/rollback.

Nothing here ever changes live parsing without an explicit promote() call.
"""
import copy
import logging
import re
import shutil
import time
from collections import Counter
from datetime import datetime, timezone

import requests
import yaml

from src import config
from src.core import raw_store
from src.dlq import store as dlq_store
from src.parser.engine import ParseError, ParserEngine, prepare_config
from src.selfheal import config_registry, inference, regression

logger = logging.getLogger("ulpf.selfheal")

MIN_PROMOTE_MATCH_RATE = 0.5


def _engine():
    from src.pipeline import get_engine
    return get_engine()


# ------------------------------------------------------------------ samples
def _load_samples(entries: list) -> list:
    """Full original events from the raw archive (DLQ snippets may be truncated)."""
    samples = []
    for e in entries:
        text = None
        if e.get("raw_ref"):
            try:
                text = raw_store.read_ref(e["raw_ref"]).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                text = None
        samples.append(text if text is not None else e["raw_snippet"])
    return samples


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")[:40]


def _suggest_source_id(entries: list, samples: list) -> str:
    from src.parser import envelope as env_mod
    live = {c["source_id"] for c in _engine().configs}
    name = None
    env, payload = env_mod.parse(samples[0])
    m = re.search(r'"(?:vendor|product|device_vendor)"\s*:\s*"([^"]+)"', payload)
    if m:
        name = m.group(1)
    elif "CEF:" in payload or "LEEF:" in payload:
        parts = payload[payload.find("EF:") + 3:].split("|")
        name = "_".join(parts[1:3])
    elif env and env.get("app_name"):
        name = env["app_name"]
    elif env and env.get("hostname"):
        name = env["hostname"]
    base = _slug(name) if name else f"source_{entries[0]['cluster_id'][:6]}"
    base = re.sub(r"_v\d+$", "", base) or "source"
    candidate, n = base, 2
    while candidate in live:
        candidate, n = f"{base}_{n}", n + 1
    return candidate


# ------------------------------------------------------------------ validation
def validate_candidate(cfg_dict: dict, samples: list, channel: str, entries: list = None) -> dict:
    """Scores a candidate config against the cluster samples AND the regression corpus."""
    try:
        prepared = prepare_config(copy.deepcopy(cfg_dict), path="<proposal>")
    except Exception as e:  # noqa: BLE001
        return {"valid_config": False, "error": f"Invalid parser config: {e}", "match_rate": 0.0,
                "parsed": 0, "total": len(samples), "regression": {"passed": False, "failures": [str(e)]}}
    one = ParserEngine([prepared])
    parsed, errors, preview = 0, Counter(), None
    now = datetime.now(timezone.utc).isoformat()
    for i, s in enumerate(samples):
        e = entries[i] if entries and i < len(entries) else {}
        raw_info = {"sha256": e.get("raw_sha256") or "0" * 64,
                    "raw_ref": e.get("raw_ref") or "local://proposal/00000000-0000-4000-8000-000000000000",
                    "size_bytes": len(s)}
        uid = e.get("event_id") or "00000000-0000-4000-8000-000000000000"
        try:
            ev, _ = one.process(s, channel, uid, e.get("ingest_time") or now, raw_info=raw_info)
            parsed += 1
            preview = preview or ev
        except ParseError as err:
            errors[f"{err.reason}: {err.detail}"[:200]] += 1
    reg = regression.run_with([prepared])
    total = len(samples)
    return {
        "valid_config": True,
        "match_rate": round(parsed / total, 3) if total else 0.0,
        "parsed": parsed,
        "total": total,
        "errors": [f"{n}x {msg}" for msg, n in errors.most_common(5)],
        "preview": preview,
        "preview_raw": samples[0] if samples else None,
        "regression": reg,
    }


# ------------------------------------------------------------------ LLM (optional, local only)
_ollama_cache = {"t": 0.0, "model": None}


def _ollama_model():
    if not config.OLLAMA_ENABLED:
        return None
    if time.time() - _ollama_cache["t"] < 60:
        return _ollama_cache["model"]
    model = None
    try:
        resp = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=1.5)
        if resp.ok:
            names = [m["name"] for m in resp.json().get("models", [])]
            preferred = [n for n in names if n.split(":")[0] == config.OLLAMA_MODEL.split(":")[0]]
            coder = [n for n in names if "code" in n]
            model = (preferred or coder or names or [None])[0]
    except requests.RequestException:
        model = None
    _ollama_cache.update(t=time.time(), model=model)
    return model


LLM_PROMPT = """You write parser configs for a log normalization engine that outputs OCSF 1.3.
Improve the DRAFT config below so it parses ALL samples and maps as many security-relevant
fields as possible to OCSF paths (src_endpoint.ip, src_endpoint.port, dst_endpoint.ip,
dst_endpoint.port, connection_info.protocol_name, disposition, actor.user.name,
http_request.url.url_string, process.cmd_line, finding_info.title, severity_id, message ...).
Keep the same top-level keys and tokenizer types (regex|json|kv|csv|cef|leef|xml).
Regex patterns must use Python named groups. Return ONLY YAML, no prose, no code fences.

DRAFT:
{draft}

SAMPLES:
{samples}
"""


def _call_ollama(draft_yaml: str, samples: list):
    model = _ollama_model()
    if not model:
        return None, None
    prompt = LLM_PROMPT.format(draft=draft_yaml, samples="\n".join(s[:600] for s in samples[:6]))
    try:
        resp = requests.post(f"{config.OLLAMA_URL}/api/generate",
                             json={"model": model, "prompt": prompt, "stream": False,
                                   "options": {"temperature": 0.1}},
                             timeout=config.OLLAMA_TIMEOUT)
        resp.raise_for_status()
        text = resp.json().get("response", "")
        text = re.sub(r"^```(?:ya?ml)?\s*|```\s*$", "", text.strip(), flags=re.MULTILINE)
        data = yaml.safe_load(text)
        return (data if isinstance(data, dict) else None), f"Local LLM ({model})"
    except Exception as e:  # noqa: BLE001
        logger.info(f"[selfheal] Ollama proposal failed: {e}")
        return None, None


# ------------------------------------------------------------------ proposal generation
def _read_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _bump(version: str) -> str:
    m = re.fullmatch(r"v(\d+)", str(version))
    return f"v{int(m.group(1)) + 1}" if m else f"{version}.1"


def _vnum(version) -> int:
    m = re.fullmatch(r"v(\d+)", str(version or ""))
    return int(m.group(1)) if m else 0


def _drift_candidates(parent: dict, inferred: dict) -> list:
    """For format drift in an existing parser: (a) extend its regex with the new
    variant, or (b) a sibling 'variant' parser that inherits its product identity."""
    out = []
    parent_yaml = _read_yaml(parent["_path"])
    tk_p, tk_i = parent_yaml["tokenize"], inferred["tokenize"]
    if tk_p.get("type") == "regex" and tk_i.get("type") == "regex":
        merged = copy.deepcopy(parent_yaml)
        pats = merged["tokenize"].pop("patterns", None) or [merged["tokenize"].pop("pattern")]
        merged["tokenize"]["patterns"] = pats + [tk_i["pattern"]]
        fields = merged.setdefault("mapping", {}).setdefault("fields", {})
        for k, v in inferred["mapping"]["fields"].items():
            fields.setdefault(k, v)
        merged["version"] = _bump(parent_yaml.get("version", "v1"))
        out.append(("extends", merged))
    variant = copy.deepcopy(inferred)
    variant["source_id"] = f"{parent['source_id']}_variant"
    variant["product"] = dict(parent_yaml.get("product") or {})
    variant["log_name"] = parent_yaml.get("log_name", parent["source_id"])
    variant["channels"] = parent_yaml.get("channels") or ([parent_yaml["channel"]] if parent_yaml.get("channel") else variant["channels"])
    variant["priority"] = int(parent_yaml.get("priority", 50)) - 1
    variant["fingerprint"] = {"type": "all", "rules": [parent_yaml["fingerprint"], inferred["fingerprint"]]}
    out.append(("variant", variant))
    return out


def _score(v: dict, mapped: int):
    return (v.get("valid_config", False), v.get("regression", {}).get("passed", False),
            v.get("match_rate", 0), mapped)


def generate_proposal(cluster_id: str) -> dict:
    entries = dlq_store.cluster_entries(cluster_id, limit=config.DLQ_SAMPLES_FOR_PROPOSAL)
    if not entries:
        raise ValueError(f"no pending DLQ entries for cluster {cluster_id}")
    pending_total = len(dlq_store.cluster_entries(cluster_id, limit=1_000_000))
    samples = _load_samples(entries)
    channel = entries[0]["channel"]
    engine = _engine()
    parser_ids = [e["parser_id"] for e in entries
                  if e.get("parser_id") and e.get("reason") in ("tokenize_failed", "schema_violation", "normalize_error")]
    drift_parent_id = Counter(parser_ids).most_common(1)[0][0] if parser_ids else None
    drift_parent = engine.get(drift_parent_id) if drift_parent_id else None

    source_id = _suggest_source_id(entries, samples) if not drift_parent else f"{drift_parent_id}_variant"
    inferred = inference.propose(samples, channel, source_id)
    candidates = []
    if drift_parent and drift_parent.get("_path"):
        for kind, cfg_dict in _drift_candidates(drift_parent, inferred["config"]):
            candidates.append((f"Structure inference ({kind} '{drift_parent_id}')", cfg_dict, inferred["mapped_fields"]))
    candidates.append(("Structure inference (air-gapped, deterministic)", inferred["config"], inferred["mapped_fields"]))

    llm_cfg, llm_tag = _call_ollama(inference.to_yaml(inferred["config"]), samples)
    if llm_cfg:
        mapped = len((llm_cfg.get("mapping") or {}).get("fields") or {})
        candidates.append((llm_tag, llm_cfg, mapped))

    scored = []
    for tag, cfg_dict, mapped in candidates:
        v = validate_candidate(cfg_dict, samples, channel, entries)
        scored.append((_score(v, mapped), tag, cfg_dict, v))
    scored.sort(key=lambda x: x[0], reverse=True)
    _, generator, best_cfg, validation = scored[0]
    alternatives = [{"generator": t, "match_rate": v.get("match_rate"),
                     "regression_passed": v.get("regression", {}).get("passed")} for _, t, _, v in scored[1:]]

    label = entries[0].get("cluster_label") or cluster_id
    header = (f"# Proposed by ULPF self-heal -- NOT LIVE until a human promotes it.\n"
              f"# cluster: {cluster_id} ({label}) on channel {channel}\n"
              f"# generator: {generator}\n"
              f"# validation: parses {validation['parsed']}/{validation['total']} samples; "
              f"regression {'PASSED' if validation['regression']['passed'] else 'FAILED'}")
    yaml_text = inference.to_yaml(best_cfg, header)
    awareness = config_registry.awareness(best_cfg, samples, [e.get("parser_id") for e in entries], engine)
    notes = list(inferred["notes"])
    if inferred["mapped_fields"] < 2 and not drift_parent:
        notes.append("Few security fields recognized -- this cluster may be noise; consider dismissing it.")
    awareness["notes"] = notes
    awareness["alternatives"] = alternatives

    filename = f"{best_cfg['source_id']}_proposed.yaml"
    (config.PARSER_PROPOSED_DIR / filename).write_text(yaml_text, encoding="utf-8")
    preview = validation.pop("preview", None)
    validation["preview"] = preview
    proposal_id = dlq_store.add_proposal({
        "cluster_id": cluster_id, "channel": channel, "cluster_label": label, "filename": filename,
        "yaml": yaml_text, "generator": generator, "sample_count": len(samples),
        "pending_at_creation": pending_total, "match_rate": validation["match_rate"],
        "validation": validation, "awareness": awareness,
    })
    return dlq_store.get_proposal(proposal_id)


# ------------------------------------------------------------------ promotion / replay
def replay_cluster(cluster_id: str) -> dict:
    from src.pipeline import replay_dlq_entry
    entries = dlq_store.cluster_entries(cluster_id, limit=1_000_000)
    ok_ids, still_failing = [], 0
    for e in entries:
        if replay_dlq_entry(e)["status"] == "parsed":
            ok_ids.append(e["id"])
        else:
            still_failing += 1
    dlq_store.mark_status(ok_ids, "replayed")
    return {"attempted": len(entries), "parsed": len(ok_ids), "still_failing": still_failing}


def replay_all_pending() -> dict:
    totals = {"attempted": 0, "parsed": 0, "still_failing": 0}
    for c in dlq_store.pending_clusters():
        r = replay_cluster(c["cluster_id"])
        for k in totals:
            totals[k] += r[k]
    return totals


def _live_file_for(source_id: str):
    for c in _engine().configs:
        if c["source_id"] == source_id and c.get("_path"):
            return c
    return None


def promote(proposal_id: int, yaml_text: str = None, approved_by: str = "operator") -> dict:
    p = dlq_store.get_proposal(proposal_id)
    if not p:
        return {"success": False, "error": f"proposal {proposal_id} not found"}
    if p["status"] not in ("open",):
        return {"success": False, "error": f"proposal is {p['status']}, not open"}
    text = yaml_text or p["yaml"]
    try:
        cfg_dict = yaml.safe_load(text)
        if not isinstance(cfg_dict, dict) or "source_id" not in cfg_dict:
            return {"success": False, "error": "YAML must be a mapping with a 'source_id'."}
    except yaml.YAMLError as e:
        return {"success": False, "error": f"YAML syntax error: {e}"}

    entries = dlq_store.cluster_entries(p["cluster_id"], limit=config.DLQ_SAMPLES_FOR_PROPOSAL)
    samples = _load_samples(entries)
    validation = validate_candidate(cfg_dict, samples, p["channel"], entries) if samples else \
        {"valid_config": True, "match_rate": 1.0, "regression": regression.run_with([prepare_config(copy.deepcopy(cfg_dict))])}
    if not validation.get("valid_config"):
        return {"success": False, "error": validation.get("error"), "validation": validation}
    if not validation["regression"]["passed"]:
        return {"success": False, "validation": validation,
                "error": "Regression corpus FAILED -- promotion rejected so existing sources keep working:\n"
                         + "\n".join(validation["regression"]["failures"][:8])}
    if samples and validation["match_rate"] < MIN_PROMOTE_MATCH_RATE:
        return {"success": False, "validation": validation,
                "error": f"Proposal parses only {validation['parsed']}/{validation['total']} cluster samples "
                         f"(need >= {int(MIN_PROMOTE_MATCH_RATE * 100)}%). Errors: {validation.get('errors')}"}

    # version + archive the live file for this source (rollback point)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    live = _live_file_for(cfg_dict["source_id"])
    if live:
        live_path = config.PARSER_CONFIG_DIR / live["_path"].replace("\\", "/").split("/")[-1]
        old_version = str(live.get("version", "v1"))
        if _vnum(cfg_dict.get("version")) <= _vnum(old_version):
            cfg_dict["version"] = _bump(old_version)
        shutil.copy(live_path, config.PARSER_ARCHIVE_DIR / f"{live_path.stem}.{old_version}.{ts}.yaml")
        dest = live_path
    else:
        dest = config.PARSER_CONFIG_DIR / f"{cfg_dict['source_id']}_v1.yaml"

    header = (f"# Promoted by ULPF self-heal {ts} from proposal #{proposal_id} "
              f"(cluster {p['cluster_id']}), approved by {approved_by}.\n"
              f"# Validation: {validation.get('parsed', '?')}/{validation.get('total', '?')} samples, "
              f"regression {validation['regression']['total']} corpus events passed.")
    dest.write_text(inference.to_yaml(cfg_dict, header), encoding="utf-8")

    _engine().reload()
    replay = replay_cluster(p["cluster_id"])
    dlq_store.update_proposal(proposal_id, status="promoted", yaml=text,
                              note=f"live as {dest.name} {cfg_dict.get('version')}; replayed {replay['parsed']}/{replay['attempted']}")
    return {
        "success": True,
        "message": (f"Promoted {cfg_dict['source_id']} {cfg_dict.get('version')} -> {dest.name} "
                    f"(regression {validation['regression']['total']}/{validation['regression']['total']} passed). "
                    f"Replayed {replay['parsed']}/{replay['attempted']} quarantined events from the raw archive."),
        "file": dest.name,
        "version": cfg_dict.get("version"),
        "replay": replay,
        "validation": {k: v for k, v in validation.items() if k != "preview"},
    }


def dismiss_proposal(proposal_id: int) -> dict:
    dlq_store.update_proposal(proposal_id, status="dismissed")
    return {"success": True}


def dismiss_cluster(cluster_id: str) -> dict:
    n = dlq_store.mark_cluster(cluster_id, "dismissed")
    latest = dlq_store.latest_proposal(cluster_id)
    if latest and latest["status"] == "open":
        dlq_store.update_proposal(latest["id"], status="dismissed")
    return {"success": True, "dismissed_events": n}


# ------------------------------------------------------------------ parser registry / rollback
def _archives_for(stem: str) -> list:
    return sorted(config.PARSER_ARCHIVE_DIR.glob(f"{stem}.*.yaml"), key=lambda p: p.stat().st_mtime,
                  reverse=True)


def list_parsers() -> list:
    from src.core import metrics
    per_source = metrics.snapshot()["per_source"]
    out = []
    for c in _engine().configs:
        stem = c["_path"].replace("\\", "/").split("/")[-1].rsplit(".", 1)[0] if c.get("_path") else None
        out.append({
            "source_id": c["source_id"],
            "version": str(c.get("version")),
            "product": c.get("product"),
            "file": f"{stem}.yaml" if stem else None,
            "priority": c.get("priority"),
            "channels": sorted(c["_channels"]),
            "fingerprint": c["fingerprint"].get("type"),
            "tokenizer": c["tokenize"].get("type"),
            "class_uid": (c.get("ocsf") or {}).get("class_uid"),
            "mapped_fields": len((c.get("mapping") or {}).get("fields") or {}),
            "parsed": per_source.get(c["source_id"], {}).get("parsed", 0),
            "dlq": per_source.get(c["source_id"], {}).get("dlq", 0),
            "history": [p.name for p in _archives_for(stem)] if stem else [],
        })
    return out


def rollback(source_id: str) -> dict:
    live = _live_file_for(source_id)
    if not live:
        return {"success": False, "error": f"no live parser '{source_id}'"}
    live_path = config.PARSER_CONFIG_DIR / live["_path"].replace("\\", "/").split("/")[-1]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archives = [a for a in _archives_for(live_path.stem) if ".rolledback." not in a.name]
    shutil.move(str(live_path), config.PARSER_ARCHIVE_DIR / f"{live_path.stem}.rolledback.{ts}.yaml")
    if archives:
        shutil.move(str(archives[0]), live_path)
        msg = f"Rolled back {source_id} to {archives[0].name}."
    else:
        msg = f"{source_id} had no previous version -- parser retired (archived)."
    _engine().reload()
    return {"success": True, "message": msg}
