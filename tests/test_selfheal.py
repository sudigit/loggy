"""
Self-heal loop tests: unknown formats -> DLQ cluster -> continuous watcher
proposes a parser -> human promotes -> regression-gated, versioned, hot-reloaded,
quarantined events replayed from the raw archive -> rollback.
"""
import log_samples as S
import pytest

from src import config
from src.dlq import store as dlq_store
from src.parser.engine import ParserEngine, prepare_config
from src.pipeline import get_engine, process_event
from src.selfheal import inference, service
from src.selfheal.dlq_processor import DLQProcessor

UID = "22222222-2222-4222-8222-222222222222"
RAW = {"sha256": "b" * 64, "raw_ref": "local://t/" + UID, "size_bytes": 1}


def _send(fn, n):
    for _ in range(n):
        transport, hint, raw = fn()
        process_event(S.as_bytes(raw), channel=S.CHANNELS[transport], source_hint=hint)


def _cluster_for(fn):
    transport, _, raw = fn()
    from src.dlq import signature
    text = S.as_bytes(raw).decode()
    return signature.compute(text, S.CHANNELS[transport])[0]


@pytest.mark.parametrize("fn", S.DRIFT, ids=[f.__name__ for f in S.DRIFT])
def test_inference_parses_every_drift_family(fn):
    samples = [fn() for _ in range(15)]
    channel = S.CHANNELS[samples[0][0]]
    texts = [S.as_bytes(s[2]).decode() for s in samples]
    proposal = inference.propose(texts, channel, "candidate")
    one = ParserEngine([prepare_config(proposal["config"])])
    parsed = [one.process(t, channel, UID, "2026-09-16T10:00:00+00:00", raw_info=RAW)[0] for t in texts]
    assert len(parsed) == len(texts)
    assert proposal["mapped_fields"] >= 3


def test_watcher_thresholds_are_per_cluster():
    proc = DLQProcessor(tick_seconds=1, min_samples=5, count_threshold=10, time_threshold_sec=3600)
    cid = _cluster_for(S.sonicwall)
    dlq_store.mark_cluster(cid, "dismissed")  # start from an empty cluster regardless of test order
    _send(S.sonicwall, 3)
    cluster = next(c for c in dlq_store.pending_clusters() if c["cluster_id"] == cid)
    assert proc.evaluate(cluster)["state"] == "waiting_min"
    _send(S.sonicwall, 4)
    cluster = next(c for c in dlq_store.pending_clusters() if c["cluster_id"] == cid)
    assert proc.evaluate(cluster)["state"] == "waiting"   # >= min but < count and young
    _send(S.sonicwall, 5)
    cluster = next(c for c in dlq_store.pending_clusters() if c["cluster_id"] == cid)
    assert proc.evaluate(cluster)["state"] == "ready"


def test_end_to_end_propose_promote_replay_rollback():
    proc = DLQProcessor(tick_seconds=1, min_samples=5, count_threshold=10, time_threshold_sec=3600)
    _send(S.crowdstrike, 12)
    cid = _cluster_for(S.crowdstrike)

    created = proc.tick()
    proposal = next(p for p in created if p["cluster_id"] == cid)
    assert proposal["status"] == "open"
    assert proposal["match_rate"] == 1.0
    assert proposal["validation"]["regression"]["passed"]
    assert "json_key" in proposal["yaml"]

    # no new samples -> the next tick does not spam a new proposal for this cluster
    assert not [p for p in proc.tick() if p["cluster_id"] == cid]

    result = service.promote(proposal["id"], approved_by="pytest")
    assert result["success"], result
    assert result["replay"]["parsed"] == result["replay"]["attempted"] >= 12
    assert not dlq_store.cluster_entries(cid)                       # DLQ drained
    assert (config.PARSER_CONFIG_DIR / result["file"]).exists()

    # the new source is live without a restart
    transport, hint, raw = S.crowdstrike()
    r = process_event(S.as_bytes(raw), channel="http", source_hint=hint)
    assert r["status"] == "parsed" and r["class_uid"] == 1007

    # retire it again (no previous version -> archived)
    rb = service.rollback(r["source_id"])
    assert rb["success"]
    assert get_engine().get(r["source_id"]) is None


def test_format_drift_extends_existing_parser_with_versioning():
    proc = DLQProcessor(tick_seconds=1, min_samples=5, count_threshold=10, time_threshold_sec=3600)
    _send(S.pfsense_ipv6, 12)
    cid = _cluster_for(S.pfsense_ipv6)
    proposal = next(p for p in proc.tick(force_cluster=cid) if p["cluster_id"] == cid)
    assert proposal["awareness"]["extends_existing"] == "pfsense"
    assert proposal["validation"]["regression"]["passed"]
    result = service.promote(proposal["id"])
    assert result["success"], result
    assert result["replay"]["parsed"] >= 12
    # old pfSense IPv4 traffic is untouched (regression) and IPv6 now parses
    transport, hint, raw = S.pfsense()
    assert process_event(S.as_bytes(raw), channel="udp:5514")["status"] == "parsed"


def test_promotion_is_refused_when_regression_breaks():
    _send(S.juniper_rtflow, 6)
    cid = _cluster_for(S.juniper_rtflow)
    proposal = service.generate_proposal(cid)
    # an operator "edit" that would silently claim pfSense traffic as Base Events must be refused
    greedy = (
        "source_id: greedy\nversion: v1\npriority: 99\n"
        "fingerprint: {type: any, rules: [{type: contains, pattern: filterlog}, {type: contains, pattern: RT_FLOW}]}\n"
        "tokenize: {type: regex, pattern: '(?P<msg>.*)'}\n"
        "ocsf: {class_uid: 0, activity: Other}\n"
        "mapping: {fields: {msg: message}}\n"
    )
    result = service.promote(proposal["id"], yaml_text=greedy)
    assert not result["success"]
    assert "Regression" in result["error"]
    assert get_engine().get("greedy") is None
    # the untouched proposal itself is fine and still promotable
    assert dlq_store.get_proposal(proposal["id"])["status"] == "open"
