"""
End-to-end pipeline tests: lossless raw preservation, traceability between
the normalized record and the archived original, and DLQ quarantine.
"""
import json

import log_samples as S

from src import config
from src.core import ids, metrics, raw_store
from src.dlq import store as dlq_store
from src.pipeline import process_event


def _normalized_record(source_id, uid):
    for f in (config.NORMALIZED_DIR / source_id).glob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if uid in line:
                return json.loads(line)
    return None


def test_raw_is_preserved_byte_for_byte_and_linked():
    raw = b"<134>Sep 16 10:22:01 pfsense filterlog: rule 12 block in on em0 src=10.1.2.3 dst=192.168.1.5 proto=tcp"
    result = process_event(raw, channel="udp:5514", source_hint="pfsense")
    assert result["status"] == "parsed"

    # (a) lossless: archived bytes are identical, hash re-verifies
    v = raw_store.verify(result["raw_ref"])
    assert v["raw_bytes"] == raw and v["verified"]

    # (d) traceability: the normalized record points at exactly that original
    rec = _normalized_record("pfsense", result["event_id"])
    assert rec["metadata"]["raw_ref"] == result["raw_ref"]
    assert rec["metadata"]["raw_sha256"] == ids.sha256_hex(raw)
    assert rec["metadata"]["ingest_channel"] == "udp:5514"
    assert metrics.get_recent_event(result["event_id"]) is not None


def test_non_utf8_bytes_are_still_preserved():
    raw = b"%ASA-4-106023: Deny tcp src outside:203.0.113.19/1 dst inside:10.1.2.15/443 by access-group x \xff\xfe"
    result = process_event(raw, channel="udp:5514")
    assert raw_store.read_ref(result["raw_ref"]) == raw


def test_unknown_event_is_quarantined_with_trace():
    raw = b"###UNKNOWN_DEVICE### code=1 weird_field~~value blah"
    result = process_event(raw, channel="udp:5514")
    assert result["status"] == "dlq" and result["reason"] == "no_parser_match"
    row = dlq_store.get_by_event_id(result["event_id"])
    assert row["status"] == "pending" and row["raw_ref"] == result["raw_ref"]
    assert row["raw_sha256"] == ids.sha256_hex(raw) and row["cluster_id"]


def test_every_known_vendor_sample_normalizes():
    for fn in S.KNOWN:
        for attack in (False, True):
            transport, hint, raw = fn(attack=attack)
            r = process_event(S.as_bytes(raw), channel=S.CHANNELS[transport], source_hint=hint)
            assert r["status"] == "parsed", (fn.__name__, attack, r, raw)


def test_drift_samples_cluster_by_shape():
    for fn in S.DRIFT:
        for _ in range(3):
            transport, hint, raw = fn()
            r = process_event(S.as_bytes(raw), channel=S.CHANNELS[transport], source_hint=hint)
            assert r["status"] == "dlq", (fn.__name__, r)
    labels = {c["cluster_id"] for c in dlq_store.pending_clusters()}
    assert len(labels) >= len(S.DRIFT)
