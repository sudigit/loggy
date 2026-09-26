"""HTTP API + console tests."""
import log_samples as S

from src.ingestion.http_api import app

client = app.test_client()


def test_console_routes_serve_the_app():
    for path in ("/", "/dashboard", "/events", "/selfheal", "/parsers"):
        resp = client.get(path)
        assert resp.status_code == 200
        assert b"ULPF Console" in resp.data


def test_metrics_endpoint():
    data = client.get("/metrics").get_json()
    for key in ("total_ingested", "events_per_second", "buffer_mode", "raw_store_mode", "dlq_pending",
                "parsers_loaded", "sinks"):
        assert key in data
    assert isinstance(client.get("/metrics/history").get_json(), list)


def test_ingest_trace_and_verify_roundtrip():
    _, _, raw = S.suricata(attack=True)
    r = client.post("/ingest", json={"channel": "http", "source_hint": "suricata", "raw": raw}).get_json()
    assert r["status"] == "parsed"
    uid = r["event_id"]

    detail = client.get(f"/events/{uid}").get_json()
    assert detail["status"] == "normalized"
    assert detail["event"]["metadata"]["raw_ref"] == r["raw_ref"]

    proof = client.get(f"/events/{uid}/raw").get_json()
    assert proof["verified"] and proof["normalized_link_ok"]
    assert proof["stored_sha256"] == proof["computed_sha256"] == detail["event"]["metadata"]["raw_sha256"]


def test_batch_ingest_and_dlq_event_lookup():
    body = {"events": [{"raw": "###UNKNOWN### x", "channel": "http"}, {"raw": S.suricata()[2], "channel": "http"}]}
    results = client.post("/ingest", json=body).get_json()["results"]
    assert [r["status"] for r in results] == ["dlq", "parsed"]
    dlq_uid = results[0]["event_id"]
    assert client.get(f"/events/{dlq_uid}").get_json()["status"] == "dlq"
    assert client.get(f"/events/{dlq_uid}/raw").get_json()["raw_text"] == "###UNKNOWN### x"


def test_ingest_requires_raw():
    assert client.post("/ingest", json={"channel": "http"}).status_code == 400


def test_selfheal_endpoints():
    status = client.get("/api/selfheal/status").get_json()
    assert {"running", "settings", "clusters", "activity"} <= set(status)
    assert isinstance(client.get("/api/selfheal/proposals").get_json(), list)
    assert isinstance(client.get("/api/dlq/pending").get_json(), list)
    bad = client.post("/api/selfheal/settings", json={"count_threshold": -1})
    assert bad.status_code == 400


def test_parser_registry_endpoints():
    parsers = client.get("/api/parsers").get_json()
    ids = {p["source_id"] for p in parsers}
    assert {"pfsense", "suricata", "squid", "cisco_asa", "fortigate", "paloalto", "generic_cef", "generic_leef"} <= ids
    assert b"source_id: pfsense" in client.get("/api/parsers/pfsense/yaml").data
    r = client.post("/api/parsers/reload").get_json()
    assert r["success"] and r["regression"]["passed"]


def test_schema_is_published():
    assert client.get("/api/schema").get_json()["title"].startswith("ULPF Normalized Event")
