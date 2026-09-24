"""
Tests for HTTP API endpoints including dashboard, selfheal studio, and metrics.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingestion.http_api import app


def test_dashboard_view():
    client = app.test_client()
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Universal Log Pre-processing Framework" in resp.data


def test_selfheal_view():
    client = app.test_client()
    resp = client.get("/selfheal")
    assert resp.status_code == 200
    assert b"DLQ & AI Self-Healing Studio" in resp.data


def test_metrics_endpoint():
    client = app.test_client()
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_ingested" in data
    assert "events_per_second" in data
    assert "buffer_mode" in data
    assert "raw_store_mode" in data


def test_events_stream_endpoint():
    client = app.test_client()
    resp = client.get("/events/stream")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_dlq_pending_api():
    client = app.test_client()
    resp = client.get("/api/dlq/pending")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)
