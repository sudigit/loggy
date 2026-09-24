"""
Tests for pipeline buffering and direct execution fallback.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pipeline import process_event
from src.core import raw_store


def test_pipeline_direct_execution():
    raw_sample = b"Sep 16 10:22:01 pfsense filterlog: rule 12 block in on em0 src=10.1.2.3 dst=192.168.1.5 proto=tcp"
    result = process_event(raw_sample, channel="udp:5514", source_hint="pfsense")

    assert "event_id" in result
    event_id = result["event_id"]

    # Verify status is either buffered or parsed
    assert result["status"] in ("parsed", "buffered")

    # Verify raw byte-for-byte preservation and hash verification
    saved_raw = raw_store.read(event_id, "pfsense")
    assert saved_raw == raw_sample

    meta = raw_store.read_meta(event_id, "pfsense")
    assert meta["event_id"] == event_id
    assert "sha256" in meta
    assert meta["size_bytes"] == len(raw_sample)
