"""
This is the regression corpus referenced in the architecture doc: any
proposed parser patch must pass all of these before src/selfheal/promote.py
will let it go live. Add a fixture + assertion here for every source you
onboard, so a "fix" for one format variant can never silently break another.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.parser.engine import ParserEngine

FIXTURES = Path(__file__).parent / "fixtures"
engine = ParserEngine()


def test_pfsense_parses():
    text = (FIXTURES / "pfsense_good.txt").read_text().strip()
    cfg = engine.select(text, channel="udp:5514")
    assert cfg is not None, "pfSense fingerprint should match"
    tokens = engine.tokenize(text, cfg)
    ocsf = engine.normalize(tokens, cfg, event_id="test-1", ingest_time_iso="2026-01-01T00:00:00+00:00")
    assert ocsf["src_endpoint"]["ip"] == "10.1.2.3"
    assert ocsf["dst_endpoint"]["ip"] == "192.168.1.5"
    assert ocsf["disposition"] == "Blocked"


def test_suricata_parses():
    text = (FIXTURES / "suricata_good.json").read_text().strip()
    cfg = engine.select(text, channel="http")
    assert cfg is not None, "Suricata fingerprint should match"
    tokens = engine.tokenize(text, cfg)
    ocsf = engine.normalize(tokens, cfg, event_id="test-2", ingest_time_iso="2026-01-01T00:00:00+00:00")
    assert ocsf["src_endpoint"]["ip"] == "10.1.2.3"
    assert ocsf["dst_endpoint"]["ip"] == "192.168.1.5"


def test_squid_parses():
    text = (FIXTURES / "squid_good.txt").read_text().strip()
    cfg = engine.select(text, channel="file:squid")
    assert cfg is not None, "Squid fingerprint should match"
    tokens = engine.tokenize(text, cfg)
    ocsf = engine.normalize(tokens, cfg, event_id="test-3", ingest_time_iso="2026-01-01T00:00:00+00:00")
    assert ocsf["src_endpoint"]["ip"] == "10.1.2.3"
    assert ocsf["http"]["method"] == "GET"


def test_unknown_format_has_no_matching_parser():
    text = "###UNKNOWN_DEVICE### code=1 weird_field~~value blah"
    cfg = engine.select(text, channel="udp:5514")
    assert cfg is None, "garbage input must not accidentally match a real parser"
