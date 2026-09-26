"""
Parser engine tests: every shipped vendor normalizes to the expected OCSF
shape, the generic layers (envelope, tokenizers, timestamps) behave, and the
regression corpus -- the same gate used before any promotion -- passes.
"""
import json

import pytest

from src.parser import envelope, tokenizers
from src.parser.engine import ParseError, ParserEngine
from src.schema import ocsf
from src.selfheal import regression

engine = ParserEngine()
UID = "11111111-1111-4111-8111-111111111111"
RAW = {"sha256": "a" * 64, "raw_ref": "local://test/" + UID, "size_bytes": 1}
NOW = "2026-09-16T10:22:05+00:00"


def run(line, channel="udp:5514"):
    return engine.process(line, channel, UID, NOW, raw_info=RAW)


def test_regression_corpus_passes():
    result = regression.run(engine)
    assert result["passed"], result["failures"]
    assert result["total"] >= 20


SURICATA_ALERT = json.dumps({
    "timestamp": "2026-09-16T10:22:04.123456+0000", "event_type": "alert", "src_ip": "203.0.113.19",
    "src_port": 51820, "dest_ip": "10.1.2.15", "dest_port": 445, "proto": "TCP",
    "alert": {"action": "blocked", "signature_id": 2024217, "signature": "ET EXPLOIT ETERNALBLUE",
              "category": "Attempted Administrator Privilege Gain", "severity": 1}})

GOLDEN = [
    # (channel, raw, source_id, class_uid, activity, expected dotted fields)
    ("udp:5514", "Sep 16 10:22:01 pfsense filterlog: rule 12 block in on em0 src=10.1.2.3 dst=192.168.1.5 proto=tcp",
     "pfsense", 4001, "Refuse", {"src_endpoint.ip": "10.1.2.3", "dst_endpoint.ip": "192.168.1.5",
                                 "disposition": "Blocked", "action": "Denied", "connection_info.protocol_num": 6}),
    ("udp:5514", "<134>Sep 16 10:22:01 pfsense filterlog[1234]: 5,,,1000000103,igb1,match,pass,in,4,0x0,,64,0,0,DF,"
                 "17,udp,60,10.1.2.3,8.8.8.8,53001,53,0",
     "pfsense", 4001, "Traffic", {"dst_endpoint.port": 53, "dst_endpoint.svc_name": "dns", "disposition": "Allowed",
                                  "connection_info.direction": "Outbound", "device.hostname": "pfsense"}),
    ("file:squid", "1758013327.456    195 10.1.2.32 TCP_DENIED/403 4120 CONNECT evil.ru:443 alice HIER_NONE/- text/html",
     "squid", 4002, "Connect", {"http_response.code": 403, "actor.user.name": "alice", "disposition": "Blocked"}),
    ("http", SURICATA_ALERT,
     "suricata", 2004, "Create", {"finding_info.title": "ET EXPLOIT ETERNALBLUE", "severity": "High",
                                  "disposition": "Blocked", "time_dt": "2026-09-16T10:22:04.123456+00:00"}),
    ("udp:5514", '<166>Sep 16 2026 10:22:01 asa-fw : %ASA-4-106023: Deny tcp src outside:203.0.113.19/51820 '
                 'dst inside:10.1.2.15/443 by access-group "outside_access_in"',
     "cisco_asa", 4001, "Refuse", {"src_endpoint.port": 51820, "firewall_rule.name": "outside_access_in",
                                   "severity": "Medium", "time_dt": "2026-09-16T10:22:01+00:00"}),
    ("udp:5514", 'date=2026-09-16 time=10:22:01 devname="FGT60D" type="traffic" level="notice" srcip=10.1.2.3 '
                 'srcport=51820 dstip=8.8.8.8 dstport=443 proto=6 action="accept" sentbyte=1234',
     "fortigate", 4001, "Traffic", {"connection_info.protocol_name": "tcp", "traffic.bytes_out": 1234,
                                    "device.hostname": "FGT60D", "time_dt": "2026-09-16T10:22:01+00:00"}),
    ("udp:5514", "<14>Sep 16 10:22:02 PA-VM 1,2026/09/16 10:22:02,012801000001,TRAFFIC,drop,2561,2026/09/16 10:22:02,"
                 "185.220.101.5,10.1.2.15,0.0.0.0,0.0.0.0,block-inbound,,,not-applicable,vsys1,untrust,trust,"
                 "ethernet1/1,,default,,0,1,4444,445,0,0,0x0,tcp,deny,60,60,0,1,2026/09/16 10:22:02,0,any,,7102,"
                 "0x0,DE,US,,1,0,policy-deny",
     "paloalto", 4001, "Refuse", {"src_endpoint.zone": "untrust", "firewall_rule.name": "block-inbound",
                                  "disposition": "Blocked", "dst_endpoint.port": 445}),
    ("udp:5514", "CEF:0|Check Point|VPN-1 & FireWall-1|R81|Drop|Drop|5|src=203.0.113.19 spt=51820 dst=10.1.2.15 "
                 "dpt=22 proto=TCP act=Drop rt=1758017521000",
     "generic_cef", 4001, "Refuse", {"metadata.product.vendor_name": "Check Point", "disposition": "Dropped",
                                     "severity": "Medium"}),
    ("udp:5514", "LEEF:2.0|Juniper|SRX|21.2|RT_FLOW_SESSION_DENY|^|src=10.1.2.3^dst=8.8.8.8^srcPort=51234^"
                 "dstPort=53^proto=17^action=deny^sev=5",
     "generic_leef", 4001, "Refuse", {"metadata.product.vendor_name": "Juniper",
                                      "connection_info.protocol_name": "udp"}),
]


def _get(d, path):
    for p in path.split("."):
        d = d[p]
    return d


@pytest.mark.parametrize("channel,raw,source_id,class_uid,activity,fields", GOLDEN,
                         ids=[f"{g[2]}-{i}" for i, g in enumerate(GOLDEN)])
def test_golden_normalization(channel, raw, source_id, class_uid, activity, fields):
    ev, cfg = run(raw, channel)
    assert cfg["source_id"] == source_id
    assert ev["class_uid"] == class_uid and ev["activity_name"] == activity
    assert ev["type_uid"] == class_uid * 100 + ev["activity_id"]
    for path, expected in fields.items():
        assert _get(ev, path) == expected, path
    # traceability + contract on every record
    assert ev["metadata"]["uid"] == UID
    assert ev["metadata"]["raw_sha256"] == RAW["sha256"] and ev["metadata"]["raw_ref"] == RAW["raw_ref"]
    assert isinstance(ev["time"], int)
    assert ocsf.validate(ev) == []


def test_unknown_format_goes_to_dlq():
    with pytest.raises(ParseError) as e:
        run("###UNKNOWN_DEVICE### code=1 weird_field~~value blah")
    assert e.value.reason == "no_parser_match"


def test_format_drift_is_attributed_to_the_parser():
    with pytest.raises(ParseError) as e:
        run("Sep 16 10:22:01 pfsense filterlog: SOMETHING_NEW code=1")
    assert e.value.reason == "tokenize_failed" and e.value.parser_id == "pfsense"


def test_unmapped_fields_are_preserved():
    ev, _ = run('date=2026-09-16 time=10:22:01 devname="FGT60D" type="traffic" srcip=10.1.2.3 dstip=8.8.8.8 '
                'action="accept" vd="root" customfield="keep-me"')
    assert ev["unmapped"]["customfield"] == "keep-me"
    assert ev["unmapped"]["vd"] == "root"


def test_signature_beats_channel():
    """A known device on an unexpected port/channel is still recognized."""
    _, cfg = run("%ASA-4-106023: Deny udp src outside:198.51.100.23/5353 dst inside:10.1.2.32/161 by access-group acl1",
                 channel="tcp:9999")
    assert cfg["source_id"] == "cisco_asa"


def test_schema_violation_is_detected():
    ev, _ = run("Sep 16 10:22:01 pfsense filterlog: rule 12 block in on em0 src=10.1.2.3 dst=192.168.1.5 proto=tcp")
    ev["src_endpoint"]["ip"] = "not-an-ip"
    assert any("src_endpoint.ip" in e for e in ocsf.validate(ev))


# ---------------------------------------------------------------- generic layers
def test_envelope_rfc5424():
    env, payload = envelope.parse('<165>1 2026-09-16T10:22:01.003Z fw01 app 123 ID47 [ex@32473 iut="3"] hello world')
    assert env["format"] == "rfc5424" and env["hostname"] == "fw01" and env["syslog_severity"] == 5
    assert payload == "hello world"


def test_envelope_rfc3164_and_none():
    env, payload = envelope.parse("<134>Sep 16 10:22:01 host01 sshd[42]: Failed password")
    assert env["app_name"] == "sshd" and env["procid"] == "42" and payload == "Failed password"
    assert envelope.parse('{"a": 1}') == (None, '{"a": 1}')


def test_cef_escaping():
    t = tokenizers.tokenize_cef(r"CEF:0|Ven\|dor|Prod|1|100|Name|5|msg=a\=b c spt=1 cs1=x y", {})
    assert t["device_vendor"] == "Ven|dor" and t["msg"] == "a=b c" and t["cs1"] == "x y"


def test_xml_tokenizer():
    t = tokenizers.tokenize_xml('<Event><System><EventID>4625</EventID></System><EventData>'
                                '<Data Name="IpAddress">10.1.2.3</Data></EventData></Event>', {})
    assert t["Event.System.EventID"] == "4625" and t["IpAddress"] == "10.1.2.3"


def test_csv_tokenizer():
    spec = tokenizers.compile_spec({"type": "csv", "fields": ["a", "_", "c"]})
    assert tokenizers.tokenize('1,"x,y",3', spec) == {"a": "1", "c": "3"}
