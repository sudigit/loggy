"""
Realistic perimeter-device log line builders, shared by the demo generator
(tools/generate_sample_logs.py), the benchmark and the test-suite.

Each builder returns (channel, source_hint, raw) where raw is a str (syslog /
file line) or a dict (JSON body for the HTTP ingest API).

  KNOWN     -- vendors ULPF ships parsers for (normalize immediately)
  ATTACK    -- the same vendors during an incident
  DRIFT     -- formats ULPF has NO parser for yet (land in the DLQ -> self-heal)
"""
import json
import random
import time

INTERNAL = ["10.1.2.15", "10.1.2.32", "10.1.2.45", "10.1.2.88", "192.168.1.10", "192.168.1.50", "172.16.10.4"]
EXTERNAL = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14", "151.101.65.140", "185.199.108.153"]
ATTACKERS = ["198.51.100.23", "203.0.113.19", "185.220.101.5", "45.155.205.233"]
DOMAINS = ["github.com", "update.microsoft.com", "cloudflare.com", "aws.amazon.com", "internal-auth.corp.local"]
BAD_DOMAINS = ["c2-beacon.darkops.biz", "pastebin.com/raw/d9f8s7", "evil-dyn-dns.ru", "exfil-node.onion.ws"]
USERS = ["alice", "bob", "svc_backup", "carol"]

R = random.Random()


def _bsd(ts=None):
    return time.strftime("%b %d %H:%M:%S", time.gmtime(ts))


def _port():
    return R.randint(1024, 65000)


# ---------------------------------------------------------------- known vendors
def pfsense(attack=False, attacker=None):
    src = (attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL)
    dst = R.choice(INTERNAL) if attack else R.choice(EXTERNAL)
    action = "block" if attack or R.random() < 0.08 else "pass"
    if R.random() < 0.5:  # real CSV filterlog
        proto, pnum = R.choice([("tcp", 6), ("udp", 17)])
        return ("syslog", "pfsense",
                f"<134>{_bsd()} pfsense filterlog[4211]: {R.randint(5, 90)},,,1000000{R.randint(100, 999)},igb0,match,"
                f"{action},in,4,0x0,,64,{R.randint(1, 65000)},0,DF,{pnum},{proto},60,{src},{dst},{_port()},"
                f"{R.choice([22, 443, 3389, 445]) if attack else R.choice([443, 53, 80])},0")
    return ("syslog", "pfsense",
            f"{_bsd()} pfsense filterlog: rule {99 if attack else R.randint(10, 45)} {action} in on em0 "
            f"src={src} dst={dst} proto={R.choice(['tcp', 'udp'])}")


def suricata(attack=False, attacker=None):
    base = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime()),
        "flow_id": R.randint(10 ** 14, 10 ** 15), "in_iface": "eth0",
        "src_ip": (attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL), "src_port": _port(),
        "dest_ip": R.choice(INTERNAL) if attack else R.choice(EXTERNAL),
        "dest_port": R.choice([445, 443, 80, 3389]), "proto": "TCP",
    }
    if not attack and R.random() < 0.5:
        return ("http", "suricata", {**base, "event_type": "flow", "app_proto": "tls",
                                     "flow": {"bytes_toserver": R.randint(200, 9000), "bytes_toclient": R.randint(200, 90000)}})
    sig, sev, cat = R.choice([
        ("ET EXPLOIT Possible ETERNALBLUE MS17-010", 1, "Attempted Administrator Privilege Gain"),
        ("ET SCAN Nmap Scripting Engine Probe", 2, "Attempted Information Leak"),
        ("ET MALWARE Cobalt Strike Beacon Observed", 1, "A Network Trojan was detected"),
    ] if attack else [("ET POLICY TLS possible TOR SSL traffic", 3, "Misc activity"),
                      ("ET INFO Observed DNS Query to .biz TLD", 3, "Potentially Bad Traffic")])
    return ("http", "suricata", {**base, "event_type": "alert",
                                 "alert": {"action": "blocked" if attack and sev == 1 else "allowed", "gid": 1,
                                           "signature_id": R.randint(2000000, 2040000), "rev": 3,
                                           "signature": sig, "category": cat, "severity": sev}})


def squid(attack=False):
    src = R.choice(INTERNAL)
    if attack:
        return ("file", "squid", f"{time.time():.3f}    {R.randint(5, 900)} {src} TCP_MISS/200 {R.randint(20000, 900000)} "
                                 f"POST http://{R.choice(BAD_DOMAINS)}/upload - HIER_DIRECT/{R.choice(ATTACKERS)} application/octet-stream")
    status = R.choice(["TCP_MISS/200", "TCP_HIT/200", "TCP_TUNNEL/200", "TCP_DENIED/403"])
    return ("file", "squid", f"{time.time():.3f}    {R.randint(5, 900)} {src} {status} {R.randint(300, 90000)} "
                             f"GET http://{R.choice(DOMAINS)}/index.html {R.choice(USERS + ['-'])} HIER_DIRECT/{R.choice(EXTERNAL)} text/html")


def cisco_asa(attack=False, attacker=None):
    if attack or R.random() < 0.3:
        return ("syslog", "cisco_asa",
                f"<164>{time.strftime('%b %d %Y %H:%M:%S', time.gmtime())} asa-edge : %ASA-4-106023: Deny tcp src "
                f"outside:{attacker or R.choice(ATTACKERS)}/{_port()} dst inside:{R.choice(INTERNAL)}/{R.choice([22, 445, 3389])} "
                f'by access-group "outside_access_in" [0x0, 0x0]')
    cid = R.randint(100000, 999999)
    return ("syslog", "cisco_asa",
            f"<166>{time.strftime('%b %d %Y %H:%M:%S', time.gmtime())} asa-edge : %ASA-6-302013: Built outbound TCP connection "
            f"{cid} for outside:{R.choice(EXTERNAL)}/443 ({R.choice(EXTERNAL)}/443) to inside:{R.choice(INTERNAL)}/{_port()} "
            f"({R.choice(INTERNAL)}/{_port()})")


def fortigate(attack=False, attacker=None):
    action = "deny" if attack else R.choice(["accept", "accept", "close", "timeout"])
    src = (attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL)
    dst = R.choice(INTERNAL) if attack else R.choice(EXTERNAL)
    return ("syslog", "fortigate",
            f'<189>date={time.strftime("%Y-%m-%d", time.gmtime())} time={time.strftime("%H:%M:%S", time.gmtime())} '
            f'devname="FGT60F-HQ" devid="FGT60FTK2109000" logid="0000000013" type="traffic" subtype="forward" '
            f'level="{"warning" if attack else "notice"}" vd="root" srcip={src} srcport={_port()} srcintf="{"wan1" if attack else "internal"}" '
            f'dstip={dst} dstport={R.choice([3389, 445]) if attack else 443} dstintf="{"internal" if attack else "wan1"}" '
            f'proto=6 action="{action}" policyid={0 if attack else 1} service="{"RDP" if attack else "HTTPS"}" '
            f'sentbyte={R.randint(0, 9000)} rcvdbyte={R.randint(0, 90000)}')


def paloalto(attack=False, attacker=None):
    src = (attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL)
    dst = R.choice(INTERNAL) if attack else R.choice(EXTERNAL)
    ts = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
    sub, action, rule = ("drop", "deny", "block-inbound") if attack else ("end", "allow", "allow-web")
    app = "not-applicable" if attack else R.choice(["ssl", "web-browsing", "dns"])
    return ("syslog", "paloalto",
            f"<14>{_bsd()} PA-3220 1,{ts},012801000001,TRAFFIC,{sub},2561,{ts},{src},{dst},0.0.0.0,0.0.0.0,{rule},"
            f"{'' if attack else R.choice(USERS)},,{app},vsys1,{'untrust' if attack else 'trust'},{'trust' if attack else 'untrust'},"
            f"ethernet1/1,ethernet1/2,default,,{R.randint(1000, 99999)},1,{_port()},{R.choice([445, 3389]) if attack else 443},"
            f"0,0,0x0,tcp,{action},{R.randint(60, 90000)},{R.randint(60, 9000)},{R.randint(0, 90000)},{R.randint(1, 90)},"
            f"{ts},{R.randint(0, 60)},any,,{R.randint(1000, 9999)},0x0,US,US,,{R.randint(1, 40)},{R.randint(0, 40)},"
            f"{'policy-deny' if attack else 'tcp-fin'}")


def checkpoint_cef(attack=False, attacker=None):
    act = "Drop" if attack else "Accept"
    return ("syslog", "checkpoint",
            f"<134>{_bsd()} cp-gw01 CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|{act}|{act}|{5 if attack else 1}|"
            f"src={(attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL)} spt={_port()} "
            f"dst={R.choice(INTERNAL) if attack else R.choice(EXTERNAL)} dpt={R.choice([22, 3389]) if attack else 443} "
            f"proto=TCP act={act} rt={int(time.time() * 1000)} deviceInboundInterface=eth1")


def juniper_leef(attack=False, attacker=None):
    act = "deny" if attack else "permit"
    return ("syslog", "juniper",
            f"<13>{_bsd()} srx-dc LEEF:2.0|Juniper|SRX|21.4R3|RT_FLOW_SESSION_{'DENY' if attack else 'CREATE'}|^|"
            f"src={(attacker or R.choice(ATTACKERS)) if attack else R.choice(INTERNAL)}^dst={R.choice(INTERNAL) if attack else R.choice(EXTERNAL)}"
            f"^srcPort={_port()}^dstPort={R.choice([445, 22]) if attack else 443}^proto=6^action={act}^sev={7 if attack else 2}"
            f"^devTime={int(time.time() * 1000)}")


KNOWN = [pfsense, suricata, squid, cisco_asa, fortigate, paloalto, checkpoint_cef, juniper_leef]
ATTACK = [pfsense, suricata, squid, cisco_asa, fortigate, paloalto, checkpoint_cef, juniper_leef]


# ---------------------------------------------------------------- drift: formats with NO parser yet
def sonicwall():
    act = R.choice(["drop", "forward"])
    return ("syslog", "sonicwall",
            f'<134>{_bsd()} sonicwall-edge id=firewall sn=0017C5A1B2C3 time="{time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())} UTC" '
            f'fw=203.0.113.1 pri={R.choice([1, 5, 6])} c=32 m=36 msg="{"TCP packet dropped" if act == "drop" else "Connection Opened"}" '
            f'src={R.choice(ATTACKERS)}:{_port()}:X1 dst={R.choice(INTERNAL)}:{R.choice([22, 443, 3389])}:X0 '
            f'proto=tcp/{R.choice(["ssh", "https", "ms-wbt-server"])} fw_action="{act}"')


def juniper_rtflow():
    return ("syslog", "juniper_text",
            f"<14>{_bsd()} srx-branch RT_FLOW: RT_FLOW_SESSION_DENY: session denied "
            f"{R.choice(ATTACKERS)}/{_port()}->{R.choice(INTERNAL)}/{R.choice([22, 445, 3389])} 0x0 "
            f"{R.choice(['junos-ssh', 'junos-smb', 'junos-rdp'])} 6(0) default-deny untrust trust UNKNOWN UNKNOWN "
            f"N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny")


def crowdstrike():
    return ("http", "crowdstrike", {
        "vendor": "crowdstrike_falcon", "event_simpleName": "ProcessRollup2",
        "aid": R.choice(["f3b89081e7d24c1a", "9a1c7e33b0d14f02"]), "timestamp": str(int(time.time() * 1000)),
        "ComputerName": R.choice(["WS-042", "WS-017", "SRV-DB01"]), "UserName": R.choice(USERS),
        "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": R.choice(["powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi", "powershell.exe -nop -w hidden -c IEX"]),
        "RawProcessId": str(R.randint(1000, 9000)),
    })


def pfsense_ipv6():
    """Format drift in a KNOWN source: pfSense starts logging IPv6 (different CSV layout)."""
    return ("syslog", "pfsense",
            f"<134>{_bsd()} pfsense filterlog[4211]: {R.randint(5, 90)},,,1000000{R.randint(100, 999)},igb0,match,"
            f"{R.choice(['block', 'pass'])},in,6,0x00,0x00000,64,tcp,6,40,2001:db8:{R.randint(1, 9)}::{R.randint(2, 99)},"
            f"2001:db8::1,{_port()},{R.choice([22, 443])},0,S,1,,64240,,mss")


DRIFT = [sonicwall, juniper_rtflow, crowdstrike, pfsense_ipv6]


def as_bytes(raw) -> bytes:
    return json.dumps(raw).encode("utf-8") if isinstance(raw, dict) else str(raw).encode("utf-8")


CHANNELS = {"syslog": "udp:5514", "http": "http", "file": "file:squid"}
