"""
Offline enrichment stage -- adds derived, ML-friendly features to every
normalized event. No lookups leave the box (air-gap safe).

  src/dst_endpoint.zone     internal | external   (configurable CIDRs)
  dst_endpoint.svc_name     well-known service for the destination port
  connection_info.direction Inbound | Outbound | Lateral
  enrichments.*             flat numeric/boolean features for ML pipelines
"""
import ipaddress
from functools import lru_cache

from src import config
from src.schema import ocsf

WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    69: "tftp", 80: "http", 88: "kerberos", 110: "pop3", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch",
}
RISKY_PORTS = {21, 23, 135, 137, 139, 445, 1433, 3306, 3389, 5900, 6379}


@lru_cache(maxsize=1)
def _internal_nets():
    return [ipaddress.ip_network(n, strict=False) for n in config.INTERNAL_NETWORKS]


@lru_cache(maxsize=65536)
def is_internal(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(addr in net for net in _internal_nets())


def enrich(ev: dict):
    src = ev.get("src_endpoint") if isinstance(ev.get("src_endpoint"), dict) else None
    dst = ev.get("dst_endpoint") if isinstance(ev.get("dst_endpoint"), dict) else None
    feats = {}

    src_int = is_internal(src["ip"]) if src and src.get("ip") else None
    dst_int = is_internal(dst["ip"]) if dst and dst.get("ip") else None
    if src_int is not None:
        src.setdefault("zone", "internal" if src_int else "external")
        feats["src_is_internal"] = src_int
    if dst_int is not None:
        dst.setdefault("zone", "internal" if dst_int else "external")
        feats["dst_is_internal"] = dst_int

    if src_int is not None and dst_int is not None:
        direction_id = 3 if (src_int and dst_int) else 2 if src_int else 1 if dst_int else 0
        conn = ev.setdefault("connection_info", {})
        conn.setdefault("direction_id", direction_id)
        conn.setdefault("direction", ocsf.DIRECTION[conn["direction_id"]])

    port = dst.get("port") if dst else None
    if isinstance(port, int):
        if port in WELL_KNOWN_PORTS:
            dst.setdefault("svc_name", WELL_KNOWN_PORTS[port])
        feats["dst_port_class"] = "well_known" if port < 1024 else "registered" if port < 49152 else "dynamic"
        feats["dst_port_risky"] = port in RISKY_PORTS

    feats["is_blocked"] = ev.get("action_id") == 2
    feats["is_finding"] = ev.get("class_uid") == 2004
    feats["severity_score"] = ev.get("severity_id", 0) if ev.get("severity_id") != 99 else 0
    ev["enrichments"] = feats
