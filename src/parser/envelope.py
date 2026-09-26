"""
Layer 1 of parsing: the transport envelope.

Almost every perimeter device ships logs inside a syslog envelope (RFC 3164
or RFC 5424), sometimes just a bare <PRI>. The envelope is parsed ONCE here,
generically, for every vendor -- so vendor parser configs only ever describe
their own payload, never the syslog header in front of it.
"""
import re
from datetime import datetime, timezone

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2})\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?(?P<msg>.*)$",
    re.DOTALL,
)
_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?\s*"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s:]+)\s*"
    r"(?:(?P<app>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+|:\s+)?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)
_PRI_ONLY = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$", re.DOTALL)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_bsd_timestamp(ts: str, now: datetime = None):
    """'Sep 16 10:22:01' (no year, no tz) -> aware UTC datetime.
    Year is inferred; a date more than a day in the future is assumed to be last year."""
    now = now or datetime.now(timezone.utc)
    parts = ts.split()
    try:
        month = _MONTHS[parts[0]]
        day = int(parts[1])
        if len(parts) == 4:
            year, clock = int(parts[2]), parts[3]
        else:
            year, clock = now.year, parts[2]
        hh, mm, ss = (int(x) for x in clock.split(":"))
        dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
    except (KeyError, ValueError, IndexError):
        return None
    if len(parts) == 3 and (dt - now).days >= 1:
        dt = dt.replace(year=year - 1)
    return dt


def _pri_fields(pri: str) -> dict:
    p = int(pri)
    return {"pri": p, "facility": p // 8, "syslog_severity": p % 8}


def parse(text: str):
    """Returns (envelope_dict_or_None, payload_text)."""
    stripped = text.lstrip("﻿").strip()

    m = _RFC5424.match(stripped)
    if m:
        env = {"format": "rfc5424", **_pri_fields(m["pri"]), "timestamp": m["ts"]}
        for key, grp in (("hostname", "host"), ("app_name", "app"), ("procid", "procid"),
                         ("msgid", "msgid")):
            if m[grp] != "-":
                env[key] = m[grp]
        if m["sd"] != "-":
            env["structured_data"] = m["sd"]
        try:
            env["time"] = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        except ValueError:
            pass
        return env, m["msg"].lstrip("﻿")

    m = _RFC3164.match(stripped)
    if m:
        env = {"format": "rfc3164", "timestamp": m["ts"], "hostname": m["host"]}
        if m["pri"]:
            env.update(_pri_fields(m["pri"]))
        if m["app"]:
            env["app_name"] = m["app"]
        if m["pid"]:
            env["procid"] = m["pid"]
        dt = parse_bsd_timestamp(m["ts"])
        if dt:
            env["time"] = dt
        return env, m["msg"]

    m = _PRI_ONLY.match(stripped)
    if m:
        return {"format": "pri_only", **_pri_fields(m["pri"])}, m["msg"]

    return None, stripped


def public_view(env: dict) -> dict:
    """JSON-safe copy (datetimes -> ISO) for embedding in metadata."""
    if not env:
        return None
    out = {k: v for k, v in env.items() if k != "time"}
    if env.get("time"):
        out["time"] = env["time"].astimezone(timezone.utc).isoformat()
    return out
