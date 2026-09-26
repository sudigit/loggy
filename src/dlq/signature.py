"""
Structural signature of an unparsed event, used to cluster the DLQ.

One syslog port routinely carries several unknown devices at once (a SonicWall,
a Juniper, a drifted pfSense ...). Proposing one parser per *channel* would mix
them; instead every quarantined event gets a signature of its SHAPE (format +
stable literal tokens, with variable values masked), and self-heal proposes one
parser per cluster.
"""
import hashlib
import json
import re

from src.parser import envelope

_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:[:/]\d+)*$")
_NUM = re.compile(r"^[-+]?\d+(?:[.,:]\d+)*$")
_HEX = re.compile(r"^(?:0x)?[0-9a-fA-F]{8,}$")
_WORD = re.compile(r"^[A-Za-z%_][\w%\-]*:?$")
_KV = re.compile(r"([A-Za-z_][\w.\-]*)=")


def _shape(tok: str) -> str:
    if _IP.match(tok):
        return "<ip>"
    if _NUM.match(tok):
        return "<num>"
    if _HEX.match(tok):
        return "<hex>"
    if "=" in tok:
        return "<kv>"
    if _WORD.match(tok) and len(tok) <= 40:
        return re.sub(r"\d", "#", tok)
    return "<*>"


def compute(text: str, channel: str):
    """Returns (cluster_id, human_label, format_guess)."""
    env, payload = envelope.parse(text)
    p = payload.strip()
    app = (env or {}).get("app_name")
    fmt, key, label = "text", None, None

    if p.startswith("{"):
        try:
            obj = json.loads(p)
            if isinstance(obj, dict):
                keys = sorted(obj.keys())
                fmt, key = "json", "json:" + ",".join(keys[:12])
                label = "JSON {" + ", ".join(keys[:5]) + (", …" if len(keys) > 5 else "") + "}"
        except json.JSONDecodeError:
            pass
    if key is None and "CEF:" in p:
        parts = p[p.find("CEF:"):].split("|")
        fmt, key = "cef", "cef:" + "|".join(parts[1:3])
        label = "CEF " + " / ".join(parts[1:3])
    if key is None and "LEEF:" in p:
        parts = p[p.find("LEEF:"):].split("|")
        fmt, key = "leef", "leef:" + "|".join(parts[1:3])
        label = "LEEF " + " / ".join(parts[1:3])
    if key is None and p.startswith("<"):
        m = re.match(r"<\s*([\w:.\-]+)", p)
        fmt, key = "xml", "xml:" + (m.group(1) if m else "?")
        label = f"XML <{m.group(1) if m else '?'}>"
    if key is None:
        kv_keys = _KV.findall(p)
        if len(kv_keys) >= 3:
            fmt, key = "kv", "kv:" + ",".join(kv_keys[:4])
            label = "key=value {" + ", ".join(kv_keys[:4]) + ", …}"
        elif p.count(",") >= 5 and p.count(",") > p.count(" "):
            ncols = p.count(",") + 1
            fmt, key = "csv", f"csv:{ncols}"
            label = f"CSV ({ncols} columns)"
        else:
            shape = " ".join(_shape(t) for t in p.split()[:4])
            key = "text:" + shape
            label = shape
    if app:
        key = f"app={app}|{key}"
        label = f"{app}: {label}"

    cluster_id = hashlib.sha1(f"{channel}|{key}".encode("utf-8")).hexdigest()[:12]
    return cluster_id, label[:120], fmt
