"""
Deterministic parser inference -- the air-gapped "AI" of the self-heal loop.

Given a cluster of DLQ samples, it infers a complete, runnable parser config:

  1. format      json | cef | leef | xml | kv | csv | text   (payload after the syslog envelope)
  2. tokenizer   kv grammar / csv delimiter / an aligned regex built from the samples
  3. mapping     vendor field names -> OCSF paths via a synonym dictionary, plus
                 value-shape detection (IPs, ports) for anonymous columns/tokens
  4. semantics   disposition + activity tables from observed verbs (deny/allow/...)
  5. class       Network / HTTP / Process / Authentication / Base, from what was found
  6. timestamp   field + format that parses on EVERY sample (else envelope / ingest)
  7. fingerprint the most specific literal shared by all samples

The result is only a *proposal*: it is scored against the samples, regression
tested, and must be approved by a human before it touches live traffic.
An optional local LLM (Ollama) can propose too; the better-scoring one wins.
"""
import csv
import io
import json
import re
from collections import Counter

import yaml

from src.parser import envelope as envelope_mod
from src.parser import tokenizers

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]+$")
IP_PORT_RE = re.compile(r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[:/](?P<port>\d{1,5})(?:[:/](?P<rest>\S+))?$")
INT_RE = re.compile(r"^\d+$")
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
FLOW_RE = re.compile(rf"^{_IPV4}[:/]\d+\s*-+>\s*{_IPV4}[:/]\d+$")

# normalized vendor field name -> OCSF path (names compared lowercase, non-alnum stripped)
SYNONYMS = {
    "src_endpoint.ip": ["src", "srcip", "srcaddr", "sourceip", "sourceaddress", "saddr", "sip", "clientip",
                        "cip", "srcipaddr", "source", "localip", "ipsrc", "remoteip", "callingstationid"],
    "dst_endpoint.ip": ["dst", "dstip", "destip", "dstaddr", "destinationip", "destinationaddress", "daddr",
                        "dip", "serverip", "destaddr", "ipdst", "dest", "destination"],
    "src_endpoint.port": ["sport", "srcport", "sourceport", "spt", "sprt", "clientport", "srcprt", "sourcetransportport"],
    "dst_endpoint.port": ["dport", "dstport", "destport", "destinationport", "dpt", "dprt", "serverport",
                          "dstprt", "destinationtransportport"],
    "src_endpoint.hostname": ["shost", "srchost", "sourcehost", "sourcehostname", "clienthost", "computername"],
    "dst_endpoint.hostname": ["dhost", "dsthost", "desthost", "destinationhost", "destinationhostname", "serverhost"],
    "src_endpoint.interface_name": ["srcintf", "iniface", "inif", "ingressinterface", "srcinterface", "inboundinterface",
                                    "srczone", "fromzone"],
    "dst_endpoint.interface_name": ["dstintf", "outiface", "outif", "egressinterface", "dstinterface",
                                    "outboundinterface", "dstzone", "tozone"],
    "src_endpoint.mac": ["smac", "srcmac", "sourcemac"],
    "dst_endpoint.mac": ["dmac", "dstmac", "destmac"],
    "connection_info.protocol_name": ["proto", "protocol", "ipproto", "transport", "protocolname", "l4proto"],
    "disposition": ["action", "act", "disposition", "verdict", "decision", "fwaction", "result", "outcome"],
    "actor.user.name": ["user", "username", "usr", "suser", "usrname", "account", "accountname", "login",
                        "srcuser", "userid", "subjectusername", "targetusername"],
    "http_request.url.url_string": ["url", "uri", "requesturl", "request", "requri", "fullurl"],
    "http_request.http_method": ["method", "httpmethod", "requestmethod", "reqmethod", "verb"],
    "http_response.code": ["status", "statuscode", "httpstatus", "responsecode", "httpcode", "sc"],
    "message": ["msg", "message", "description", "desc", "eventdesc", "summary", "note", "name", "eventname"],
    "severity_id": ["severity", "sev", "level", "priority", "pri", "loglevel", "risk"],
    "device.hostname": ["devname", "devicename", "dvchost", "fw", "hostname", "firewall", "host", "sensor",
                        "observer", "computer", "reportinghost"],
    "device.uid": ["devid", "sn", "serial", "serialnumber", "deviceid", "aid", "agentid", "sensorid"],
    "firewall_rule.name": ["rule", "rulename", "policy", "policyname", "acl", "aclname", "accesslist"],
    "firewall_rule.uid": ["ruleid", "policyid", "ruleuid", "ruleno"],
    "traffic.bytes_out": ["sentbyte", "sentbytes", "bytessent", "bytesout", "sbytes", "srcbytes", "outbytes",
                          "bytestoserver", "sent"],
    "traffic.bytes_in": ["rcvdbyte", "rcvdbytes", "bytesreceived", "bytesin", "rbytes", "dstbytes", "inbytes",
                         "bytestoclient", "rcvd"],
    "traffic.packets": ["packets", "pkts", "totalpackets"],
    "connection_info.uid": ["sessionid", "session", "connid", "connectionid", "flowid"],
    "app_name": ["app", "application", "appname", "service", "appid"],
    "process.cmd_line": ["commandline", "cmdline", "cmd", "processcommandline"],
    "process.file.path": ["image", "imagefilename", "processpath", "exe", "executable", "newprocessname"],
    "process.pid": ["pid", "processid", "newprocessid"],
    "finding_info.title": ["signature", "signaturename", "threatname", "alertname", "attackname", "rulename2"],
    "metadata.event_code": ["eventid", "eventcode", "msgid", "logid", "id", "messageid", "c", "m", "eventtype"],
}
_SYN_INDEX = {syn: path for path, syns in SYNONYMS.items() for syn in syns}
TIME_KEYS = ["timestamp", "time", "eventtime", "ts", "datetime", "rt", "devtime", "date", "eventtimestamp",
             "createdat", "logtime", "receivetime", "generatedtime", "starttime", "timecreated", "utctime"]

ALLOW_WORDS = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "passed", "built",
               "success", "ok", "established", "open", "forward", "forwarded"}
BLOCK_WORDS = {"deny", "denied", "block", "blocked", "reject", "rejected", "refused", "fail", "failed",
               "failure", "prevent", "prevented", "dropped", "drop"}
DROP_WORDS = {"drop", "dropped", "discard", "discarded"}

TIME_FORMATS = ["epoch", "epoch_ms", "iso8601", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC",
                "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%b %d %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "syslog"]


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.split(".")[-1].split("@")[-1].lower())


# ---------------------------------------------------------------- format detection
def detect_format(payloads: list) -> str:
    votes = Counter()
    for p in payloads:
        s = p.strip()
        if s.startswith("{"):
            try:
                if isinstance(json.loads(s), dict):
                    votes["json"] += 1
                    continue
            except json.JSONDecodeError:
                pass
        if "CEF:" in s:
            votes["cef"] += 1
        elif "LEEF:" in s:
            votes["leef"] += 1
        elif s.startswith("<") and s.endswith(">"):
            votes["xml"] += 1
        elif len(re.findall(r"[\w.\-]+=", s)) >= 3:
            votes["kv"] += 1
        elif any(s.count(d) >= 4 and s.count(d) > s.count(" ") for d in (",", "|", ";", "\t")):
            votes["csv"] += 1
        else:
            votes["text"] += 1
    return votes.most_common(1)[0][0] if votes else "text"


def _detect_delimiter(payloads: list) -> str:
    best, best_score = ",", -1
    for d in (",", "\t", "|", ";"):
        counts = [p.count(d) for p in payloads]
        if min(counts) >= 3 and len(set(counts)) <= 2 and min(counts) > best_score:
            best, best_score = d, min(counts)
    return best


# ---------------------------------------------------------------- text -> aligned regex
def _token_regex(values: list, name: str):
    """Regex fragment + inferred semantic kind for one aligned text column."""
    if all(FLOW_RE.match(v) for v in values):
        return (rf"(?P<src_ip>{_IPV4})[:/](?P<src_port>\d+)\s*-+>\s*"
                rf"(?P<dst_ip>{_IPV4})[:/](?P<dst_port>\d+)"), "flow"
    if all(IP_PORT_RE.match(v) for v in values):
        return rf"(?P<{name}_ip>(?:\d{{1,3}}\.){{3}}\d{{1,3}})[:/](?P<{name}_port>\d+)(?:[:/]\S+)?", "ip_port"
    if all(IP_RE.match(v) for v in values):
        return rf"(?P<{name}>\S+)", "ip"
    if all(INT_RE.match(v) for v in values):
        return rf"(?P<{name}>\d+)", "int"
    return rf"(?P<{name}>\S+)", "word"


def infer_text_regex(payloads: list):
    """Aligns whitespace tokens across samples. Constant tokens become literals,
    varying ones become named groups (named after a preceding label token if any)."""
    rows = [p.split() for p in payloads]
    width = Counter(len(r) for r in rows).most_common(1)[0][0]
    aligned = [r for r in rows if len(r) == width] or rows
    width = min(len(r) for r in aligned)
    parts, kinds, used = [], {}, Counter()
    for i in range(width):
        col = [r[i] for r in aligned]
        if len(set(col)) == 1:
            tok = col[0]
            m = re.fullmatch(r"([A-Za-z_][\w\-]*)=(.*)", tok)
            if m:
                parts.append(rf"{re.escape(m.group(1))}=(?P<{m.group(1)}>\S+)")
            elif i == 0 or re.fullmatch(r"[A-Za-z_\-]+:?", tok):
                parts.append(re.escape(tok))   # stable word -> literal anchor
            else:
                parts.append(r"\S+")           # constant-looking value (ids, interfaces) -> wildcard
            continue
        label = None
        if i > 0 and len(set(r[i - 1] for r in aligned)) == 1 and re.fullmatch(r"[A-Za-z_]+:?", aligned[0][i - 1]):
            label = aligned[0][i - 1].rstrip(":").lower()
        kv = [re.fullmatch(r"([A-Za-z_][\w\-]*)=(.*)", v) for v in col]
        if all(kv) and len({m.group(1) for m in kv}) == 1:
            key = kv[0].group(1)
            frag, kind = _token_regex([m.group(2) for m in kv], key)
            parts.append(rf"{re.escape(key)}={frag}")
            kinds[key] = kind
            continue
        base = label or "field"
        used[base] += 1
        name = base if used[base] == 1 and label else f"{base}{used[base]}"
        frag, kind = _token_regex(col, name)
        parts.append(frag)
        kinds[name] = kind
    regex = r"\s+".join(parts)
    if any(len(r) > width for r in rows):
        regex += r"(?:\s+(?P<rest>.*))?"
    return regex, kinds


# ---------------------------------------------------------------- tokenization of samples
def tokenize_samples(fmt: str, payloads: list):
    """Returns (tokenize_spec, list_of_token_dicts, kinds{name: ip|int|word|ip_port})."""
    kinds = {}
    if fmt == "json":
        spec = {"type": "json"}
    elif fmt == "cef":
        spec = {"type": "cef"}
    elif fmt == "leef":
        spec = {"type": "leef"}
    elif fmt == "xml":
        spec = {"type": "xml"}
    elif fmt == "kv":
        spec = {"type": "kv"}
    elif fmt == "csv":
        delim = _detect_delimiter(payloads)
        ncols = Counter(len(next(csv.reader(io.StringIO(p), delimiter=delim))) for p in payloads).most_common(1)[0][0]
        spec = {"type": "csv", "delimiter": "\\t" if delim == "\t" else delim,
                "fields": [f"col{i + 1}" for i in range(ncols)], "min_columns": max(2, ncols - 2)}
    else:
        regex, kinds = infer_text_regex(payloads)
        spec = {"type": "regex", "pattern": regex}
    compiled = tokenizers.compile_spec(spec)
    token_rows = []
    for p in payloads:
        try:
            token_rows.append(tokenizers.tokenize(p, compiled))
        except tokenizers.TokenizeError:
            pass
    return spec, token_rows, kinds


def _flatten(d: dict, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


# ---------------------------------------------------------------- mapping inference
def infer_mapping(token_rows: list, kinds: dict, fmt: str):
    flat_rows = [_flatten(r) for r in token_rows]
    keys = [k for k, _ in Counter(k for r in flat_rows for k in r).most_common()]
    values = {k: [str(r[k]) for r in flat_rows if k in r and r[k] not in (None, "")] for k in keys}
    fields, extract, taken = {}, [], set()

    def assign(src_key, path):
        if path in taken or src_key in fields:
            return False
        fields[src_key] = path
        taken.add(path)
        return True

    # 1) by name
    for k in keys:
        path = _SYN_INDEX.get(_norm(k))
        if not path or not values[k]:
            continue
        vals = values[k]
        if path.endswith(".ip"):
            if all(IP_PORT_RE.match(v) for v in vals):
                side = path.split(".")[0]
                rx = rf"^(?P<{_norm(k)}_ip>(?:\d{{1,3}}\.){{3}}\d{{1,3}})[:/](?P<{_norm(k)}_port>\d+)"
                extract.append({"from": k, "pattern": rx})
                assign(f"{_norm(k)}_ip", f"{side}.ip")
                assign(f"{_norm(k)}_port", f"{side}.port")
                continue
            if not all(IP_RE.match(v) for v in vals):
                continue
        if path.endswith(".port") and not all(INT_RE.match(v) and int(v) < 65536 for v in vals):
            continue
        assign(k, path)

    # 2) by value shape for anonymous columns (csv colN / regex fieldN)
    for k in keys:
        if k in fields or not values[k]:
            continue
        kind = kinds.get(k)
        vals = values[k]
        if kind == "ip_port":
            continue
        if kind == "ip" or (fmt == "csv" and all(IP_RE.match(v) for v in vals)):
            if "src_endpoint.ip" not in taken:
                assign(k, "src_endpoint.ip")
            elif "dst_endpoint.ip" not in taken:
                assign(k, "dst_endpoint.ip")
    for k, kind in kinds.items():
        if kind == "ip_port":
            side = "src_endpoint" if "src_endpoint.ip" not in taken else "dst_endpoint"
            assign(f"{k}_ip", f"{side}.ip")
            assign(f"{k}_port", f"{side}.port")
    if fmt == "csv":
        cols = [k for k in keys if k.startswith("col")]
        cols.sort(key=lambda c: int(c[3:]) if c[3:].isdigit() else 0)
        for k in cols:
            vals = values[k]
            if k in fields or not vals:
                continue
            if all(v.lower() in ("tcp", "udp", "icmp") for v in vals):
                assign(k, "connection_info.protocol_name")
            elif all(v.lower() in ALLOW_WORDS | BLOCK_WORDS for v in vals):
                assign(k, "disposition")

        dst_col = next((k for k, p in fields.items() if p == "dst_endpoint.ip" and k.startswith("col")), None)
        if dst_col and dst_col[3:].isdigit():
            n = int(dst_col[3:])
            nxt = [f"col{n + 1}", f"col{n + 2}"]
            if all(values.get(c) and all(INT_RE.match(v) and int(v) < 65536 for v in values[c]) for c in nxt):
                assign(nxt[0], "src_endpoint.port")
                assign(nxt[1], "dst_endpoint.port")

    # 3) disposition / activity tables from observed verbs
    lookups, values_tables = [], {}
    disp_key = next((k for k, p in fields.items() if p == "disposition"), None)
    if disp_key:
        observed = {v.lower() for v in values.get(disp_key, [])}
        table, act = {}, {}
        for v in sorted(observed):
            if v in DROP_WORDS:
                table[v], act[v] = "Dropped", "Refuse"
            elif v in BLOCK_WORDS or any(w in v for w in ("deny", "block", "drop", "reject")):
                table[v], act[v] = "Blocked", "Refuse"
            elif v in ALLOW_WORDS or any(w in v for w in ("allow", "accept", "permit", "pass")):
                table[v], act[v] = "Allowed", "Traffic"
        if table:
            values_tables[disp_key] = table
            lookups.append({"from": disp_key, "to": "activity_name", "map": act, "default": "Traffic"})
    sev_key = next((k for k, p in fields.items() if p == "severity_id"), None)
    if sev_key:
        observed = values.get(sev_key, [])
        if observed and all(INT_RE.match(v) for v in observed):
            hi = max(int(v) for v in observed)
            if _norm(sev_key) in ("pri", "level", "loglevel", "priority") and hi <= 7:
                # syslog-style level: 0 emergency .. 7 debug
                values_tables[sev_key] = {0: 6, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 7: 1}
            elif hi > 6:  # 0-10 style scale
                values_tables[sev_key] = {i: (1 if i <= 2 else 2 if i <= 4 else 3 if i <= 6 else 4 if i <= 8 else 5)
                                          for i in range(0, 11)}
        else:
            values_tables[sev_key] = {"info": 1, "informational": 1, "notice": 1, "low": 2, "warning": 3,
                                      "warn": 3, "medium": 3, "error": 4, "high": 4, "critical": 5,
                                      "alert": 5, "emergency": 6}
    return fields, extract, values_tables, lookups, values


def infer_class(fields: dict) -> dict:
    paths = set(fields.values())
    if {"http_request.url.url_string", "http_request.http_method"} & paths:
        return {"class_uid": 4002, "activity": "Other"}
    if "process.cmd_line" in paths or "process.file.path" in paths:
        return {"class_uid": 1007, "activity": "Launch"}
    if "finding_info.title" in paths:
        return {"class_uid": 2004, "activity": "Create"}
    if {"src_endpoint.ip", "dst_endpoint.ip"} & paths:
        return {"class_uid": 4001, "activity": "Traffic"}
    return {"class_uid": 0, "activity": "Other"}


def infer_timestamp(values: dict, envelopes: list) -> dict:
    has_env_time = all(e and e.get("time") for e in envelopes)
    from src.parser.engine import _parse_time_value, _parse_tz
    tz = _parse_tz("UTC")
    norm_keys = {_norm(k): k for k in values}
    if "date" in norm_keys and "time" in norm_keys:
        d, t = values[norm_keys["date"]], values[norm_keys["time"]]
        if d and t and all(_parse_time_value(f"{a} {b}", "%Y-%m-%d %H:%M:%S", tz) for a, b in zip(d, t)):
            rule = {"source": [norm_keys["date"], norm_keys["time"]], "format": "%Y-%m-%d %H:%M:%S",
                    "timezone": "UTC"}
            if has_env_time:
                rule["fallback"] = "envelope"
            return rule
    for tk in TIME_KEYS:
        k = norm_keys.get(tk)
        if not k or not values[k]:
            continue
        for fmt in TIME_FORMATS:
            vals = values[k]
            if fmt == "epoch" and not all(re.fullmatch(r"\d{9,10}(\.\d+)?", v) for v in vals):
                continue
            if fmt == "epoch_ms" and not all(re.fullmatch(r"\d{12,13}", v) for v in vals):
                continue
            if all(_parse_time_value(v, fmt, tz) for v in vals):
                rule = {"source": k, "format": fmt}
                if has_env_time:
                    rule["fallback"] = "envelope"
                return rule
    return {"source": "envelope"} if has_env_time else {"source": "ingest_time"}


# ---------------------------------------------------------------- fingerprint
_PREFERRED_CONST_KEYS = {"vendor", "product", "type", "eventtype", "eventsimplename", "logtype", "source",
                         "id", "devtype", "category", "module", "app", "dataset"}


def _const_score(key: str, value: str):
    """Prefer descriptive constants (vendor/type names) over per-device ids/IPs."""
    v = str(value)
    looks_id = bool(re.fullmatch(r"[0-9a-fA-F:.\-]{6,}", v)) or bool(IP_RE.match(v))
    return (_norm(key) in _PREFERRED_CONST_KEYS, not looks_id, any(c.isalpha() for c in v), -len(key))


def infer_fingerprint(fmt: str, raw_samples: list, payloads: list, token_rows: list, spec: dict) -> dict:
    flat_rows = [_flatten(r) for r in token_rows]
    if fmt == "json" and flat_rows:
        common = set(flat_rows[0])
        for r in flat_rows[1:]:
            common &= set(r)
        const = [k for k in common if len({str(r[k]) for r in flat_rows}) == 1
                 and isinstance(flat_rows[0][k], str) and 2 < len(flat_rows[0][k]) < 60]
        if const:
            best = max(const, key=lambda k: _const_score(k, flat_rows[0][k]))
            return {"type": "json_key", "key": best, "value": flat_rows[0][best]}
        rare = sorted(common, key=lambda k: (-len(k), k))[:2]
        if len(rare) == 2:
            return {"type": "all", "rules": [{"type": "json_key", "key": k} for k in rare]}
        if rare:
            return {"type": "json_key", "key": rare[0]}
    if fmt == "kv" and flat_rows:
        common = set(flat_rows[0])
        for r in flat_rows[1:]:
            common &= set(r)
        const = []
        for k in common:
            vals = {str(r[k]) for r in flat_rows}
            if len(vals) == 1 and len(k) + len(next(iter(vals))) >= 5:
                lit = f"{k}={next(iter(vals))}"
                if all(lit in s for s in raw_samples):
                    const.append((k, next(iter(vals)), lit))
        if const:
            k, v, lit = max(const, key=lambda c: _const_score(c[0], c[1]))
            return {"type": "contains", "pattern": lit}
        keys = [k for k in (list(flat_rows[0].keys())) if k in common][:3]
        if keys:
            return {"type": "regex", "pattern": r"\b" + r"=.*\b".join(re.escape(k) for k in keys) + "="}
    if fmt == "csv" and flat_rows:
        delim = spec.get("delimiter", ",")
        delim = "\t" if delim == "\\t" else delim
        for k in sorted(flat_rows[0], key=lambda c: int(c[3:]) if c[3:].isdigit() else 0):
            vals = {str(r.get(k)) for r in flat_rows}
            v = next(iter(vals))
            if len(vals) == 1 and re.fullmatch(r"[A-Za-z][\w\-]{2,}", v) and all(
                    f"{delim}{v}{delim}" in s for s in raw_samples):
                return {"type": "contains", "pattern": f"{delim}{v}{delim}"}
    if fmt in ("cef", "leef") and flat_rows:
        r = flat_rows[0]
        lit = f"|{r.get('device_vendor')}|{r.get('device_product')}|"
        if all(lit in s for s in raw_samples):
            return {"type": "contains", "pattern": lit}
    # generic: the longest literal token (>= 5 chars) shared by every raw sample
    token_sets = [set(re.findall(r"[A-Za-z%_][\w%\-:.]{4,}", s)) for s in raw_samples]
    common = set.intersection(*token_sets) if token_sets else set()
    months = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
    common = {t for t in common if t[:3] not in months}
    if common:
        best = max(common, key=lambda t: (len(t), t))
        return {"type": "contains", "pattern": best}
    return {"type": "regex", "pattern": "^" + re.escape(payloads[0][:12]) if payloads else "."}


# ---------------------------------------------------------------- top level
def propose(samples: list, channel: str, source_id: str, product_hint: str = None) -> dict:
    """Returns {"config": dict, "format": str, "notes": [...], "mapped_fields": int}."""
    parsed = [envelope_mod.parse(s) for s in samples]
    envelopes = [e for e, _ in parsed]
    payloads = [p for _, p in parsed]
    fmt = detect_format(payloads)
    spec, token_rows, kinds = tokenize_samples(fmt, payloads)
    notes = [f"Detected payload format: {fmt} ({len(token_rows)}/{len(samples)} samples tokenized)"]
    if not token_rows:
        notes.append("Tokenizer could not parse any sample -- manual pattern required.")
        token_rows = [{}]

    fields, extract, values_tables, lookups, values = infer_mapping(token_rows, kinds, fmt)
    ocsf_spec = infer_class(fields)
    ts_rule = infer_timestamp(values, envelopes)
    fingerprint = infer_fingerprint(fmt, samples, payloads, token_rows, spec)

    vendor, product = "unknown", source_id
    if fmt in ("cef", "leef") and token_rows[0]:
        vendor = token_rows[0].get("device_vendor", vendor)
        product = token_rows[0].get("device_product", product)
    apps = {e.get("app_name") for e in envelopes if e and e.get("app_name")}
    if len(apps) == 1 and product == source_id:
        product = apps.pop()

    if fmt == "text" and "disposition" not in fields.values():
        words = [set(re.findall(r"[a-z]+", p.lower())) for p in payloads]
        common_words = set.intersection(*words) if words else set()
        if common_words & BLOCK_WORDS:
            ocsf_spec["static"] = {"disposition": "Blocked"}
            ocsf_spec["activity"] = "Refuse" if ocsf_spec["class_uid"] == 4001 else ocsf_spec["activity"]
        elif common_words & ALLOW_WORDS:
            ocsf_spec["static"] = {"disposition": "Allowed"}
    if ocsf_spec["class_uid"] in (1007, 3002):
        for k, p in list(fields.items()):
            if p == "src_endpoint.hostname" and "device.hostname" not in fields.values():
                fields[k] = "device.hostname"

    mapping = {"fields": fields}
    if extract:
        mapping["extract"] = extract
    if values_tables:
        mapping["values"] = values_tables
    if lookups:
        mapping["lookups"] = lookups
    mapping["timestamp"] = ts_rule

    config = {
        "source_id": source_id,
        "version": "v1",
        "log_name": product_hint or source_id,
        "product": {"name": product, "vendor_name": vendor},
        "channels": [channel],
        "priority": 55,
        "fingerprint": fingerprint,
        "tokenize": spec,
        "ocsf": ocsf_spec,
        "mapping": mapping,
    }
    semantic = [p for p in fields.values() if not p.startswith(("metadata.", "message", "device."))]
    notes.append(f"Mapped {len(fields)} field(s) to OCSF ({len(semantic)} security-relevant); "
                 f"class {ocsf_spec['class_uid']}.")
    if ts_rule["source"] in ("envelope", "ingest_time"):
        notes.append(f"No payload timestamp recognized; using {ts_rule['source']} time.")
    else:
        notes.append(f"Timestamp from '{ts_rule['source']}' ({ts_rule['format']}).")
    return {"config": config, "format": fmt, "notes": notes, "mapped_fields": len(semantic)}


def to_yaml(config: dict, header: str = None) -> str:
    body = yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=140)
    return (header + "\n" if header else "") + body
