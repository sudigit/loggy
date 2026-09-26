"""
Layer 2 of parsing: payload tokenizers.

Each tokenizer turns a payload string into a flat-or-nested dict of source
fields. They are format-generic (regex, json, kv, csv, cef, leef, xml) and
driven entirely by the parser YAML -- adding a vendor never adds code here.
"""
import csv
import io
import json
import re
import xml.etree.ElementTree as ET


class TokenizeError(Exception):
    pass


# ---------------------------------------------------------------- regex
def tokenize_regex(payload: str, spec: dict) -> dict:
    """`pattern:` or `patterns:` (list; first match wins). A list entry may be
    {pattern: ..., static: {ocsf.path: value}} to tag which variant matched."""
    for entry in spec["_compiled"]:
        m = entry["re"].search(payload)
        if m:
            tokens = {k: v for k, v in m.groupdict().items() if v is not None}
            if entry.get("static"):
                tokens["__static__"] = entry["static"]
            return tokens
    raise TokenizeError("no tokenize pattern matched")


# ---------------------------------------------------------------- json
def tokenize_json(payload: str, spec: dict) -> dict:
    start = payload.find("{")
    if start < 0:
        raise TokenizeError("payload is not a JSON object")
    try:
        obj = json.loads(payload[start:])
    except json.JSONDecodeError as e:
        raise TokenizeError(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise TokenizeError("payload is not a JSON object")
    return obj


# ---------------------------------------------------------------- key=value
_KV_DEFAULT = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]*)')


def tokenize_kv(payload: str, spec: dict) -> dict:
    """Handles quoted values (FortiGate, SonicWall, Juniper). Override the pair
    grammar with `pair_regex` (two groups: key, value) for exotic formats."""
    rx = spec.get("_pair_re") or _KV_DEFAULT
    tokens = {}
    for key, val in rx.findall(payload):
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1].replace('\\"', '"')
        tokens[key] = val
    if not tokens:
        raise TokenizeError("no key=value pairs found")
    return tokens


# ---------------------------------------------------------------- csv / tsv
def tokenize_csv(payload: str, spec: dict) -> dict:
    """`fields:` names each column positionally (null / '_' = skip column)."""
    delim = spec.get("delimiter", ",")
    if delim in ("\\t", "tab"):
        delim = "\t"
    row = next(csv.reader(io.StringIO(payload.strip()), delimiter=delim,
                          quotechar=spec.get("quotechar", '"')), None)
    names = spec.get("fields") or []
    min_cols = spec.get("min_columns", len(names) // 2 or 1)
    if not row or len(row) < min_cols:
        raise TokenizeError(f"expected >= {min_cols} columns, got {len(row) if row else 0}")
    tokens = {}
    for i, value in enumerate(row):
        name = names[i] if i < len(names) else f"_col{i}"
        if name in (None, "_") or value == "":
            continue
        tokens[name] = value
    return tokens


# ---------------------------------------------------------------- CEF
_CEF_HEADER = ["cef_version", "device_vendor", "device_product", "device_version",
               "signature_id", "name", "severity"]
_CEF_EXT = re.compile(r"([\w.\[\]]+)=((?:\\=|[^=])*?)(?=\s+[\w.\[\]]+=|\s*$)")


def _split_unescaped(s: str, sep: str, maxsplit: int) -> list:
    parts, cur, i = [], [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            cur.append(s[i + 1] if s[i + 1] in (sep, "\\") else ch + s[i + 1])
            i += 2
            continue
        if ch == sep and len(parts) < maxsplit:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def tokenize_cef(payload: str, spec: dict) -> dict:
    idx = payload.find("CEF:")
    if idx < 0:
        raise TokenizeError("no CEF header")
    parts = _split_unescaped(payload[idx + 4:], "|", 7)
    if len(parts) < 7:
        raise TokenizeError("truncated CEF header")
    tokens = dict(zip(_CEF_HEADER, (p.strip() for p in parts[:7])))
    ext = parts[7] if len(parts) > 7 else ""
    for key, val in _CEF_EXT.findall(ext):
        tokens[key] = val.replace("\\=", "=").replace("\\n", "\n").strip()
    return tokens


# ---------------------------------------------------------------- LEEF
_LEEF_HEADER = ["leef_version", "device_vendor", "device_product", "device_version", "event_id"]


def tokenize_leef(payload: str, spec: dict) -> dict:
    idx = payload.find("LEEF:")
    if idx < 0:
        raise TokenizeError("no LEEF header")
    body = payload[idx + 5:]
    version = body.split("|", 1)[0]
    nhdr = 6 if version.startswith("2") else 5
    parts = body.split("|", nhdr)
    if len(parts) == nhdr and nhdr == 5 and "	" in parts[4]:
        # LEEF 1.0 without the trailing '|' after EventID (seen in the wild)
        parts[4], rest = parts[4].split("	", 1)
        parts.append(rest)
    if len(parts) < nhdr:
        raise TokenizeError("truncated LEEF header")
    tokens = dict(zip(_LEEF_HEADER, (p.strip() for p in parts[:5])))
    delim = "\t"
    if nhdr == 6:
        d = parts[5]
        if d.lower().startswith(("x", "0x")):
            delim = chr(int(d.lower().lstrip("0").lstrip("x"), 16))
        elif d:
            delim = d
    attrs = parts[nhdr] if len(parts) > nhdr else ""
    if delim == "\t" and "\t" not in attrs:
        # many devices replace the tab with spaces in transit -- fall back to kv grammar
        tokens.update({k: v for k, v in tokenize_kv(attrs, {}).items()} if "=" in attrs else {})
        return tokens
    for pair in attrs.split(delim):
        if "=" in pair:
            k, v = pair.split("=", 1)
            tokens[k.strip()] = v.strip()
    return tokens


# ---------------------------------------------------------------- XML
def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def tokenize_xml(payload: str, spec: dict) -> dict:
    """Flattens XML into dotted paths. Elements carrying a `Name` attribute
    (e.g. <Data Name="SourceIp">10.0.0.1</Data>) become tokens by that name."""
    start = payload.find("<")
    try:
        root = ET.fromstring(payload[start:] if start >= 0 else payload)
    except ET.ParseError as e:
        raise TokenizeError(f"invalid XML: {e}") from e
    tokens = {}

    def walk(el, path):
        tag = _strip_ns(el.tag)
        here = f"{path}.{tag}" if path else tag
        for attr, val in el.attrib.items():
            if attr != "Name":
                tokens[f"{here}@{_strip_ns(attr)}"] = val
        text = (el.text or "").strip()
        if "Name" in el.attrib and text:
            tokens[el.attrib["Name"]] = text
        elif text and not list(el):
            tokens[here] = text
        for child in el:
            walk(child, here)

    walk(root, "")
    return tokens


TOKENIZERS = {
    "regex": tokenize_regex,
    "json": tokenize_json,
    "kv": tokenize_kv,
    "csv": tokenize_csv,
    "cef": tokenize_cef,
    "leef": tokenize_leef,
    "xml": tokenize_xml,
}


def compile_spec(spec: dict) -> dict:
    """Pre-compiles regexes once at config load (hot path never compiles)."""
    spec = dict(spec)
    if spec["type"] not in TOKENIZERS:
        raise ValueError(f"unknown tokenize type: {spec['type']}")
    if spec["type"] == "regex":
        entries = spec.get("patterns") or [spec["pattern"]]
        compiled = []
        for e in entries:
            if isinstance(e, str):
                e = {"pattern": e}
            compiled.append({"re": re.compile(e["pattern"]), "static": e.get("static")})
        spec["_compiled"] = compiled
    if spec["type"] == "kv" and spec.get("pair_regex"):
        spec["_pair_re"] = re.compile(spec["pair_regex"])
    return spec


def tokenize(payload: str, spec: dict) -> dict:
    return TOKENIZERS[spec["type"]](payload, spec)
