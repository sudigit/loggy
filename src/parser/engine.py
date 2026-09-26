"""
Deterministic parsing engine -- the ONE generic engine that executes whichever
YAML parser config matches. It never changes when a new source is onboarded.

Layered pipeline per event:
  0. select     -- route by channel preference + confirm by fingerprint
  1. envelope   -- generic syslog header (RFC 3164 / 5424 / <PRI>) -> device, time
  2. tokenize   -- payload format (regex|json|kv|csv|cef|leef|xml) -> source fields
  3. normalize  -- field/value/timestamp mapping -> OCSF class + derived attributes
  4. enrich     -- zone / direction / service / ML features (offline)
  5. validate   -- JSON-Schema contract; failures go to the DLQ, never to the lake

No LLM call happens anywhere in this file. That work happens offline, at
onboarding / self-heal time, and its *output* is one of these YAML files.
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import yaml

from src import config as cfg
from src.core import ids
from src.parser import envelope as envelope_mod
from src.parser import tokenizers
from src.schema import enrich, ocsf

logger = logging.getLogger("ulpf.engine")


class ParseError(Exception):
    """Raised when an event cannot be normalized. `reason` is a stable
    machine-readable category used for DLQ clustering and metrics."""

    def __init__(self, reason: str, detail: str = "", parser_id: str = None):
        self.reason = reason
        self.detail = detail
        self.parser_id = parser_id
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ------------------------------------------------------------------ config loading
def _compile_fingerprint(fp: dict) -> dict:
    fp = dict(fp)
    if fp["type"] in ("all", "any"):
        fp["rules"] = [_compile_fingerprint(r) for r in fp["rules"]]
    elif fp["type"] == "regex":
        fp["_re"] = re.compile(fp["pattern"])
    elif fp["type"] not in ("contains", "startswith", "json_key"):
        raise ValueError(f"unknown fingerprint type: {fp['type']}")
    return fp


def prepare_config(data: dict, path: str = None) -> dict:
    """Validates + pre-compiles one parser config dict. Raises ValueError on problems."""
    for key in ("source_id", "fingerprint", "tokenize", "mapping"):
        if key not in data:
            raise ValueError(f"missing required key '{key}'")
    data = dict(data)
    data["_path"] = path
    data["_fingerprint"] = _compile_fingerprint(data["fingerprint"])
    data["_tokenize"] = tokenizers.compile_spec(data["tokenize"])
    channels = data.get("channels") or ([data["channel"]] if data.get("channel") else [])
    data["_channels"] = set(channels)
    for ex in (data.get("mapping") or {}).get("extract") or []:
        ex["_re"] = re.compile(ex["pattern"])
    data.setdefault("priority", 50)
    data.setdefault("version", "v1")
    data.setdefault("ocsf", {"class_uid": 0})
    data.setdefault("product", {"name": data["source_id"], "vendor_name": data["source_id"]})
    return data


def load_config_file(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return prepare_config(yaml.safe_load(f), str(path))


def _load_all_configs() -> list:
    configs = []
    for path in sorted(cfg.PARSER_CONFIG_DIR.glob("*.yaml")):
        try:
            configs.append(load_config_file(path))
        except Exception as e:  # noqa: BLE001 - one bad file must not take the pipeline down
            logger.error(f"[engine] skipping invalid parser config {path.name}: {e}")
    return configs


# ------------------------------------------------------------------ helpers
def get_dotted(d, path: str):
    if isinstance(d, dict) and path in d:  # flat keys that themselves contain dots
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def set_dotted(d: dict, path: str, value):
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = cur[part] = {}
        cur = nxt
    cur[parts[-1]] = value


def flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and v:
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def _parse_tz(tz):
    if not tz or str(tz).upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", str(tz))
    if not m:
        return timezone.utc
    delta = timedelta(hours=int(m[2]), minutes=int(m[3]))
    return timezone(delta if m[1] == "+" else -delta)


_ISO_BASIC_TZ = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_time_value(raw_val, fmt: str, tz):
    try:
        if fmt == "epoch":
            return datetime.fromtimestamp(float(raw_val), tz=timezone.utc)
        if fmt == "epoch_ms":
            return datetime.fromtimestamp(float(raw_val) / 1000, tz=timezone.utc)
        if fmt == "epoch_ns":
            return datetime.fromtimestamp(float(raw_val) / 1e9, tz=timezone.utc)
        if fmt == "iso8601":
            s = _ISO_BASIC_TZ.sub(r"\1:\2", str(raw_val).replace("Z", "+00:00"))
            dt = datetime.fromisoformat(s)
        elif fmt == "syslog":
            dt = envelope_mod.parse_bsd_timestamp(str(raw_val))
        else:
            dt = datetime.strptime(str(raw_val), fmt)
    except (ValueError, TypeError, OverflowError, OSError):
        return None
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt


# ------------------------------------------------------------------ engine
class ParserEngine:
    def __init__(self, configs: list = None):
        if configs is None:
            self.reload()
        else:
            self.configs = configs
            self._sort()

    def reload(self):
        """Configs are re-read from disk on demand, so a newly promoted
        parser version goes live without restarting the pipeline."""
        self.configs = _load_all_configs()
        self._sort()

    def _sort(self):
        self.configs.sort(key=lambda c: -c.get("priority", 50))

    def get(self, source_id: str):
        return next((c for c in self.configs if c["source_id"] == source_id), None)

    # ---------- Stage 0: selection ----------
    def candidates(self, raw_text: str, channel: str) -> list:
        """All configs whose fingerprint matches, channel-affine ones first.
        Channel is only a routing *preference* -- a Cisco ASA log arriving on
        an unexpected port is still recognized by its signature."""
        preferred, others = [], []
        for c in self.configs:
            if not self.fingerprint_matches(raw_text, c["_fingerprint"]):
                continue
            (preferred if channel in c["_channels"] else others).append(c)
        return preferred + others

    def select(self, raw_text: str, channel: str):
        cands = self.candidates(raw_text, channel)
        return cands[0] if cands else None

    @classmethod
    def fingerprint_matches(cls, raw_text: str, fp: dict) -> bool:
        t = fp["type"]
        if t == "contains":
            return fp["pattern"] in raw_text
        if t == "startswith":
            return raw_text.lstrip().startswith(fp["pattern"])
        if t == "regex":
            return fp["_re"].search(raw_text) is not None
        if t == "json_key":
            s = raw_text.find("{")
            if s < 0 or fp["key"].split(".")[0] not in raw_text:
                return False
            try:
                obj = json.loads(raw_text[s:])
            except (json.JSONDecodeError, TypeError):
                return False
            val = get_dotted(obj, fp["key"]) if isinstance(obj, dict) else None
            if val is None:
                return False
            return "value" not in fp or str(val) == str(fp["value"])
        if t == "all":
            return all(cls.fingerprint_matches(raw_text, r) for r in fp["rules"])
        if t == "any":
            return any(cls.fingerprint_matches(raw_text, r) for r in fp["rules"])
        return False

    # ---------- Stage 1+2: envelope + tokenize ----------
    def tokenize(self, raw_text: str, parser_config: dict, payload: str = None) -> dict:
        """Tokenizes the payload (text after the syslog envelope) unless the
        config says `tokenize.on: raw`."""
        spec = parser_config.get("_tokenize") or tokenizers.compile_spec(parser_config["tokenize"])
        if spec.get("on") == "raw":
            payload = raw_text
        elif payload is None:
            payload = envelope_mod.parse(raw_text)[1]
        try:
            return tokenizers.tokenize(payload, spec)
        except tokenizers.TokenizeError as e:
            raise ParseError("tokenize_failed", str(e), parser_config["source_id"]) from e

    # ---------- Stage 3: normalize ----------
    def normalize(self, tokens: dict, parser_config: dict, event_id: str,
                  ingest_time_iso: str, envelope: dict = None, raw_info: dict = None,
                  channel: str = None) -> dict:
        mapping = parser_config.get("mapping", {})
        fields = mapping.get("fields", {}) or {}
        ocsf_spec = parser_config.get("ocsf", {}) or {}
        tokens = dict(tokens)
        static_override = tokens.pop("__static__", None) or {}
        ev = {}

        # static attributes declared by the config (e.g. connection_info.direction)
        for path, value in (ocsf_spec.get("static") or {}).items():
            set_dotted(ev, path, value)

        # extract: split composite values into sub-tokens,
        # e.g. {from: src, pattern: '^(?P<src_ip>[\d.]+):(?P<src_port>\d+)'}
        mapped_src = set()
        for ex in mapping.get("extract") or []:
            val = get_dotted(tokens, ex["from"])
            if val is None:
                continue
            rx = ex.get("_re") or re.compile(ex["pattern"])
            m = rx.search(str(val))
            if m:
                mapped_src.add(ex["from"])
                tokens.update({k: v for k, v in m.groupdict().items() if v is not None})

        # field renames (dotted source paths into nested JSON are supported)
        for src_field, dest in fields.items():
            value = get_dotted(tokens, src_field)
            if value is None or value == "" or value == "-":
                continue
            mapped_src.add(src_field)
            for dest_path in (dest if isinstance(dest, list) else [dest]):
                set_dotted(ev, dest_path, value)

        # value translation, keyed by source field (case-insensitive)
        for src_field, valmap in (mapping.get("values") or {}).items():
            dest = fields.get(src_field, src_field)
            for dest_path in (dest if isinstance(dest, list) else [dest]):
                current = get_dotted(ev, dest_path)
                if current is None:
                    continue
                lookup = {str(k).lower(): v for k, v in valmap.items()}
                key = str(current).lower()
                if key in lookup:
                    set_dotted(ev, dest_path, lookup[key])

        # lookups: derive an OCSF attribute from a source field through a table,
        # e.g. {from: action, to: activity_name, map: {deny: Refuse}, default: Traffic}
        for lk in mapping.get("lookups") or []:
            raw_val = get_dotted(tokens, lk["from"])
            if raw_val is None and "default" not in lk:
                continue
            table = {str(k).lower(): v for k, v in (lk.get("map") or {}).items()}
            result = table.get(str(raw_val).lower(), lk.get("default"))
            if result is not None:
                mapped_src.add(lk["from"])
                set_dotted(ev, lk["to"], result)

        # per-variant overrides from regex `patterns:` entries
        for path, value in static_override.items():
            set_dotted(ev, path, value)

        # explicit type casts, e.g. {traffic.bytes_in: int}
        for path, typ in (mapping.get("types") or {}).items():
            val = get_dotted(ev, path)
            if val is None:
                continue
            try:
                set_dotted(ev, path, {"int": int, "float": float, "str": str}[typ](val))
            except (ValueError, TypeError, KeyError):
                pass

        # classification: class is declared, activity may come from data
        class_uid = int(ev.pop("class_uid", ocsf_spec.get("class_uid", 0)))
        activity = ev.pop("activity_id", None)
        if activity is None:
            activity = ev.pop("activity_name", None) or ocsf_spec.get("activity_id",
                                                                      ocsf_spec.get("activity"))
        else:
            ev.pop("activity_name", None)
        ocsf.apply_classification(ev, class_uid, ocsf.activity_id_from_name(class_uid, activity))
        if "severity_id" not in ev:
            ev["severity_id"] = ocsf_spec.get("severity_id", 1)

        # time: always epoch-ms + ISO in the output; original string preserved
        event_dt, original = self._event_time(tokens, mapping.get("timestamp") or {}, envelope)
        if event_dt is None:
            event_dt = datetime.fromisoformat(ingest_time_iso)
        ev["time"] = int(event_dt.timestamp() * 1000)
        ev["time_dt"] = event_dt.astimezone(timezone.utc).isoformat()

        # reporting device from the syslog envelope
        if envelope and envelope.get("hostname"):
            ev.setdefault("device", {}).setdefault("hostname", envelope["hostname"])

        ocsf.derive(ev)

        # anything not explicitly mapped is preserved, not discarded
        consumed = set(mapped_src)
        ts_src = (mapping.get("timestamp") or {}).get("source")
        consumed.update(ts_src if isinstance(ts_src, list) else [ts_src] if ts_src else [])
        prefixes = tuple(m + "." for m in consumed)
        unmapped = {k: v for k, v in flatten(tokens).items()
                    if k not in consumed and not k.startswith(prefixes)}
        if unmapped:
            ev["unmapped"] = unmapped

        raw_info = raw_info or {}
        # mappings may target metadata.* (e.g. CEF header vendor/product) --
        # merged in, but never allowed to overwrite the traceability keys below
        mapped_meta = ev.pop("metadata", None) or {}
        product = {**(parser_config.get("product") or {}), **(mapped_meta.pop("product", None) or {})}
        meta = {
            **mapped_meta,
            "uid": event_id,
            "version": cfg.OCSF_VERSION,
            "product": product,
            "source_id": parser_config["source_id"],
            "log_name": parser_config.get("log_name", parser_config["source_id"]),
            "parser": {"id": parser_config["source_id"],
                       "version": str(parser_config.get("version", "v1"))},
            "raw_sha256": raw_info.get("sha256"),
            "raw_ref": raw_info.get("raw_ref"),
            "raw_size": raw_info.get("size_bytes"),
            "ingest_channel": channel,
            "ingest_time": ingest_time_iso,
            "ulpf_schema_version": cfg.ULPF_SCHEMA_VERSION,
        }
        if original is not None:
            meta["original_time"] = str(original)
        env_view = envelope_mod.public_view(envelope)
        if env_view:
            meta["envelope"] = env_view
        ev["metadata"] = {k: v for k, v in meta.items() if v is not None}

        enrich.enrich(ev)
        return ev

    @classmethod
    def _event_time(cls, tokens: dict, rule: dict, envelope: dict):
        """Returns (aware datetime or None, original string or None).
        `format` may be a list (first that parses wins); `fallback: envelope`
        uses the syslog header time when the payload time is missing/unparseable."""
        dt, original = cls._event_time_once(tokens, rule, envelope)
        if dt is None and rule.get("fallback") == "envelope" and envelope and envelope.get("time"):
            return envelope["time"], original or envelope.get("timestamp")
        return dt, original

    @staticmethod
    def _event_time_once(tokens: dict, rule: dict, envelope: dict):
        source = rule.get("source", "envelope" if envelope and envelope.get("time") else None)
        if not source or source == "ingest_time":
            return None, None
        if source == "envelope":
            if envelope and envelope.get("time"):
                return envelope["time"], envelope.get("timestamp")
            return None, None
        if isinstance(source, list):
            parts = [get_dotted(tokens, s) for s in source]
            raw_val = " ".join(str(p) for p in parts if p is not None) if all(parts) else None
        else:
            raw_val = get_dotted(tokens, source)
        if raw_val in (None, ""):
            return None, None
        formats = rule.get("format", "iso8601")
        tz = _parse_tz(rule.get("timezone"))
        for fmt in (formats if isinstance(formats, list) else [formats]):
            dt = _parse_time_value(raw_val, fmt, tz)
            if dt is not None:
                return dt, raw_val
        return None, raw_val

    # ---------- full per-event run ----------
    def process(self, raw_text: str, channel: str, event_id: str, ingest_time_iso: str,
                raw_info: dict = None, validate: bool = True):
        """Runs every stage. Returns (ocsf_event, parser_config) or raises ParseError.
        If several configs fingerprint-match, the first one that parses AND
        validates wins; otherwise the most specific failure is reported."""
        cands = self.candidates(raw_text, channel)
        if not cands:
            raise ParseError("no_parser_match", "no fingerprint matched")
        envelope, payload = envelope_mod.parse(raw_text)
        first_error = None
        for c in cands:
            try:
                tokens = self.tokenize(raw_text, c, payload=payload)
                ev = self.normalize(tokens, c, event_id, ingest_time_iso, envelope=envelope,
                                    raw_info=raw_info, channel=channel)
            except ParseError as e:
                first_error = first_error or e
                continue
            except Exception as e:  # noqa: BLE001 - a buggy mapping must never crash ingestion
                first_error = first_error or ParseError("normalize_error", str(e), c["source_id"])
                continue
            if validate and cfg.SCHEMA_ENFORCE:
                errors = ocsf.validate(ev)
                if errors:
                    first_error = first_error or ParseError(
                        "schema_violation", "; ".join(errors[:3]), c["source_id"])
                    continue
            return ev, c
        raise first_error


def utc_now_iso() -> str:
    return ids.utc_now_iso()
