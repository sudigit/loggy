"""
Deterministic parsing engine.

This is the piece that makes onboarding "config, not code": every source is
described by a YAML file (fingerprint + tokenize rule + field/value/timestamp
mapping table). This module is the ONE generic engine that executes whichever
config matches -- it never changes when a new source is added.

No LLM call happens anywhere in this file. That work happens once, offline,
at onboarding / self-heal time, and its *output* is one of these YAML files.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from src import config as cfg


class ParseError(Exception):
    pass


def _load_all_configs() -> list:
    configs = []
    for path in sorted(cfg.PARSER_CONFIG_DIR.glob("*.yaml")):
        with open(path) as f:
            data = yaml.safe_load(f)
            data["_path"] = str(path)
            configs.append(data)
    return configs


class ParserEngine:
    def __init__(self):
        self.reload()

    def reload(self):
        """Configs are re-read from disk on demand, so a newly promoted
        parser version goes live without restarting the pipeline."""
        self.configs = _load_all_configs()

    # ---------- Stage 0: selection ----------
    def select(self, raw_text: str, channel: str):
        """Coarse routing by channel first, then confirm with a signature
        check -- never assume a channel always carries one device/version."""
        candidates = [c for c in self.configs if c.get("channel") in (channel, None)]
        if not candidates:
            candidates = self.configs
        for c in candidates:
            if self._fingerprint_matches(raw_text, c["fingerprint"]):
                return c
        return None

    @staticmethod
    def _fingerprint_matches(raw_text: str, fp: dict) -> bool:
        ftype = fp["type"]
        if ftype == "contains":
            return fp["pattern"] in raw_text
        if ftype == "regex":
            return re.search(fp["pattern"], raw_text) is not None
        if ftype == "json_key":
            try:
                obj = json.loads(raw_text)
            except (json.JSONDecodeError, TypeError):
                return False
            return isinstance(obj, dict) and fp["key"] in obj
        raise ParseError(f"Unknown fingerprint type: {ftype}")

    # ---------- Stage A: tokenize ----------
    def tokenize(self, raw_text: str, parser_config: dict) -> dict:
        tk = parser_config["tokenize"]
        ttype = tk["type"]
        if ttype == "regex":
            m = re.search(tk["pattern"], raw_text)
            if not m:
                raise ParseError("tokenize regex did not match")
            return m.groupdict()
        if ttype == "json":
            return json.loads(raw_text)
        if ttype == "kv":
            sep = tk.get("pair_sep", " ")
            kvsep = tk.get("kv_sep", "=")
            tokens = {}
            for part in raw_text.strip().split(sep):
                if kvsep in part:
                    k, v = part.split(kvsep, 1)
                    tokens[k.strip()] = v.strip()
            return tokens
        raise ParseError(f"Unknown tokenize type: {ttype}")

    # ---------- Stage B: normalize to OCSF-subset ----------
    def normalize(self, tokens: dict, parser_config: dict, event_id: str,
                  ingest_time_iso: str) -> dict:
        mapping = parser_config["mapping"]
        ocsf = {}

        # field renames (supports dotted paths -> nested dict, e.g. src_endpoint.ip)
        for src_field, dest_path in mapping.get("fields", {}).items():
            value = self._get_dotted(tokens, src_field)
            if value is not None:
                self._set_dotted(ocsf, dest_path, value)

        # value translation (e.g. FortiGate "DROP" / pfSense "block" -> "Blocked")
        for field, valmap in mapping.get("values", {}).items():
            current = self._get_dotted(ocsf, mapping["fields"].get(field, field))
            if current in valmap:
                self._set_dotted(ocsf, mapping["fields"].get(field, field), valmap[current])

        # timestamp normalization -> always UTC ISO-8601 in the output
        ocsf["time"] = self._normalize_timestamp(tokens, mapping.get("timestamp", {}), ingest_time_iso)

        # anything not explicitly mapped is preserved, not discarded --
        # keeps this "close to lossless" even in the normalized copy
        mapped_src_fields = set(mapping.get("fields", {}).keys())
        unmapped = {k: v for k, v in tokens.items() if k not in mapped_src_fields}
        if unmapped:
            ocsf["unmapped"] = unmapped

        ocsf["metadata"] = {
            "uid": event_id,
            "product": {"vendor_name": parser_config["source_id"]},
            "parser_version": parser_config.get("version", "v1"),
        }
        return ocsf

    @staticmethod
    def _normalize_timestamp(tokens: dict, ts_rule: dict, ingest_time_iso: str) -> str:
        source = ts_rule.get("source")
        if not source or source == "ingest_time":
            # e.g. classic BSD syslog carries no year/timezone -- rather than
            # guess, we fall back to the framework's own ingest wall-clock
            # and keep the vendor's raw string in `unmapped` for reference.
            return ingest_time_iso
        raw_val = tokens.get(source)
        if raw_val is None:
            return ingest_time_iso
        fmt = ts_rule.get("format", "iso8601")
        if fmt == "epoch":
            return datetime.fromtimestamp(float(raw_val), tz=timezone.utc).isoformat()
        if fmt == "iso8601":
            try:
                dt = datetime.fromisoformat(raw_val.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                return ingest_time_iso
        return ingest_time_iso

    @staticmethod
    def _get_dotted(d: dict, path: str):
        cur = d
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    @staticmethod
    def _set_dotted(d: dict, path: str, value):
        parts = path.split(".")
        cur = d
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
