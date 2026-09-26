"""
The ULPF common event taxonomy -- a strict subset of OCSF (Open Cybersecurity
Schema Framework) 1.3.

Parser configs only declare *what* an event is (class + activity) and map
vendor fields onto OCSF attribute paths. Everything derivable is derived here,
once, for every vendor, so the output is consistent no matter who wrote the
parser config:

    class_uid + activity_id  -> class_name, category_uid/name, type_uid, activity_name
    severity_id              -> severity
    disposition (string)     -> disposition_id, action, action_id
    protocol_name <-> protocol_num
"""
import json
from functools import lru_cache

from src import config

CATEGORIES = {
    0: "Uncategorized",
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
}

# class_uid -> (class_name, category_uid, {activity_id: activity_name})
CLASSES = {
    0: ("Base Event", 0, {0: "Unknown", 99: "Other"}),
    1007: ("Process Activity", 1, {0: "Unknown", 1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 99: "Other"}),
    2004: ("Detection Finding", 2, {0: "Unknown", 1: "Create", 2: "Update", 3: "Close", 99: "Other"}),
    3002: ("Authentication", 3, {0: "Unknown", 1: "Logon", 2: "Logoff", 3: "Authentication Ticket",
                                 4: "Service Ticket Request", 99: "Other"}),
    4001: ("Network Activity", 4, {0: "Unknown", 1: "Open", 2: "Close", 3: "Reset", 4: "Fail",
                                   5: "Refuse", 6: "Traffic", 99: "Other"}),
    4002: ("HTTP Activity", 4, {0: "Unknown", 1: "Connect", 2: "Delete", 3: "Get", 4: "Head",
                                5: "Options", 6: "Post", 7: "Put", 8: "Trace", 99: "Other"}),
    4003: ("DNS Activity", 4, {0: "Unknown", 1: "Query", 2: "Response", 6: "Traffic", 99: "Other"}),
}

SEVERITY = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High",
            5: "Critical", 6: "Fatal", 99: "Other"}

DISPOSITION = {0: "Unknown", 1: "Allowed", 2: "Blocked", 3: "Quarantined", 4: "Isolated",
               5: "Deleted", 6: "Dropped", 7: "Custom Action", 8: "Approved", 9: "Restored",
               10: "Exonerated", 15: "Detected", 16: "No Action", 17: "Logged", 99: "Other"}
_DISPOSITION_BY_NAME = {v.lower(): k for k, v in DISPOSITION.items()}

ACTION = {0: "Unknown", 1: "Allowed", 2: "Denied", 99: "Other"}
_DISPOSITION_TO_ACTION = {1: 1, 8: 1, 16: 1, 17: 1, 15: 1, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2}

PROTOCOL_NUM = {"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51,
                "icmpv6": 58, "sctp": 132}
PROTOCOL_NAME = {v: k for k, v in PROTOCOL_NUM.items()}

DIRECTION = {0: "Unknown", 1: "Inbound", 2: "Outbound", 3: "Lateral", 99: "Other"}


def activity_id_from_name(class_uid: int, name) -> int:
    if name is None:
        return 0
    if isinstance(name, int) or (isinstance(name, str) and name.isdigit()):
        return int(name)
    activities = CLASSES.get(class_uid, CLASSES[0])[2]
    for aid, aname in activities.items():
        if aname.lower() == str(name).lower():
            return aid
    return 99


def apply_classification(ev: dict, class_uid: int, activity_id: int):
    class_name, category_uid, activities = CLASSES.get(class_uid, CLASSES[0])
    if class_uid not in CLASSES:
        class_uid = 0
    if activity_id not in activities:
        activity_id = 99
    ev["class_uid"] = class_uid
    ev["class_name"] = class_name
    ev["category_uid"] = category_uid
    ev["category_name"] = CATEGORIES[category_uid]
    ev["activity_id"] = activity_id
    ev["activity_name"] = activities[activity_id]
    ev["type_uid"] = class_uid * 100 + activity_id
    ev["type_name"] = f"{class_name}: {activities[activity_id]}"


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def derive(ev: dict):
    """Fill every OCSF sibling attribute that can be derived from another."""
    # severity
    sev = _to_int(ev.get("severity_id"))
    ev["severity_id"] = sev if sev in SEVERITY else (1 if sev is None else 99)
    ev["severity"] = SEVERITY[ev["severity_id"]]

    # disposition / action
    if "disposition" in ev and "disposition_id" not in ev:
        ev["disposition_id"] = _DISPOSITION_BY_NAME.get(str(ev["disposition"]).lower(), 99)
    if "disposition_id" in ev:
        did = _to_int(ev["disposition_id"])
        ev["disposition_id"] = did if did in DISPOSITION else 99
        ev["disposition"] = DISPOSITION[ev["disposition_id"]] if ev["disposition_id"] != 99 \
            else str(ev.get("disposition", "Other"))
        if "action_id" not in ev:
            ev["action_id"] = _DISPOSITION_TO_ACTION.get(ev["disposition_id"], 0)
    if "action_id" in ev:
        aid = _to_int(ev["action_id"])
        ev["action_id"] = aid if aid in ACTION else 99
        ev["action"] = ACTION[ev["action_id"]]

    # protocol name <-> number
    conn = ev.get("connection_info")
    if isinstance(conn, dict):
        name = conn.get("protocol_name")
        num = _to_int(conn.get("protocol_num"))
        if name is not None:
            name = str(name).lower()
            if name.isdigit():
                num, name = int(name), PROTOCOL_NAME.get(int(name), name)
            conn["protocol_name"] = name
        if num is not None:
            conn["protocol_num"] = num
            conn.setdefault("protocol_name", PROTOCOL_NAME.get(num, str(num)))
        elif name in PROTOCOL_NUM:
            conn["protocol_num"] = PROTOCOL_NUM[name]

    # endpoint ports must be integers
    for side in ("src_endpoint", "dst_endpoint"):
        ep = ev.get(side)
        if isinstance(ep, dict) and "port" in ep:
            port = _to_int(ep["port"])
            if port is None:
                ep.pop("port")
            else:
                ep["port"] = port

    # HTTP status code must be an integer
    resp = ev.get("http_response")
    if isinstance(resp, dict) and "code" in resp:
        code = _to_int(resp["code"])
        if code is None:
            resp.pop("code")
        else:
            resp["code"] = code


@lru_cache(maxsize=1)
def _validator():
    import jsonschema
    with open(config.SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    cls = jsonschema.validators.validator_for(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


_UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


@lru_cache(maxsize=1)
def _fast_validator():
    """Schema compiled to Python code once -- the hot path costs a few microseconds."""
    import fastjsonschema
    with open(config.SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    return fastjsonschema.compile(schema, formats={"uuid": _UUID_RE})


def validate(ev: dict) -> list:
    """Returns a list of human-readable schema violations (empty == valid).
    Fast compiled check first; the slower, descriptive validator only runs on failures."""
    import fastjsonschema
    try:
        _fast_validator()(ev)
        return []
    except fastjsonschema.JsonSchemaValueException:
        pass
    errors = []
    for err in _validator().iter_errors(ev):
        path = ".".join(str(p) for p in err.absolute_path) or "<root>"
        if err.validator in ("anyOf", "oneOf", "allOf"):
            reqs = [sch.get("required") for sch in err.validator_value if isinstance(sch, dict)]
            msg = ("needs one of " + " / ".join(",".join(r) for r in reqs if r)) if any(reqs)                 else f"value {str(err.instance)[:60]!r} does not match the expected format"
        else:
            msg = err.message if len(err.message) < 160 else err.message[:157] + "..."
        errors.append(f"{path}: {msg}")
    return errors
