import hashlib
import uuid
from datetime import datetime, timezone


def new_event_id() -> str:
    """Mint a framework-owned UUIDv4 for an event. Never trust a source's
    own ID as the canonical key -- IDs collide across vendors and many
    raw log lines (plain syslog) don't carry one at all."""
    return str(uuid.uuid4())


def sha256_hex(raw_bytes: bytes) -> str:
    """Integrity hash stored alongside the raw object so the framework can
    later prove the archived original was never altered (chain of custody)."""
    return hashlib.sha256(raw_bytes).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
