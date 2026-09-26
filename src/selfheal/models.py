"""Small data models shared by the listener manager."""
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class ListenerStatus:
    """Status information for an ingestion listener."""
    name: str
    enabled: bool
    running: bool
    port: Optional[int] = None
    channel: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
