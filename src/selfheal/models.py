"""
Data models for the config-aware-selfheal feature.

These dataclasses represent parser configurations, proposal results,
queue statistics, and listener status for the self-healing pipeline.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TimestampConfig:
    """Timestamp configuration for parser mappings."""
    source: str  # Field name or 'ingest_time'
    format: Optional[str] = None  # epoch, iso8601, or None for ingest_time


@dataclass
class FingerprintConfig:
    """
    Fingerprint configuration for log source identification.
    
    Attributes:
        type: Detection type - 'contains', 'regex', or 'json_key'
        pattern: Pattern string for matching
        key: Optional key for json_key type
    """
    type: str
    pattern: str
    key: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'FingerprintConfig':
        """Create from dictionary for deserialization."""
        return cls(**data)


@dataclass
class TokenizeConfig:
    """
    Tokenization configuration for log parsing.
    
    Attributes:
        type: Tokenize type - 'regex', 'json', or 'kv'
        pattern: Regex pattern (for regex type)
        pair_sep: Pair separator (for kv type)
        kv_sep: Key-value separator (for kv type)
    """
    type: str
    pattern: Optional[str] = None
    pair_sep: Optional[str] = None
    kv_sep: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'TokenizeConfig':
        """Create from dictionary for deserialization."""
        return cls(**data)


@dataclass
class MappingConfig:
    """
    Field mapping configuration for log normalization.
    
    Attributes:
        fields: Dictionary mapping source field names to OCSF dotted paths
        values: Dictionary of field value mappings (e.g., disposition translations)
        timestamp: Timestamp configuration
    """
    fields: Dict[str, str] = field(default_factory=dict)
    values: Dict[str, Dict] = field(default_factory=dict)
    timestamp: TimestampConfig = field(default_factory=lambda: TimestampConfig(source="ingest_time"))

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "fields": self.fields,
            "values": self.values,
            "timestamp": asdict(self.timestamp) if isinstance(self.timestamp, TimestampConfig) else self.timestamp
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'MappingConfig':
        """Create from dictionary for deserialization."""
        timestamp_data = data.get("timestamp", {})
        if isinstance(timestamp_data, dict):
            timestamp = TimestampConfig(**timestamp_data)
        else:
            timestamp = TimestampConfig(source=str(timestamp_data) if timestamp_data else "ingest_time")
        
        return cls(
            fields=data.get("fields", {}),
            values=data.get("values", {}),
            timestamp=timestamp
        )


@dataclass
class ParserConfig:
    """
    Complete parser configuration for a log source.
    
    Attributes:
        source_id: Unique identifier for the log source
        version: Version string (e.g., 'v1')
        channel: Channel identifier (e.g., 'udp:5514', 'file:squid')
        fingerprint: Fingerprint configuration for source detection
        tokenize: Tokenization configuration for parsing
        mapping: Field mapping configuration for normalization
        file_path: Path to the parser configuration file
    """
    source_id: str
    version: str
    channel: str
    fingerprint: FingerprintConfig
    tokenize: TokenizeConfig
    mapping: MappingConfig
    file_path: Optional[Path] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "source_id": self.source_id,
            "version": self.version,
            "channel": self.channel,
            "fingerprint": self.fingerprint.to_dict() if hasattr(self.fingerprint, 'to_dict') else self.fingerprint,
            "tokenize": self.tokenize.to_dict() if hasattr(self.tokenize, 'to_dict') else self.tokenize,
            "mapping": self.mapping.to_dict() if hasattr(self.mapping, 'to_dict') else self.mapping,
            "file_path": str(self.file_path) if self.file_path else None
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ParserConfig':
        """Create from dictionary for deserialization."""
        fingerprint_data = data.get("fingerprint", {})
        if isinstance(fingerprint_data, dict):
            fingerprint = FingerprintConfig.from_dict(fingerprint_data)
        else:
            fingerprint = FingerprintConfig(type=str(fingerprint_data.get("type", "")), pattern="")

        tokenize_data = data.get("tokenize", {})
        if isinstance(tokenize_data, dict):
            tokenize = TokenizeConfig.from_dict(tokenize_data)
        else:
            tokenize = TokenizeConfig(type="regex")

        mapping_data = data.get("mapping", {})
        if isinstance(mapping_data, dict):
            mapping = MappingConfig.from_dict(mapping_data)
        else:
            mapping = MappingConfig()

        file_path = data.get("file_path")
        if file_path and isinstance(file_path, str):
            file_path = Path(file_path)

        return cls(
            source_id=data.get("source_id", ""),
            version=data.get("version", "v1"),
            channel=data.get("channel", ""),
            fingerprint=fingerprint,
            tokenize=tokenize,
            mapping=mapping,
            file_path=file_path
        )


@dataclass
class ConfigAwarenessReport:
    """
    Report containing config awareness information for a proposal.
    
    Attributes:
        similar_parsers: List of existing parsers with similar patterns
        duplicate_warnings: Warnings about duplicate field mappings
        recommendations: Suggestions for extending existing parsers
        extends_existing: Name of parser to extend, if applicable
    """
    similar_parsers: List[str] = field(default_factory=list)
    duplicate_warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    extends_existing: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'ConfigAwarenessReport':
        """Create from dictionary for deserialization."""
        return cls(**data)


@dataclass
class ProposalResult:
    """
    Result of a parser proposal generation.
    
    Attributes:
        channel: Channel identifier for the proposal
        filename: Proposed filename
        yaml: YAML content of the proposal
        generator: Source of proposal generation (e.g., 'Ollama', 'Heuristic')
        sample_count: Number of samples used for generation
        config_awareness: Configuration awareness report
    """
    channel: str
    filename: str
    yaml: str
    generator: str
    sample_count: int
    config_awareness: Optional[ConfigAwarenessReport] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "channel": self.channel,
            "filename": self.filename,
            "yaml": self.yaml,
            "generator": self.generator,
            "sample_count": self.sample_count,
            "config_awareness": self.config_awareness.to_dict() if self.config_awareness else None
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ProposalResult':
        """Create from dictionary for deserialization."""
        config_awareness_data = data.get("config_awareness")
        if config_awareness_data and isinstance(config_awareness_data, dict):
            config_awareness = ConfigAwarenessReport.from_dict(config_awareness_data)
        else:
            config_awareness = None

        return cls(
            channel=data.get("channel", ""),
            filename=data.get("filename", ""),
            yaml=data.get("yaml", ""),
            generator=data.get("generator", ""),
            sample_count=data.get("sample_count", 0),
            config_awareness=config_awareness
        )


@dataclass
class QueueStats:
    """
    Statistics about the DLQ (Dead Letter Queue).
    
    Attributes:
        pending_count: Number of pending entries in the queue
        last_process_time: Timestamp of last processing (None if never processed)
        next_process_time: Timestamp when next processing will occur
        time_until_next: Seconds until next scheduled processing
        count_until_next: Entries needed to trigger count-based processing
        should_process: Whether processing should occur now
    """
    pending_count: int
    last_process_time: Optional[datetime]
    next_process_time: datetime
    time_until_next: float
    count_until_next: int
    should_process: bool

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "pending_count": self.pending_count,
            "last_process_time": self.last_process_time.isoformat() if self.last_process_time else None,
            "next_process_time": self.next_process_time.isoformat(),
            "time_until_next": self.time_until_next,
            "count_until_next": self.count_until_next,
            "should_process": self.should_process
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'QueueStats':
        """Create from dictionary for deserialization."""
        last_process_time = data.get("last_process_time")
        if last_process_time and isinstance(last_process_time, str):
            last_process_time = datetime.fromisoformat(last_process_time)

        next_process_time = data.get("next_process_time")
        if isinstance(next_process_time, str):
            next_process_time = datetime.fromisoformat(next_process_time)

        return cls(
            pending_count=data.get("pending_count", 0),
            last_process_time=last_process_time,
            next_process_time=next_process_time or datetime.now(),
            time_until_next=data.get("time_until_next", 0.0),
            count_until_next=data.get("count_until_next", 0),
            should_process=data.get("should_process", False)
        )


@dataclass
class ListenerStatus:
    """
    Status information for a listener.
    
    Attributes:
        name: Listener name (e.g., 'syslog', 'http', 'filewatcher')
        enabled: Whether the listener is enabled in configuration
        running: Whether the listener is currently running
        port: Port number (if applicable)
        channel: Channel identifier (if applicable)
        error: Error message if listener failed to start
    """
    name: str
    enabled: bool
    running: bool
    port: Optional[int] = None
    channel: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'ListenerStatus':
        """Create from dictionary for deserialization."""
        return cls(**data)