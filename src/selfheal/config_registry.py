"""
ConfigRegistry - Scans and indexes parser configurations for the self-heal feature.

This module provides a ConfigRegistry class that:
- Scans all YAML parser configs in src/parser/configs/ (excluding 'proposed' subdirectory)
- Indexes each parser with source_id, channel, and mapping fields
- Provides methods to query field mappings, find similar fingerprints, and detect duplicates
- Uses caching for performance
"""
import importlib.util
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from .models import (
    FingerprintConfig,
    MappingConfig,
    ParserConfig,
    TimestampConfig,
    TokenizeConfig,
)

# Import config directly to avoid package shadowing issue (src.config vs src/config/)
# config.py is at src/config.py relative to project root
_project_root = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("config", _project_root / "src" / "config.py")
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)

logger = logging.getLogger(__name__)


class ConfigRegistry:
    """
    Registry for parser configurations.
    
    Scans and indexes all YAML parser configs, providing methods to query
    field mappings, find similar fingerprints, and detect duplicate mappings.
    
    Attributes:
        _parsers: Dictionary mapping source_id to ParserConfig
        _field_index: Dictionary mapping source field names to list of source_ids
        _channel_index: Set of supported channel names
        _fingerprint_index: List of (source_id, fingerprint_pattern) tuples
        _cache_valid: Whether the cache is valid
    """
    
    def __init__(self):
        """Initialize the ConfigRegistry."""
        self._parsers: Dict[str, ParserConfig] = {}
        self._field_index: Dict[str, List[str]] = {}
        self._channel_index: Set[str] = set()
        self._fingerprint_index: List[tuple] = []
        self._cache_valid: bool = False
        self._config_dir: Path = config.PARSER_CONFIG_DIR
        self._proposed_dir: Path = config.PARSER_PROPOSED_DIR
    
    def scan_configs(self) -> Dict[str, ParserConfig]:
        """
        Scan all YAML parser configs in PARSER_CONFIG_DIR.
        
        Excludes files in the 'proposed' subdirectory.
        
        Returns:
            Dictionary mapping source_id to ParserConfig
            
        Raises:
            None - Errors are logged and invalid configs are skipped
        """
        self._parsers = {}
        self._field_index = {}
        self._channel_index = set()
        self._fingerprint_index = []
        
        # Scan directory for YAML files
        if not self._config_dir.exists():
            logger.warning(f"Parser config directory does not exist: {self._config_dir}")
            return self._parsers
        
        # Find all YAML files, excluding the 'proposed' subdirectory
        yaml_files: List[Path] = []
        for yaml_file in self._config_dir.rglob("*.yaml"):
            # Skip files in proposed subdirectory
            try:
                yaml_file.relative_to(self._proposed_dir)
                logger.debug(f"Skipping proposed config: {yaml_file}")
                continue
            except ValueError:
                # File is not in proposed directory, include it
                yaml_files.append(yaml_file)
        
        # Parse each YAML file
        for yaml_file in yaml_files:
            try:
                parser_config = self._parse_yaml_config(yaml_file)
                if parser_config:
                    self._parsers[parser_config.source_id] = parser_config
                    self._index_parser(parser_config)
                    logger.info(f"Loaded parser config: {parser_config.source_id}")
            except Exception as e:
                logger.warning(f"Failed to parse config {yaml_file}: {e}")
        
        self._cache_valid = True
        logger.info(f"Scanned {len(self._parsers)} parser configs")
        return self._parsers
    
    def _parse_yaml_config(self, yaml_path: Path) -> Optional[ParserConfig]:
        """
        Parse a single YAML parser configuration file.
        
        Args:
            yaml_path: Path to the YAML file
            
        Returns:
            ParserConfig if successful, None if invalid
        """
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                logger.warning(f"Empty config file: {yaml_path}")
                return None
            
            # Parse fingerprint config
            fingerprint_data = data.get("fingerprint", {})
            fingerprint = FingerprintConfig(
                type=fingerprint_data.get("type", "contains"),
                pattern=fingerprint_data.get("pattern", ""),
                key=fingerprint_data.get("key")
            )
            
            # Parse tokenize config
            tokenize_data = data.get("tokenize", {})
            tokenize = TokenizeConfig(
                type=tokenize_data.get("type", "regex"),
                pattern=tokenize_data.get("pattern"),
                pair_sep=tokenize_data.get("pair_sep"),
                kv_sep=tokenize_data.get("kv_sep")
            )
            
            # Parse mapping config
            mapping_data = data.get("mapping", {})
            timestamp_data = mapping_data.get("timestamp", {})
            if isinstance(timestamp_data, dict):
                timestamp = TimestampConfig(
                    source=timestamp_data.get("source", "ingest_time"),
                    format=timestamp_data.get("format")
                )
            else:
                timestamp = TimestampConfig(source=str(timestamp_data) if timestamp_data else "ingest_time")
            
            mapping = MappingConfig(
                fields=mapping_data.get("fields", {}),
                values=mapping_data.get("values", {}),
                timestamp=timestamp
            )
            
            # Create ParserConfig
            return ParserConfig(
                source_id=data.get("source_id", ""),
                version=data.get("version", "v1"),
                channel=data.get("channel", ""),
                fingerprint=fingerprint,
                tokenize=tokenize,
                mapping=mapping,
                file_path=yaml_path
            )
            
        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML in {yaml_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {yaml_path}: {e}")
            return None
    
    def _index_parser(self, parser: ParserConfig) -> None:
        """
        Index a parser configuration for fast lookups.
        
        Args:
            parser: ParserConfig to index
        """
        # Index channel
        if parser.channel:
            self._channel_index.add(parser.channel)
        
        # Index field mappings
        for source_field in parser.mapping.fields.keys():
            if source_field not in self._field_index:
                self._field_index[source_field] = []
            if parser.source_id not in self._field_index[source_field]:
                self._field_index[source_field].append(parser.source_id)
        
        # Index fingerprint for similarity search
        if parser.fingerprint and parser.fingerprint.pattern:
            self._fingerprint_index.append((
                parser.source_id,
                parser.fingerprint.type,
                parser.fingerprint.pattern,
                parser.fingerprint.key
            ))
    
    def get_field_mapping(self, field: str) -> List[ParserConfig]:
        """
        Find all parsers that map a specific source field.
        
        Args:
            field: Source field name to look up
            
        Returns:
            List of ParserConfig objects that map this field
        """
        if not self._cache_valid:
            self.scan_configs()
        
        source_ids = self._field_index.get(field, [])
        return [self._parsers[sid] for sid in source_ids if sid in self._parsers]
    
    def find_similar_fingerprint(self, pattern: str) -> List[ParserConfig]:
        """
        Find parsers with similar fingerprint patterns.
        
        Performs substring matching on fingerprint patterns to find
        parsers that might handle similar log formats.
        
        Args:
            pattern: Fingerprint pattern to search for
            
        Returns:
            List of ParserConfig objects with similar patterns
        """
        if not self._cache_valid:
            self.scan_configs()
        
        if not pattern:
            return []
        
        similar_parsers: List[ParserConfig] = []
        pattern_lower = pattern.lower()
        
        for source_id, fp_type, fp_pattern, fp_key in self._fingerprint_index:
            # Check for substring match
            if pattern_lower in fp_pattern.lower():
                if source_id in self._parsers:
                    similar_parsers.append(self._parsers[source_id])
                continue
            
            # Check for regex similarity (simple word overlap)
            if fp_pattern:
                fp_words = set(re.findall(r'\w+', fp_pattern.lower()))
                pattern_words = set(re.findall(r'\w+', pattern_lower))
                overlap = fp_words & pattern_words
                # If significant word overlap, consider it similar
                if len(overlap) >= 2 and source_id in self._parsers:
                    if self._parsers[source_id] not in similar_parsers:
                        similar_parsers.append(self._parsers[source_id])
        
        return similar_parsers
    
    def get_supported_channels(self) -> List[str]:
        """
        Get list of all supported channel names.
        
        Returns:
            List of channel identifiers
        """
        if not self._cache_valid:
            self.scan_configs()
        
        return sorted(list(self._channel_index))
    
    def get_duplicate_warnings(self, new_mapping: Dict[str, str]) -> List[str]:
        """
        Check for duplicate field mappings in existing parsers.
        
        Compares a new field mapping dictionary against all existing
        parser mappings and returns warnings for any duplicate fields.
        
        Args:
            new_mapping: Dictionary of source field -> OCSF path mappings
            
        Returns:
            List of warning messages for duplicate mappings
        """
        if not self._cache_valid:
            self.scan_configs()
        
        warnings: List[str] = []
        new_fields = set(new_mapping.keys())
        
        for source_id, parser in self._parsers.items():
            existing_fields = set(parser.mapping.fields.keys())
            overlap = new_fields & existing_fields
            
            for field in overlap:
                new_ocsf = new_mapping[field]
                existing_ocsf = parser.mapping.fields.get(field)
                if new_ocsf == existing_ocsf:
                    warnings.append(
                        f"Field '{field}' already mapped to '{existing_ocsf}' "
                        f"in parser '{source_id}'"
                    )
                else:
                    warnings.append(
                        f"Field '{field}' mapped to different OCSF paths: "
                        f"'{new_ocsf}' (new) vs '{existing_ocsf}' (existing in '{source_id}')"
                    )
        
        return warnings
    
    def get_parser(self, source_id: str) -> Optional[ParserConfig]:
        """
        Get a parser configuration by source_id.
        
        Args:
            source_id: The source ID to look up
            
        Returns:
            ParserConfig if found, None otherwise
        """
        if not self._cache_valid:
            self.scan_configs()
        
        return self._parsers.get(source_id)
    
    def get_all_parsers(self) -> Dict[str, ParserConfig]:
        """
        Get all registered parsers.
        
        Returns:
            Dictionary of source_id -> ParserConfig
        """
        if not self._cache_valid:
            self.scan_configs()
        
        return self._parsers.copy()
    
    def invalidate_cache(self) -> None:
        """Invalidate the cache and force a rescan on next access."""
        self._cache_valid = False
        self._parsers = {}
        self._field_index = {}
        self._channel_index = set()
        self._fingerprint_index = []


# Module-level singleton for convenience
_registry: Optional[ConfigRegistry] = None


def get_registry() -> ConfigRegistry:
    """
    Get the singleton ConfigRegistry instance.
    
    Returns:
        ConfigRegistry singleton
    """
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


def scan_all_configs() -> Dict[str, ParserConfig]:
    """
    Convenience function to scan all configs.
    
    Returns:
        Dictionary of source_id -> ParserConfig
    """
    return get_registry().scan_configs()