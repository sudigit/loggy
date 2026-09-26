"""
Environment Configuration for ULPF.

Loads all configuration from environment variables (ULPF_* prefix).
Provides default values when environment variables are not set.
Validates port values (1-65535).
"""
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def _get_bool(env_key: str, default: bool) -> bool:
    """Get boolean value from environment variable."""
    value = os.environ.get(env_key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


def _get_int(env_key: str, default: int, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    """Get integer value from environment variable with validation."""
    value = os.environ.get(env_key)
    if value is None:
        return default
    try:
        int_value = int(value)
        if min_val is not None and int_value < min_val:
            logger.warning(f"ULPF config: {env_key}={int_value} is below minimum {min_val}, using default {default}")
            return default
        if max_val is not None and int_value > max_val:
            logger.warning(f"ULPF config: {env_key}={int_value} is above maximum {max_val}, using default {default}")
            return default
        return int_value
    except ValueError:
        logger.warning(f"ULPF config: {env_key}={value} is not a valid integer, using default {default}")
        return default


def _get_float(env_key: str, default: float) -> float:
    """Get float value from environment variable."""
    value = os.environ.get(env_key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning(f"ULPF config: {env_key}={value} is not a valid float, using default {default}")
        return default


def _get_str(env_key: str, default: str) -> str:
    """Get string value from environment variable."""
    return os.environ.get(env_key, default)


class EnvConfig:
    """Environment-based configuration for ULPF listeners and system settings."""

    # Syslog Listener Configuration
    SYSLOG_ENABLED: bool = True
    SYSLOG_PORT: int = 5514
    SYSLOG_CHANNEL: str = "udp:5514"

    # HTTP API Listener Configuration
    HTTP_ENABLED: bool = True
    HTTP_PORT: int = 8080

    # File Watcher Configuration
    FILEWATCHER_ENABLED: bool = True
    FILEWATCHER_PATH: str = "data/incoming/squid_access.log"
    FILEWATCHER_CHANNEL: str = "file:squid"
    FILEWATCHER_POLL_INTERVAL: float = 0.5

    # DLQ Processing Thresholds
    DLQ_TIME_THRESHOLD: int = 60  # seconds
    DLQ_COUNT_THRESHOLD: int = 20

    # Self-Heal Configuration
    SELFHEAL_ENABLED: bool = True

    @classmethod
    def load_from_env(cls) -> "EnvConfig":
        """
        Load all configuration from environment variables.
        
        Returns:
            EnvConfig: New instance with values loaded from environment.
        """
        config = cls()
        
        # Syslog Listener
        config.SYSLOG_ENABLED = _get_bool("ULPF_SYSLOG_ENABLED", True)
        config.SYSLOG_PORT = _get_int("ULPF_SYSLOG_PORT", 5514, min_val=1, max_val=65535)
        config.SYSLOG_CHANNEL = _get_str("ULPF_SYSLOG_CHANNEL", "udp:5514")
        
        # HTTP API Listener
        config.HTTP_ENABLED = _get_bool("ULPF_HTTP_ENABLED", True)
        config.HTTP_PORT = _get_int("ULPF_HTTP_PORT", 8080, min_val=1, max_val=65535)
        
        # File Watcher
        config.FILEWATCHER_ENABLED = _get_bool("ULPF_FILEWATCHER_ENABLED", True)
        config.FILEWATCHER_PATH = _get_str("ULPF_FILEWATCHER_PATH", "data/incoming/squid_access.log")
        config.FILEWATCHER_CHANNEL = _get_str("ULPF_FILEWATCHER_CHANNEL", "file:squid")
        config.FILEWATCHER_POLL_INTERVAL = _get_float("ULPF_FILEWATCHER_POLL_INTERVAL", 0.5)
        
        # DLQ Thresholds
        config.DLQ_TIME_THRESHOLD = _get_int("ULPF_DLQ_TIME_THRESHOLD", 60)
        config.DLQ_COUNT_THRESHOLD = _get_int("ULPF_DLQ_COUNT_THRESHOLD", 20)
        
        # Self-Heal
        config.SELFHEAL_ENABLED = _get_bool("ULPF_SELFHEAL_ENABLED", True)
        
        return config

    @classmethod
    def get_listener_configs(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get all listener configurations for initialization.
        
        Returns:
            Dict mapping listener names to their configuration dicts.
        """
        config = cls.load_from_env()
        
        configs = {}
        
        if config.SYSLOG_ENABLED:
            configs["syslog"] = {
                "enabled": True,
                "port": config.SYSLOG_PORT,
                "channel": config.SYSLOG_CHANNEL,
                "protocol": "udp"
            }
        
        if config.HTTP_ENABLED:
            configs["http"] = {
                "enabled": True,
                "port": config.HTTP_PORT
            }
        
        if config.FILEWATCHER_ENABLED:
            configs["filewatcher"] = {
                "enabled": True,
                "path": config.FILEWATCHER_PATH,
                "channel": config.FILEWATCHER_CHANNEL,
                "poll_interval": config.FILEWATCHER_POLL_INTERVAL
            }
        
        return configs

    @classmethod
    def get_syslog_config(cls) -> Dict[str, Any]:
        """Get syslog listener configuration."""
        config = cls.load_from_env()
        return {
            "enabled": config.SYSLOG_ENABLED,
            "port": config.SYSLOG_PORT,
            "channel": config.SYSLOG_CHANNEL
        }

    @classmethod
    def get_http_config(cls) -> Dict[str, Any]:
        """Get HTTP API listener configuration."""
        config = cls.load_from_env()
        return {
            "enabled": config.HTTP_ENABLED,
            "port": config.HTTP_PORT
        }

    @classmethod
    def get_filewatcher_config(cls) -> Dict[str, Any]:
        """Get file watcher configuration."""
        config = cls.load_from_env()
        return {
            "enabled": config.FILEWATCHER_ENABLED,
            "path": config.FILEWATCHER_PATH,
            "channel": config.FILEWATCHER_CHANNEL,
            "poll_interval": config.FILEWATCHER_POLL_INTERVAL
        }

    @classmethod
    def get_dlq_config(cls) -> Dict[str, int]:
        """Get DLQ threshold configuration."""
        config = cls.load_from_env()
        return {
            "time_threshold": config.DLQ_TIME_THRESHOLD,
            "count_threshold": config.DLQ_COUNT_THRESHOLD
        }

    @classmethod
    def get_selfheal_config(cls) -> Dict[str, bool]:
        """Get self-heal configuration."""
        config = cls.load_from_env()
        return {
            "enabled": config.SELFHEAL_ENABLED
        }