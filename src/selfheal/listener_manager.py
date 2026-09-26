"""
ListenerManager for managing lifecycle of all listeners based on .env configuration.

This module provides a unified interface to start, stop, restart, and monitor
all listeners (syslog, HTTP, file watcher) based on EnvConfig settings.
"""
import logging
import threading
from typing import Dict

from src.config_env.env_config import EnvConfig
from src.selfheal.models import ListenerStatus

# Import listener modules from src.ingestion
from src.ingestion import syslog_listener
from src.ingestion import http_api
from src.ingestion import file_watcher

logger = logging.getLogger(__name__)


class ListenerManager:
    """
    Manages lifecycle of all listeners based on .env configuration.
    
    Attributes:
        config: EnvConfig instance containing listener settings
        _listeners: Dict mapping listener names to their running thread/instance
    """
    
    def __init__(self, config: EnvConfig):
        """
        Initialize ListenerManager with environment configuration.
        
        Args:
            config: EnvConfig instance with listener settings
        """
        self.config = config
        self._listeners: Dict[str, threading.Thread] = {}
        self._listener_info: Dict[str, Dict] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        
        # Initialize listener info from config
        self._init_listener_info()
    
    def _init_listener_info(self) -> None:
        """Initialize listener info from configuration."""
        # Syslog listener info
        self._listener_info["syslog"] = {
            "enabled": self.config.SYSLOG_ENABLED,
            "port": self.config.SYSLOG_PORT,
            "channel": self.config.SYSLOG_CHANNEL
        }
        
        # HTTP listener info
        self._listener_info["http"] = {
            "enabled": self.config.HTTP_ENABLED,
            "port": self.config.HTTP_PORT
        }
        
        # File watcher info
        self._listener_info["filewatcher"] = {
            "enabled": self.config.FILEWATCHER_ENABLED,
            "path": self.config.FILEWATCHER_PATH,
            "channel": self.config.FILEWATCHER_CHANNEL,
            "poll_interval": self.config.FILEWATCHER_POLL_INTERVAL
        }
    
    def start_all(self) -> Dict[str, bool]:
        """
        Start all enabled listeners based on configuration.
        
        Returns:
            Dict mapping listener names to success status (True if started, False if failed)
        """
        results: Dict[str, bool] = {}
        
        # Start syslog if enabled
        if self.config.SYSLOG_ENABLED:
            results["syslog"] = self._start_syslog()
        
        # Start HTTP API if enabled
        if self.config.HTTP_ENABLED:
            results["http"] = self._start_http()
        
        # Start file watcher if enabled
        if self.config.FILEWATCHER_ENABLED:
            results["filewatcher"] = self._start_filewatcher()
        
        return results
    
    def _start_syslog(self) -> bool:
        """Start the syslog listener."""
        try:
            with self._lock:
                if "syslog" in self._listeners and self._listeners["syslog"].is_alive():
                    logger.warning("Syslog listener already running")
                    return True
                
                thread = syslog_listener.start_background(self.config.SYSLOG_PORT, self.config.SYSLOG_CHANNEL)
                self._listeners["syslog"] = thread
                logger.info(f"Syslog listener started on port {self.config.SYSLOG_PORT}")
                if self.config.SYSLOG_TCP_ENABLED:
                    try:
                        self._listeners["syslog_tcp"] = syslog_listener.start_tcp_background(
                            self.config.SYSLOG_TCP_PORT, f"tcp:{self.config.SYSLOG_TCP_PORT}")
                    except OSError as e:
                        logger.error(f"TCP syslog listener failed: {e}")
                return True
        except Exception as e:
            logger.error(f"Failed to start syslog listener: {e}")
            return False
    
    def _start_http(self) -> bool:
        """Start the HTTP API listener."""
        try:
            with self._lock:
                if "http" in self._listeners and self._listeners["http"].is_alive():
                    logger.warning("HTTP listener already running")
                    return True
                
                # HTTP API runs in a thread to avoid blocking
                def run_http():
                    http_api.run(self.config.HTTP_PORT)
                
                thread = threading.Thread(target=run_http, daemon=True)
                thread.start()
                self._listeners["http"] = thread
                logger.info(f"HTTP listener started on port {self.config.HTTP_PORT}")
                return True
        except Exception as e:
            logger.error(f"Failed to start HTTP listener: {e}")
            return False
    
    def _start_filewatcher(self) -> bool:
        """Start the file watcher listener."""
        try:
            from pathlib import Path
            
            with self._lock:
                if "filewatcher" in self._listeners and self._listeners["filewatcher"].is_alive():
                    logger.warning("File watcher already running")
                    return True
                
                from src import config as app_config
                path = Path(self.config.FILEWATCHER_PATH)
                if not path.is_absolute():
                    path = app_config.BASE_DIR / path
                thread = file_watcher.start_background(
                    path=path,
                    channel=self.config.FILEWATCHER_CHANNEL,
                    poll_interval=self.config.FILEWATCHER_POLL_INTERVAL
                )
                self._listeners["filewatcher"] = thread
                logger.info(f"File watcher started for {self.config.FILEWATCHER_PATH}")
                return True
        except Exception as e:
            logger.error(f"Failed to start file watcher: {e}")
            return False
    
    def stop_all(self) -> None:
        """
        Stop all running listeners.
        
        Note: Daemon threads will be terminated when the main process exits.
        For graceful shutdown, consider setting stop events for each listener.
        """
        with self._lock:
            for name, thread in self._listeners.items():
                if thread.is_alive():
                    # Daemon threads will be cleaned up automatically
                    logger.info(f"Stopping {name} listener (daemon thread)")
            
            # Clear the listeners dict
            self._listeners.clear()
            logger.info("All listeners stopped")
    
    def restart_listener(self, name: str) -> bool:
        """
        Restart a specific listener by name.
        
        Args:
            name: Listener name ('syslog', 'http', or 'filewatcher')
            
        Returns:
            True if restart was successful, False otherwise
        """
        valid_names = ["syslog", "http", "filewatcher"]
        if name not in valid_names:
            logger.error(f"Invalid listener name: {name}")
            return False
        
        # Check if enabled in config
        info = self._listener_info.get(name, {})
        if not info.get("enabled", False):
            logger.warning(f"Listener '{name}' is disabled in configuration")
            return False
        
        # Stop the listener first
        with self._lock:
            if name in self._listeners:
                del self._listeners[name]
        
        # Restart based on type
        if name == "syslog":
            return self._start_syslog()
        elif name == "http":
            return self._start_http()
        elif name == "filewatcher":
            return self._start_filewatcher()
        
        return False
    
    def get_status(self) -> Dict[str, ListenerStatus]:
        """
        Get status of all managed listeners.
        
        Returns:
            Dict mapping listener names to their ListenerStatus
        """
        status: Dict[str, ListenerStatus] = {}
        
        for name, info in self._listener_info.items():
            running = False
            error = None
            
            # Check if listener is running
            if name in self._listeners:
                running = self._listeners[name].is_alive()
            
            # Get port if applicable
            port = info.get("port")
            
            # Get channel if applicable
            channel = info.get("channel")
            
            status[name] = ListenerStatus(
                name=name,
                enabled=info.get("enabled", False),
                running=running,
                port=port,
                channel=channel,
                error=error
            )
        
        return status
    
    def is_running(self, name: str) -> bool:
        """
        Check if a specific listener is running.
        
        Args:
            name: Listener name
            
        Returns:
            True if running, False otherwise
        """
        with self._lock:
            if name in self._listeners:
                return self._listeners[name].is_alive()
            return False
    
    def get_config(self) -> EnvConfig:
        """
        Get the configuration instance.
        
        Returns:
            EnvConfig instance
        """
        return self.config