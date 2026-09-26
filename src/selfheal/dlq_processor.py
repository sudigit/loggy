"""
DLQ Processor - Dual-trigger processing for the Dead Letter Queue.

This module provides a DLQProcessor class that processes failed log entries
when either a time threshold OR a count threshold is met (whichever comes first).

Default thresholds:
- Time: 60 seconds (1 minute)
- Count: 20 events
"""
import importlib.util
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Import config directly to avoid package shadowing issue (src.config vs src/config/)
# config.py is at src/config.py relative to project root
_project_root = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("config", _project_root / "src" / "config.py")
_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_config)

from src.dlq import store as dlq_store
from .config_registry import get_registry
from .models import QueueStats

logger = logging.getLogger(__name__)

# File path for persisting last_process_time
_STATE_FILE = _config.DATA_DIR / "dlq_processor_state.json"


class ProcessingResult:
    """Result of a DLQ processing operation."""
    
    def __init__(
        self,
        channels_processed: int,
        entries_processed: int,
        proposals_generated: int,
        errors: list = None
    ):
        self.channels_processed = channels_processed
        self.entries_processed = entries_processed
        self.proposals_generated = proposals_generated
        self.errors = errors or []
    
    def to_dict(self) -> dict:
        return {
            "channels_processed": self.channels_processed,
            "entries_processed": self.entries_processed,
            "proposals_generated": self.proposals_generated,
            "errors": self.errors
        }


class DLQProcessor:
    """
    Dual-trigger DLQ processor.
    
    Processes pending DLQ entries when either:
    - Time threshold: now() - last_process_time >= time_threshold
    - Count threshold: pending_count >= count_threshold
    
    Attributes:
        time_threshold_sec: Seconds between processing cycles (default: 60)
        count_threshold: Number of pending entries to trigger processing (default: 20)
    """
    
    def __init__(
        self,
        time_threshold_sec: int = 60,
        count_threshold: int = 20,
        state_file: Optional[Path] = None
    ):
        """
        Initialize the DLQProcessor with configurable thresholds.
        
        Args:
            time_threshold_sec: Time threshold in seconds (default: 60)
            count_threshold: Count threshold for pending entries (default: 20)
            state_file: Optional custom path for state persistence
        """
        self.time_threshold_sec = time_threshold_sec
        self.count_threshold = count_threshold
        self._state_file = state_file or _STATE_FILE
        self._lock = threading.Lock()
        
        # Load or initialize state
        self._last_process_time: Optional[datetime] = self._load_last_process_time()
        
        # Registry for config-aware proposal generation
        self._config_registry = get_registry()
        
        logger.info(
            f"DLQProcessor initialized: time_threshold={time_threshold_sec}s, "
            f"count_threshold={count_threshold}"
        )
    
    def _load_last_process_time(self) -> Optional[datetime]:
        """
        Load last_process_time from state file.
        
        Returns:
            datetime of last processing, or None if never processed
        """
        try:
            if self._state_file.exists():
                with open(self._state_file, 'r') as f:
                    data = json.load(f)
                if data.get("last_process_time"):
                    return datetime.fromisoformat(data["last_process_time"])
        except Exception as e:
            logger.warning(f"Failed to load state file: {e}")
        return None
    
    def _save_last_process_time(self) -> None:
        """Save last_process_time to state file."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "last_process_time": self._last_process_time.isoformat() 
                    if self._last_process_time else None
            }
            with open(self._state_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save state file: {e}")
    
    def _get_pending_count(self) -> int:
        """
        Get the current count of pending DLQ entries.
        
        Returns:
            Number of pending entries across all channels
        """
        grouped = dlq_store.pending_grouped_by_channel()
        return sum(len(entries) for entries in grouped.values())
    
    def should_process(self) -> bool:
        """
        Determine if processing should occur now.
        
        Returns True if EITHER:
        - Time threshold is met: now() - last_process_time >= time_threshold
        - Count threshold is met: pending_count >= count_threshold
        
        Returns:
            True if either threshold is met, False otherwise
        """
        with self._lock:
            # Get current pending count
            pending_count = self._get_pending_count()
            
            # Check count threshold
            count_triggered = pending_count >= self.count_threshold
            
            # Check time threshold
            time_triggered = False
            if self._last_process_time is None:
                # Never processed, time threshold is met
                time_triggered = True
            else:
                elapsed = datetime.now(timezone.utc) - self._last_process_time
                time_triggered = elapsed.total_seconds() >= self.time_threshold_sec
            
            # OR logic: process if either trigger is met
            should_process = time_triggered or count_triggered
            
            logger.debug(
                f"should_process check: count_triggered={count_triggered} "
                f"(pending={pending_count}, threshold={self.count_threshold}), "
                f"time_triggered={time_triggered} "
                f"(elapsed={self._get_elapsed_seconds():.1f}s, threshold={self.time_threshold_sec}s)"
            )
            
            return should_process
    
    def _get_elapsed_seconds(self) -> float:
        """Get seconds since last processing."""
        if self._last_process_time is None:
            return float('inf')
        return (datetime.now(timezone.utc) - self._last_process_time).total_seconds()
    
    def _get_time_until_next(self) -> float:
        """Get seconds until time threshold is met."""
        if self._last_process_time is None:
            return 0.0
        elapsed = self._get_elapsed_seconds()
        return max(0.0, self.time_threshold_sec - elapsed)
    
    def _get_count_until_next(self) -> int:
        """Get count needed to trigger count threshold."""
        pending = self._get_pending_count()
        return max(0, self.count_threshold - pending)
    
    def get_next_process_time(self) -> datetime:
        """
        Calculate the next processing time based on earliest triggering threshold.
        
        Returns:
            datetime of the next processing based on which threshold triggers first
        """
        now = datetime.now(timezone.utc)
        
        time_until = self._get_time_until_next()
        
        # If time threshold is 0 (never processed), return now
        if time_until <= 0:
            return now
        
        # Next process time is time_threshold seconds from last_process_time
        if self._last_process_time:
            next_time = self._last_process_time + timedelta(seconds=self.time_threshold_sec)
        else:
            # If never processed, next time is now
            next_time = now
        
        # Ensure next_time is in the future
        if next_time <= now:
            next_time = now + timedelta(seconds=time_until)
        
        return next_time
    
    def get_current_queue_stats(self) -> QueueStats:
        """
        Get current DLQ state for monitoring.
        
        Returns:
            QueueStats object with current queue statistics
        """
        pending_count = self._get_pending_count()
        now = datetime.now(timezone.utc)
        
        # Calculate values
        should_process = self.should_process()
        next_process_time = self.get_next_process_time()
        time_until_next = self._get_time_until_next()
        count_until_next = self._get_count_until_next()
        
        return QueueStats(
            pending_count=pending_count,
            last_process_time=self._last_process_time,
            next_process_time=next_process_time,
            time_until_next=time_until_next,
            count_until_next=count_until_next,
            should_process=should_process
        )
    
    def process_pending(self) -> ProcessingResult:
        """
        Process all pending DLQ entries.
        
        Generates enhanced proposals using ConfigRegistry for each channel
        with pending entries.
        
        Returns:
            ProcessingResult with processing statistics
        """
        if not self.should_process():
            logger.debug("Processing skipped - thresholds not met")
            return ProcessingResult(
                channels_processed=0,
                entries_processed=0,
                proposals_generated=0,
                errors=["Thresholds not met"]
            )
        
        logger.info("Starting DLQ processing cycle")
        
        grouped = dlq_store.pending_grouped_by_channel()
        channels_processed = 0
        entries_processed = 0
        proposals_generated = 0
        errors = []
        
        # Ensure config registry is loaded
        self._config_registry.scan_configs()
        
        # Import service for proposal generation
        from . import service
        
        for channel, entries in grouped.items():
            try:
                logger.info(f"Processing channel: {channel} ({len(entries)} entries)")
                
                # Generate proposal using the enhanced service
                result = service.generate_proposal_for_channel(channel)
                
                if result:
                    proposals_generated += 1
                    entries_processed += len(entries)
                    channels_processed += 1
                    
                    # Mark entries as processed (we mark them as 'processed' not 'promoted')
                    # The service will mark as 'promoted' if promotion succeeds
                    entry_ids = [e["id"] for e in entries]
                    dlq_store.mark_status(entry_ids, status="processing")
                    
                logger.info(f"Generated proposal for channel {channel}")
                
            except Exception as e:
                error_msg = f"Failed to process channel {channel}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        # Update last process time
        with self._lock:
            self._last_process_time = datetime.now(timezone.utc)
            self._save_last_process_time()
        
        logger.info(
            f"DLQ processing complete: {channels_processed} channels, "
            f"{entries_processed} entries, {proposals_generated} proposals"
        )
        
        return ProcessingResult(
            channels_processed=channels_processed,
            entries_processed=entries_processed,
            proposals_generated=proposals_generated,
            errors=errors
        )
    
    def reset_state(self) -> None:
        """Reset the processor state (for testing)."""
        with self._lock:
            self._last_process_time = None
            if self._state_file.exists():
                self._state_file.unlink()
            logger.info("DLQProcessor state reset")


# Module-level singleton
_processor: Optional[DLQProcessor] = None


def get_processor(
    time_threshold_sec: int = 60,
    count_threshold: int = 20
) -> DLQProcessor:
    """
    Get the singleton DLQProcessor instance.
    
    Args:
        time_threshold_sec: Time threshold in seconds (default: 60)
        count_threshold: Count threshold for pending entries (default: 20)
    
    Returns:
        DLQProcessor singleton
    """
    global _processor
    if _processor is None:
        _processor = DLQProcessor(
            time_threshold_sec=time_threshold_sec,
            count_threshold=count_threshold
        )
    return _processor