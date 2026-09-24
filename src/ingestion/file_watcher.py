"""
Polls a log file for new lines and feeds each one into the pipeline.
Represents the agentless-pull case: some perimeter devices (or their
storage exports) only ever write to a local file / mounted share, never
push over the network.
"""
import threading
import time

from src import config
from src.pipeline import process_event


def _watch(path, channel: str, poll_interval: float):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    print(f"[file_watcher] tailing {path} (channel={channel})")
    with open(path, "r") as f:
        f.seek(0, 2)  # start at end -- only pick up new lines from now on
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                process_event(line.encode("utf-8"), channel=channel)
            except Exception as e:  # noqa: BLE001
                print(f"[file_watcher] error processing line: {e}")


def start_background(path=None, channel: str = "file:squid", poll_interval: float = 0.5):
    path = path or config.SQUID_LOG_FILE
    t = threading.Thread(target=_watch, args=(path, channel, poll_interval), daemon=True)
    t.start()
    return t
