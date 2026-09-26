"""
ULPF entrypoint.

Starts:
  - durable Redis Streams buffer + worker pool (or direct in-process fallback)
  - ingestion listeners (UDP/TCP syslog, HTTP API + console, file watcher) per .env
  - the continuous DLQ self-heal watcher (proposals only -- promotion is human-gated)

Run with:  python -m src.main
"""
import logging
import time

from src import config  # noqa: F401 - loads .env before anything reads the environment
from src.buffer import redis_buffer
from src.config_env.env_config import EnvConfig
from src.pipeline import get_engine
from src.selfheal.dlq_processor import get_processor
from src.selfheal.listener_manager import ListenerManager


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    print("=" * 64)
    print(" Universal Log Pre-processing Framework (ULPF)")
    print("=" * 64)

    engine = get_engine()
    print(f"[parsers] {len(engine.configs)} parser configs loaded: "
          + ", ".join(c["source_id"] for c in engine.configs))

    buffer_mode = redis_buffer.init_buffer()
    if buffer_mode == "redis":
        print(f"[buffer] Redis Streams durable buffer active (stream={config.STREAM_NAME})")
        redis_buffer.start_workers(config.STREAM_WORKER_COUNT)
    else:
        print("[buffer] direct synchronous mode (Redis not configured/reachable)")

    from src.core import raw_store
    print(f"[raw] raw archive backend: {raw_store.get_store_mode()}")
    print(f"[sinks] {', '.join(config.SINKS)}")

    env = EnvConfig.load_from_env()
    listener_manager = ListenerManager(env)
    results = listener_manager.start_all()
    print("\n[listeners]")
    for name, status in listener_manager.get_status().items():
        state = "running" if status.running else ("disabled" if not status.enabled else "FAILED")
        extra = f" port {status.port}" if status.port else ""
        print(f"  - {name}: {state}{extra}")
    if not all(results.values()):
        print("  (some listeners failed to start -- see log above)")

    if config.SELFHEAL_ENABLED:
        get_processor().start()
        print(f"\n[self-heal] DLQ watcher running: tick {config.DLQ_TICK_SECONDS}s, "
              f"min {config.DLQ_MIN_SAMPLES} samples, propose at {config.DLQ_COUNT_THRESHOLD} events "
              f"or after {config.DLQ_TIME_THRESHOLD}s")

    print(f"\n[console] http://localhost:{env.HTTP_PORT}/   (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[main] shutting down...")
        get_processor().stop()
        redis_buffer.stop_workers()
        listener_manager.stop_all()


if __name__ == "__main__":
    main()
