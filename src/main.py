"""
ULPF prototype entrypoint.

Starts:
  - Durable Redis Stream buffer / worker pool (or direct fallback)
  - ListenerManager - manages syslog, HTTP, and file watcher listeners based on EnvConfig

Run with:  python -m src.main
"""
from src.config_env.env_config import EnvConfig
from src.selfheal.listener_manager import ListenerManager
from src.buffer import redis_buffer


def main():
    print("=" * 60)
    print("Universal Log Pre-processing Framework (ULPF)")
    print("=" * 60)

    # Initialize durable streaming buffer
    buffer_mode = redis_buffer.init_buffer()
    if buffer_mode == "redis":
        from src import config
        print(f"[buffer] Redis Streams durable buffer active (stream={config.STREAM_NAME})")
        redis_buffer.start_workers(config.STREAM_WORKER_COUNT)
    else:
        print("[buffer] Running in direct synchronous mode (Redis not connected)")

    # Load configuration from environment
    config = EnvConfig.load_from_env()
    
    # Initialize and start all listeners based on configuration
    listener_manager = ListenerManager(config)
    results = listener_manager.start_all()
    
    # Print listener status
    print("\n[listeners] Status:")
    for name, status in listener_manager.get_status().items():
        enabled_str = "enabled" if status.enabled else "disabled"
        running_str = "running" if status.running else "stopped"
        port_info = f" port {status.port}" if status.port else ""
        print(f"  - {name}: {enabled_str}, {running_str}{port_info}")

    # Print success/failure of start_all
    print("\n[listeners] Startup results:")
    for name, success in results.items():
        print(f"  - {name}: {'OK' if success else 'FAILED'}")

    # Block on HTTP listener (it's the last one to run)
    # The HTTP listener runs in a daemon thread, so this won't block naturally
    # We use a simple sleep to keep the main process alive
    import time
    print("\n[main] All listeners started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[main] Shutting down...")
        listener_manager.stop_all()


if __name__ == "__main__":
    main()
