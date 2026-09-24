"""
ULPF prototype entrypoint.

Starts:
  - Durable Redis Stream buffer / worker pool (or direct fallback)
  - UDP syslog listener   (pfSense-style logs)
  - File watcher          (Squid-style access log)
  - HTTP API              (Suricata-style JSON logs in, + /metrics, /dlq, /health)

Run with:  python -m src.main
"""
from src import config
from src.buffer import redis_buffer
from src.ingestion import syslog_listener, file_watcher, http_api


def main():
    print("=" * 60)
    print("Universal Log Pre-processing Framework (ULPF)")
    print("=" * 60)

    # Initialize durable streaming buffer
    buffer_mode = redis_buffer.init_buffer()
    if buffer_mode == "redis":
        print(f"[buffer] Redis Streams durable buffer active (stream={config.STREAM_NAME})")
        redis_buffer.start_workers(config.STREAM_WORKER_COUNT)
    else:
        print("[buffer] Running in direct synchronous mode (Redis not connected)")

    syslog_listener.start_background(config.SYSLOG_UDP_PORT)
    file_watcher.start_background(config.SQUID_LOG_FILE, channel="file:squid")
    print(f"[http] API + ingestion on :{config.HTTP_API_PORT} "
          f"(POST /ingest, GET /metrics, /dlq, /health, /events/recent)")
    http_api.run(config.HTTP_API_PORT)  # blocks


if __name__ == "__main__":
    main()
