"""
ULPF prototype entrypoint.

Starts:
  - UDP syslog listener   (pfSense-style logs)
  - File watcher          (Squid-style access log)
  - HTTP API              (Suricata-style JSON logs in, + /metrics, /dlq, /health)

Run with:  python -m src.main
"""
from src import config
from src.ingestion import syslog_listener, file_watcher, http_api


def main():
    print("=" * 60)
    print("Universal Log Pre-processing Framework (ULPF) - prototype")
    print("=" * 60)
    syslog_listener.start_background(config.SYSLOG_UDP_PORT)
    file_watcher.start_background(config.SQUID_LOG_FILE, channel="file:squid")
    print(f"[http] API + ingestion on :{config.HTTP_API_PORT} "
          f"(POST /ingest, GET /metrics, /dlq, /health, /events/recent)")
    http_api.run(config.HTTP_API_PORT)  # blocks


if __name__ == "__main__":
    main()
