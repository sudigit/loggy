# ULPF — Universal Log Pre-processing Framework (Prototype)

Ingests perimeter-device logs in different formats (syslog key-value, JSON,
CSV-ish) and normalizes them into one common OCSF-style schema, while
preserving every raw event byte-for-byte with a traceable link back to it.

This is a **working demo prototype**, deliberately simplified from the full
production architecture (see `ARCHITECTURE.md` if included, or the design
doc) so it runs on a single laptop with no external services required.
Where a simplification was made, it's called out in the code comments —
e.g. the durable Redis/Kafka buffer between stages is a single Python
function call here; swapping it in later doesn't change anything else.

## What it demonstrates

- **3 real log formats, 1 output schema** — pfSense (syslog, key=value),
  Suricata (JSON), Squid (space-delimited with epoch timestamp) all land on
  the same `src_endpoint.ip` / `dst_endpoint.ip` / `time` structure.
- **Config-driven onboarding** — each source is one YAML file
  (`src/parser/configs/*.yaml`). Adding a source means adding a file, not
  writing code.
- **Lossless raw preservation + traceability** — every event gets a
  framework-minted UUID, its raw bytes are stored verbatim + SHA-256 hashed,
  and that same UUID appears in the normalized record.
- **Dead-letter queue, not data loss** — anything that fails to parse is
  quarantined, never dropped.
- **Self-healing loop** — an offline batch job reviews the DLQ and proposes
  a new parser (via a local LLM if available, or a heuristic skeleton if
  not), which a human must review and which must pass regression tests
  before it's promoted to live traffic.
- **Air-gap friendly** — no code path calls out to the internet at runtime.
- **Containerized** — ships with a `Dockerfile` and `docker-compose.yml`.
- **Data-lake ready output** — normalized JSONL can be exported to columnar
  Parquet for downstream analytics/ML.

## Requirements

- Linux (tested on Ubuntu; should work on any distro / WSL2)
- Python 3.10+
- `pip`
- (Optional, for the self-heal demo with a real LLM instead of the
  heuristic fallback) [Ollama](https://ollama.com) installed locally with
  a model pulled, e.g. `ollama pull qwen2.5-coder`
- (Optional) Docker + Docker Compose, if you want to run it containerized
  instead of in a venv

No GPU, no cloud account, and no internet access is required to run the
core pipeline.

---

## Option A — Run locally with a virtualenv (fastest for a demo)

```bash
# 1. Unzip and enter the project
unzip ulpf.zip
cd ulpf

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the regression test suite (should show 4 passed)
python -m pytest tests/ -v

# 5. Start the framework (this blocks — leave it running in this terminal)
python -m src.main
```

You should see:
```
[syslog] listening on UDP :5514 (channel=udp:5514)
[file_watcher] tailing .../data/incoming/squid_access.log (channel=file:squid)
[http] API + ingestion on :8080 ...
```

### 6. In a second terminal, feed it sample logs

```bash
cd ulpf
source .venv/bin/activate
python tools/generate_sample_logs.py --count 10 --bad
```

`--bad` also sends a few intentionally unparseable events so you can see
the dead-letter queue in action.

### 7. Inspect the results

```bash
# Overall health of the pipeline
curl http://localhost:8080/metrics | python -m json.tool

# See normalized output from two totally different raw formats,
# landing on the same schema
curl 'http://localhost:8080/events/recent?source=pfsense&n=3'  | python -m json.tool
curl 'http://localhost:8080/events/recent?source=suricata&n=3' | python -m json.tool

# See what got quarantined instead of dropped
curl http://localhost:8080/dlq | python -m json.tool
```

### 8. Try the self-healing loop

```bash
# Reviews the DLQ, proposes a parser (Ollama if running locally, else a
# heuristic skeleton) — writes to src/parser/configs/proposed/, does NOT
# touch live traffic
python -m src.selfheal.review_dlq

# Inspect / hand-edit the proposal, then promote it (this re-runs the
# regression suite first and refuses to promote if anything breaks)
python -m src.selfheal.promote src/parser/configs/proposed/udp_5514_proposed.yaml
```

### 9. Export to Parquet (the data-lake-ready artifact)

```bash
python tools/export_parquet.py
```

Output lands in `data/parquet/<source>.parquet` — open with pandas,
DuckDB, or point Spark/Athena at the folder.

### 10. Stop the server

`Ctrl+C` in the terminal running `python -m src.main`.

---

## Option B — Run containerized (Docker)

```bash
cd ulpf
docker compose up --build
```

This exposes the same ports (`5514/udp`, `8080/tcp`) and mounts `./data`
so output persists on the host. Run the same `tools/generate_sample_logs.py`
and `curl` commands from another terminal (they talk to `localhost` either
way).

To use a host-installed Ollama for the self-heal demo from inside the
container, uncomment the `ULPF_OLLAMA_URL` line in `docker-compose.yml`.

---

## Project layout

```
ulpf/
├── src/
│   ├── main.py              # entrypoint — starts all ingestion channels + API
│   ├── config.py            # all paths/ports/thresholds (env-overridable)
│   ├── pipeline.py          # the one function every channel calls
│   ├── core/
│   │   ├── ids.py           # UUID + SHA-256 minting
│   │   ├── raw_store.py     # lossless raw event storage (stands in for MinIO)
│   │   └── metrics.py       # in-memory counters for /metrics
│   ├── ingestion/
│   │   ├── syslog_listener.py   # UDP syslog (pfSense-style)
│   │   ├── http_api.py          # HTTP ingestion + /metrics /dlq /health
│   │   └── file_watcher.py      # tails a file (Squid-style)
│   ├── parser/
│   │   ├── engine.py         # THE generic engine — fingerprint, tokenize, map
│   │   └── configs/          # one YAML per source — this is "onboarding"
│   │       ├── pfsense_v1.yaml
│   │       ├── suricata_v1.yaml
│   │       ├── squid_v1.yaml
│   │       └── proposed/     # self-heal writes candidate configs here
│   ├── dlq/store.py          # SQLite dead-letter queue
│   ├── output/writer.py      # normalized JSONL writer
│   └── selfheal/
│       ├── review_dlq.py     # offline batch job: DLQ -> proposed parser
│       └── promote.py        # human-gated, regression-tested promotion
├── tools/
│   ├── generate_sample_logs.py   # demo driver — sends realistic sample logs
│   └── export_parquet.py         # JSONL -> columnar Parquet
├── tests/
│   ├── test_parser.py        # regression corpus — must pass before promote
│   └── fixtures/              # known-good raw samples per source
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Known simplifications vs. the full production architecture

These are intentional, and called out so they don't read as oversights:

- **In-process call instead of Redis Streams/Kafka** between ingestion and
  parsing. Fine for a single-process demo; the production design uses a
  durable buffer here for horizontal scaling and crash recovery.
- **Filesystem instead of MinIO** for raw storage — same key layout
  (`source_id/uuid`), so swapping in a real S3-compatible store is a
  one-file change (`src/core/raw_store.py`).
- **JSONL + on-demand Parquet export** instead of a continuous streaming
  Parquet writer — simpler to inspect for a demo, same end format.
- **Single-process pipeline** — no horizontal worker scaling. The
  architecture doc describes how this scales to billions of events/day;
  this prototype proves the *logic*, not the *throughput*.
