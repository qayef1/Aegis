# AegisAI

AegisAI is a local-first AI-powered SOC/XDR platform for Ubuntu Linux. It collects host and network telemetry, applies rule-based detections, correlates suspicious activity into attack chains, enriches the result with local threat intelligence through RAG, and asks Llama3 via Ollama for a SOC-style narrative. The LLM never receives full raw logs; it only receives summarized suspicious events, evidence excerpts, MITRE mappings, and historical context.

## What it monitors

- Authentication activity from `auth.log` or `secure`
- Web application login activity from the bundled Flask test app
- Package installation and removal logs
- Bash and Zsh history
- Process execution
- Active network connections
- Packet summaries from Scapy
- Sensitive file integrity changes

## Main capabilities

- SSH and generic auth brute force detection
- Web login brute force detection
- Port scan detection
- DDoS and flood heuristics
- Login anomaly detection
- Privilege escalation and suspicious command monitoring
- Suspicious package tooling detection
- Data staging and exfiltration heuristics
- File integrity monitoring
- MITRE ATT&CK mapping
- Historical attacker memory in SQLite
- RAG-backed threat context from local ChromaDB
- Telegram alerting
- FastAPI dashboard API
- Docker deployment with Ollama and demo web app

## Architecture

The event flow is:

`collectors -> detectors -> suspicious event objects -> correlation engine -> RAG retrieval -> Llama3 reasoning -> alerts/API`

This keeps the LLM on the reasoning layer only. Raw logs stay in collectors and are reduced to evidence-bearing event objects before any prompt is built.

## Quickstart

Default full installation:

```bash
chmod +x install.sh
./install.sh --mode docker
```

This is the primary installation path. It installs OS packages, installs Docker, generates `.env` and `config/baseline.json`, starts the stack, and pulls `llama3` automatically.

After `install.sh` finishes, do validation only:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/stats
docker ps
docker exec -it aegisai-ollama ollama list
```

Expected result:

- `aegisai-core`, `aegisai-ollama`, `aegisai-chroma`, and `aegisai-vuln-webapp` are running
- `llama3` appears in `ollama list`
- `/health` returns `{"status":"ok","service":"AegisAI"}`

Manual path, only if you do not want the default installer:

1. Copy `.env.example` to `.env`.
2. Run `python3 setup.py --mode docker` if you want the interactive wizard to generate a Docker-safe baseline configuration.
3. Start the stack:

```bash
docker compose up --build
```

4. Pull the local Llama model inside the Ollama container:

```bash
docker exec -it aegisai-ollama ollama pull llama3
```

5. Query the API:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/events
curl http://localhost:8000/alerts
curl http://localhost:8000/stats
```

## Demo scenarios

Web brute force:

```bash
python3 app/testing/attack_scripts/web_bruteforce.py --url http://localhost:5000/login
```

Packet burst / scan simulation:

```bash
python3 app/testing/traffic_simulators/packet_burst.py --target 127.0.0.1 --mode syn --count 300
```

History-based privilege and exfil simulation:

```bash
bash app/testing/attack_scripts/privilege_simulation.sh
```

Manual examples are in [demo_commands.md](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/testing/attack_scripts/demo_commands.md).

## API endpoints

- `GET /health`
- `GET /events`
- `GET /alerts`
- `GET /threats`
- `GET /connections`
- `GET /history`
- `GET /attacks`
- `GET /stats`

## How the code works

The runtime in [app/runtime.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/runtime.py) starts background collection loops. Each collector returns `RawObservation` objects. Every observation is fed through the detector set. Detectors emit `SuspiciousEvent` objects with severity, confidence, risk score, raw evidence, indicators, and MITRE mappings. Events are stored in SQLite, then passed to the correlation engine. The correlation engine merges related events, loads historical attacker activity, retrieves relevant threat intelligence from ChromaDB, and calls the Ollama `llama3` endpoint. The resulting narrative is stored as an alert and optionally sent to Telegram.

If Ollama or the RAG dependencies are unavailable, the platform can still run in fallback mode with rule-based detections and non-LLM summaries. Full mode requires Ollama plus the local model and threat-intelligence dependencies.

## Installer roles

- `install.sh` is the default host bootstrap entrypoint. Use this first.
- `installation.py` is the non-interactive configuration generator used by automation.
- `setup.py` is the interactive wizard for manually filling baseline values. It now supports `--mode docker` and `--mode local`.

## Environment variables

The project now includes a fuller reference template in [.env.example](/home/legesya/project/Ai-Autonom-Threat-Analyzer/.env.example).

Most important variables:

- `LLM_ENABLED=true`
  Enables live Ollama reasoning. Set `false` to force fallback summaries.
- `THREAT_SYNC_ENABLED=true`
  Enables threat-intelligence sync and RAG preparation on startup.
- `OLLAMA_URL=http://localhost:11434/api/generate`
  Ollama inference endpoint used by the API runtime.
- `OLLAMA_MODEL=llama3`
  Local model name to use for SOC narratives.
- `OLLAMA_TIMEOUT_SECONDS=600`
  Maximum wait time for a single Ollama response before AegisAI falls back.
- `EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2`
  Embedding model used by the threat-intelligence pipeline.
- `DATABASE_URL`
  SQLite database location for events, alerts, history, and threat docs.
- `HOST_USER_HOME`
  Host home directory used by Docker to bind shell history files safely.
- `CHROMA_PATH`
  Local vector-store persistence path.
- `AUTH_LOG_PATHS`
  Comma-separated auth log files to monitor.
- `PACKAGE_LOG_PATHS`
  Comma-separated APT and dpkg logs to monitor.
- `HISTORY_FILES`
  Comma-separated shell history files to monitor.
- `WEBAPP_LOG_FILE`
  Dedicated vulnerable webapp log path.
- `MONITORED_INTERFACES`
  Comma-separated network interfaces for packet visibility.
- `SENSITIVE_PATHS`
  Sensitive files or paths used by file-integrity monitoring.
- `TRUSTED_LOGIN_IPS`
  Baseline IP list used by login anomaly detection.
- `TRUSTED_ADMIN_USERS`
  Baseline admin usernames used by behavior correlation.
- `ALLOWED_COUNTRIES`
  Country allowlist used by anomaly heuristics.
- `NORMAL_WORKING_HOURS`
  Time window used by login anomaly detection.
- `BRUTE_FORCE_THRESHOLD`
  Failed-login threshold before brute-force detectors fire.
- `DDOS_PACKET_THRESHOLD`
  Packet-rate threshold for flood heuristics.
- `DDOS_COUNTER_DECAY_PER_TICK`
  Number of packet-count entries removed from each source every scheduler tick.
- `SCAN_UNIQUE_PORT_THRESHOLD`
  Unique-port threshold for scan detection.
- `SCHEDULER_INTERVAL_SECONDS`
  Background runtime loop interval.
- `TELEGRAM_ENABLED`
  Enables Telegram delivery.
- `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
  Telegram destination settings.

If you want fallback mode deliberately, the minimum safe change is:

```env
LLM_ENABLED=false
THREAT_SYNC_ENABLED=false
```

## Telegram configuration

Set these in `.env`:

- `TELEGRAM_ENABLED=true`
- `TELEGRAM_BOT_TOKEN=...`
- `TELEGRAM_CHAT_ID=...`

## Notes

- Packet capture usually needs elevated privileges or host networking.
- Sentence-transformer models are downloaded the first time the threat intel subsystem runs.
- The included web app is intentionally weak and only for testing.
- The existing file named `prompt` was left untouched.
- `install.sh` is the default full installer.
- `installation.py` is the non-interactive config generator used by automation.
- `setup.py` is the interactive config wizard and is not the main installer. When used, pass `--mode docker` for Docker deployments.
