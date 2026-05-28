# Installation Guide

## Default Installation

Use this if you want the standard full installation with Docker, Ollama, and `llama3` enabled by default.

```bash
chmod +x install.sh
./install.sh --mode docker
```

What this default installation does automatically:

- installs required OS packages
- installs Docker and Docker Compose
- generates ready-to-use `.env` and baseline config
- starts the full Docker stack
- pulls the `llama3` model into the Ollama container

After `install.sh` finishes, the installation phase is done. The next step is validation only:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/stats
docker ps
docker exec -it aegisai-ollama ollama list
```

Expected result:

- `aegisai-core`, `aegisai-ollama`, `aegisai-chroma`, and `aegisai-vuln-webapp` should be running
- `llama3` should appear in `ollama list`
- `/health` should return `{"status":"ok","service":"AegisAI"}`

## Prerequisites

- Ubuntu Linux host
- Docker and Docker Compose plugin
- Internet access for initial model and Python package downloads
- Optional: Telegram bot token and chat ID

## After install.sh

Normal next actions after the default installer:

1. Check health:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/stats
```

2. Confirm the local LLM service is ready:

```bash
docker exec -it aegisai-ollama ollama list
```

3. Generate test activity:

```bash
python3 app/testing/attack_scripts/web_bruteforce.py --url http://localhost:5000/login
```

4. Review detections:

```bash
curl http://localhost:8000/events
curl http://localhost:8000/alerts
```

## Installer Roles

- `install.sh`
  Default full installer. Use this first.
- `installation.py`
  Non-interactive config generator. Useful for automation or custom bootstrap flows.
- `setup.py`
  Interactive config wizard. Useful only if you want to answer prompts manually.

## Mode selection

- Default recommended mode: `./install.sh --mode docker`
- Alternative local-host mode: `./install.sh --mode local`

Use local mode only if you intentionally do not want Docker. In local mode, Ollama is installed on the host instead of running as a container.

## Option 1: Docker deployment

1. Install Docker:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo usermod -aG docker "$USER"
newgrp docker
```

2. Prepare configuration:

```bash
cp .env.example .env
python3 setup.py --mode docker
```

3. Review `.env` and adapt paths for Docker host monitoring. Recommended values:

```env
AUTH_LOG_PATHS=/host/var/log/auth.log,/host/var/log/secure
PACKAGE_LOG_PATHS=/host/var/log/dpkg.log,/host/var/log/apt/history.log
HISTORY_FILES=/root/.bash_history,/root/.zsh_history
OLLAMA_URL=http://localhost:11434/api/generate
```

4. Build and start:

```bash
docker compose up --build -d
```

5. Pull the model:

```bash
docker exec -it aegisai-ollama ollama pull llama3
```

6. Validate:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/stats
```

## Option 2: Local Python run

1. Install system packages:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip libpcap-dev
```

2. Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Run Ollama locally and pull `llama3`.

4. Generate config:

```bash
cp .env.example .env
python3 setup.py --mode local
```

5. Start the API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Setup wizard walkthrough

`setup.py` supports `--mode docker` and `--mode local`. Without an argument it will ask interactively.

`setup.py` asks for:

- Telegram bot token
- Telegram chat ID
- trusted login IPs
- trusted admin users
- working hours
- monitored interfaces
- brute force threshold
- sensitive files/directories
- allowed countries
- SSH ports
- web app ports

It writes:

- `.env`
- `data/aegisai.db`
- `config/baseline.json`
- required data and log directories

For non-interactive config generation, use:

```bash
python3 installation.py --mode docker
```

This does not install Docker, Ollama, Python packages, or system packages by itself. It only prepares configuration and storage.

## Environment Variables

The canonical template is [.env.example](/home/legesya/project/Ai-Autonom-Threat-Analyzer/.env.example). Use that file as the reference for supported variables.

Commonly changed variables:

- `LLM_ENABLED`
  `true` means full mode is allowed. `false` forces fallback narrative mode.
- `THREAT_SYNC_ENABLED`
  Enables startup threat-intelligence sync and local RAG preparation.
- `OLLAMA_URL`
  Ollama generate endpoint.
- `OLLAMA_MODEL`
  Model name to pull and use, usually `llama3`.
- `OLLAMA_TIMEOUT_SECONDS`
  How long the runtime waits for a single Ollama completion before falling back.
- `EMBEDDING_MODEL`
  Sentence-transformer model used for embeddings.
- `DATABASE_URL`
  SQLite path for event and alert persistence.
- `HOST_USER_HOME`
  Host home directory mounted by Docker for shell history collection.
- `CHROMA_PATH`
  Local Chroma persistence path.
- `AUTH_LOG_PATHS`
  Auth log files to monitor.
- `PACKAGE_LOG_PATHS`
  Package-management logs to monitor.
- `HISTORY_FILES`
  Shell history files to monitor.
- `WEBAPP_LOG_FILE`
  Log path for the bundled vulnerable webapp.
- `MONITORED_INTERFACES`
  Interface list for packet collection.
- `SENSITIVE_PATHS`
  Sensitive files or paths monitored by FIM.
- `TRUSTED_LOGIN_IPS`
  Known-safe login source IPs.
- `TRUSTED_ADMIN_USERS`
  Known-safe admin usernames.
- `ALLOWED_COUNTRIES`
  Country allowlist for login-anomaly heuristics.
- `NORMAL_WORKING_HOURS`
  Time window used by anomaly detection.
- `BRUTE_FORCE_THRESHOLD`
  Auth and web brute-force threshold.
- `DDOS_PACKET_THRESHOLD`
  Flood threshold used by packet-rate heuristics.
- `DDOS_COUNTER_DECAY_PER_TICK`
  Number of packet-count entries removed from each source every scheduler tick.
- `SCAN_UNIQUE_PORT_THRESHOLD`
  Port-scan threshold based on unique destination ports.
- `SCHEDULER_INTERVAL_SECONDS`
  How often the runtime loop executes.
- `TELEGRAM_ENABLED`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
  Telegram delivery controls.

Typical modes:

- Full mode:

```env
LLM_ENABLED=true
THREAT_SYNC_ENABLED=true
```

- Fallback mode:

```env
LLM_ENABLED=false
THREAT_SYNC_ENABLED=false
```

## Docker service layout

- `aegisai-core`: FastAPI service, collectors, detectors, correlation, alerts
- `aegisai-chroma`: Chroma vector store container
- `aegisai-ollama`: local Llama3 inference endpoint
- `aegisai-vuln-webapp`: test target for login brute force detection

## Host monitoring notes

- The compose file mounts `/var/log` from the host as `/host/var/log`.
- Host networking is used for the core service so live sockets and packet views match the host network namespace more closely.
- For full packet capture, run on a Linux host where the container can access the desired interface.

## systemd deployment

Copy the repo to `/opt/aegisai`, then:

```bash
sudo cp systemd/aegisai.service /etc/systemd/system/aegisai.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegisai
```

## Troubleshooting

- If `/events` stays empty, verify mounted log paths and generate test activity.
- If threat intelligence sync fails, make sure the sentence-transformer model finished downloading.
- If Ollama is unreachable, check `OLLAMA_URL` and confirm `docker exec aegisai-ollama ollama list`.
- If packet capture fails, test with local-mode execution or grant the container the needed host capabilities in your environment.
- If you only see fallback summaries, verify that Ollama is running, `llama3` is installed, and `LLM_ENABLED=true`.
