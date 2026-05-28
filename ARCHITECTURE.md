# AegisAI Architecture

## Purpose

AegisAI is a local-first SOC/XDR platform for Ubuntu Linux that combines rule-based detections, historical correlation, local threat-intelligence retrieval, and optional Llama3 reasoning through Ollama.

The most important architectural rule is enforced both in code and in deployment design:

`raw logs -> collectors -> detectors -> suspicious events -> correlation -> RAG context -> LLM narrative`

The LLM does not receive bulk raw logs. It only receives summarized suspicious events, selected evidence excerpts, historical context, and retrieved threat-intelligence context.

## Operational model

The project now has three separate operational layers:

1. [install.sh](/home/legesya/project/Ai-Autonom-Threat-Analyzer/install.sh)
   Main bootstrap entrypoint. It installs system dependencies, installs Docker in docker mode, generates configuration, starts runtime services, and pulls the Ollama model.
2. [installation.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/installation.py)
   Non-interactive configuration generator. It writes `.env`, writes `config/baseline.json`, creates `data/` and `logs/`, and initializes the SQLite file.
3. [setup.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/setup.py)
   Interactive configuration wizard. It exists for operators who want to answer prompts manually instead of accepting defaults or automation-driven values.

This separation is intentional. Host bootstrap, configuration generation, and runtime execution are not mixed into one file anymore.

Recommended path:

1. run `./install.sh --mode docker`
2. let it call `installation.py`
3. let it bring up the runtime stack
4. use `setup.py` only when interactive configuration is actually needed

## High-level runtime flow

The runtime path is implemented across [app/main.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/main.py), [app/runtime.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/runtime.py), and [app/ai/correlation_engine.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/ai/correlation_engine.py).

The lifecycle is:

1. FastAPI starts.
2. logging is configured.
3. SQLite schema is initialized.
4. runtime startup runs.
5. optional threat-intelligence sync runs.
6. background collection loop starts.
7. collectors emit observations.
8. detectors convert observations into suspicious events.
9. events are stored.
10. per-event alerts are stored.
11. multi-event correlation runs.
12. a final correlated alert is stored and optionally sent to Telegram.
13. API endpoints expose results from persistence.

## Runtime modes

There are two valid runtime modes.

### Full mode

Full mode means:

- `LLM_ENABLED=true`
- Ollama is reachable
- the configured model such as `llama3` is present
- threat-intelligence dependencies are installed
- retrieval succeeds when needed

In this mode, the final narrative comes from live local inference through Ollama and is enriched with retrieved threat knowledge.

### Fallback mode

Fallback mode means one or more of these is unavailable:

- LLM explicitly disabled
- Ollama unavailable
- model not pulled yet
- vector retrieval unavailable
- threat sync dependencies not ready

In this mode:

- collectors still run
- detectors still emit `SuspiciousEvent`
- correlation still builds attack chains
- history is still recorded
- alerts still reach the API
- the narrative falls back to deterministic SOC-style text

This is not a separate product tier. It is a resilience mechanism so the platform still works during first bootstrap, model download delays, or dependency failures.

## Application entrypoint

### [app/main.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/main.py)

This file is intentionally small because it should only own process startup concerns.

What it does:

1. loads settings through `get_settings()`
2. configures application logging
3. initializes the database schema immediately with `init_db()`
4. defines a FastAPI lifespan context
5. calls `runtime.startup()` on application start
6. calls `runtime.shutdown()` on application stop
7. mounts the API router

Why this matters:

- it keeps boot order explicit
- DB initialization happens before background runtime work
- runtime ownership is centralized instead of scattered into route handlers

## Configuration system

### [app/config.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/config.py)

This file is the policy surface of the platform. Most operational behavior comes from here rather than hardcoded constants elsewhere.

Important settings groups:

- storage:
  - `database_url`
  - `chroma_path`
  - `raw_log_dir`
  - `webapp_log_file`
- telemetry source paths:
  - `auth_log_paths`
  - `history_files`
  - `package_log_paths`
  - `monitored_interfaces`
  - `sensitive_paths`
- baseline and trust:
  - `trusted_admin_users`
  - `trusted_login_ips`
  - `allowed_countries`
  - `normal_working_hours`
  - `ssh_ports`
  - `webapp_ports`
  - `high_risk_ports`
- thresholds:
  - `packet_window_seconds`
  - `brute_force_threshold`
  - `brute_force_window_seconds`
  - `ddos_packet_threshold`
  - `scan_unique_port_threshold`
  - `beaconing_min_repeats`
  - `large_transfer_threshold_bytes`
  - `scheduler_interval_seconds`
  - `retriever_top_k`
- AI and enrichment:
  - `llm_enabled`
  - `ollama_url`
  - `ollama_model`
  - `embedding_model`
  - `threat_sync_enabled`
  - `threat_sync_interval_hours`
- alerting:
  - `telegram_enabled`
  - `telegram_bot_token`
  - `telegram_chat_id`

Implementation detail that matters:

- several settings are stored as comma-separated strings in `.env`
- `@computed_field` methods turn them into typed lists
- downstream code therefore consumes normalized values such as `auth_log_path_list`, `trusted_login_ip_list`, or `high_risk_port_list`

That avoids repeated parsing inside collectors and detectors.

## Data contracts

### [app/schemas.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/schemas.py)

The platform relies on strict boundaries between stages.

Key objects:

- `RawObservation`
  normalized telemetry unit emitted by collectors
- `SuspiciousEvent`
  detector result with severity, confidence, risk score, evidence, indicators, and MITRE mappings
- `CorrelatedThreat`
  final multi-event attack narrative with evidence, recommendations, retrieved context, and history

Why these contracts matter:

- collectors do not need to know about LLM prompts
- detectors do not need to know about databases
- correlation does not need to reopen raw logs
- alert formatting remains independent of raw telemetry parsing

This schema boundary is the main technical guardrail that keeps the LLM from becoming a raw-log ingestion engine.

## Database architecture

### [app/database/models.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/database/models.py)

The persistence layer uses four durable entities:

- `EventRecord`
  durable copy of detector output
- `AlertRecord`
  human-facing alert records, including per-event alerts and correlated alerts
- `AttackHistoryRecord`
  recurring attacker memory keyed by actor identity such as source IP
- `ThreatIntelDocument`
  normalized threat-intelligence documents stored for local recall and auditability

### [app/database/db.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/database/db.py)

This file owns:

- engine creation
- session lifecycle
- schema initialization
- transaction boundary handling

SQLite is used deliberately:

- simple local-first deployment
- no external DB required
- suitable for demo, lab, and single-host SOC workloads

### [app/database/history.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/database/history.py)

This file is intentionally narrow.

It provides:

- `record(...)`
  inserts a new `AttackHistoryRecord`
- `recent_for_actor(...)`
  returns recent history for an actor key ordered by newest first

The correlation engine uses this to inject attacker memory into the final analysis path.

## Collector layer

All collectors implement the interface in [app/collectors/base.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/base.py). The collector layer exists to acquire evidence and normalize it, not to make security judgments.

### [app/collectors/auth_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/auth_collector.py)

Purpose:

- read authentication logs such as `/var/log/auth.log` or `/var/log/secure`
- parse login failures and successes
- emit normalized observations

Architectural behavior:

- tracks file offsets in memory
- prevents re-emitting the same lines in the same runtime session
- preserves raw line evidence for downstream explanation

### [app/collectors/webapp_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/webapp_collector.py)

Purpose:

- watch the bundled vulnerable Flask app log
- extract login attempts from a dedicated application log source

Why this matters:

- web-auth detections stay separate from Linux auth detections
- controlled demo activity can be generated without attacking SSH

### [app/collectors/package_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/package_collector.py)

Purpose:

- parse `dpkg` and APT history
- identify install and removal operations

Used for:

- post-compromise tooling detection
- change visibility for offensive tools such as `hydra`, `nmap`, `netcat`, or `socat`

### [app/collectors/history_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/history_collector.py)

Purpose:

- inspect `.bash_history` and `.zsh_history`
- emit command-line evidence as observations

Used by detectors for:

- privilege escalation chains
- payload download patterns
- archive creation
- destructive or stealth actions

### [app/collectors/process_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/process_collector.py)

Purpose:

- inspect live processes through `psutil`
- emit newly seen processes only

Implementation pattern:

- tracks `pid/create_time` pairs
- avoids re-alerting the same long-running process on every loop

### [app/collectors/connection_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/connection_collector.py)

Purpose:

- inspect live TCP and UDP connection state through `psutil.net_connections`
- emit outbound and established session metadata

Used by detectors for:

- suspicious remote destinations
- unusual ports
- reverse-shell and beaconing heuristics
- exfiltration correlation

### [app/collectors/packet_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/packet_collector.py)

Purpose:

- observe network packets using Scapy `AsyncSniffer`
- reduce packet data into a compact telemetry shape

Important implementation choice:

- only packet metadata is buffered
- full packet payloads are not sent to the AI path

Operational resilience:

- startup is wrapped defensively
- if sniffing cannot start because of privileges or environment limitations, the runtime degrades instead of crashing the whole service

### [app/collectors/file_integrity_collector.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/collectors/file_integrity_collector.py)

Purpose:

- hash sensitive paths
- emit an observation when a digest changes

Current protected surface typically includes:

- `/etc/passwd`
- `/etc/shadow`
- `/etc/sudoers`
- `/etc/crontab`

Operational resilience:

- unreadable paths are skipped safely
- collector failure on one path should not break the loop

## Detector layer

Each detector implements [app/detectors/base.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/detectors/base.py). Detectors are intentionally rule-based, explainable, and stateful only where needed.

### `BruteForceDetector`

Consumes auth observations and detects:

- repeated failed logins
- repeated invalid usernames
- high-volume authentication failures in a time window

Core model:

- sliding window keyed by source and account context
- threshold driven by `BRUTE_FORCE_THRESHOLD`

### `WebAppDetector`

Consumes web login observations and detects:

- repeated failed POST `/login` attempts
- single-IP multi-username patterns
- credential stuffing behavior

This detector produced the successful remote test alert where repeated local failed logins were correlated into a brute-force event.

### `ScanDetector`

Consumes reduced packet observations and detects:

- SYN scan behavior
- FIN, NULL, or Xmas-like signatures using TCP flags
- aggressive unique-port enumeration

Core method:

- maintain recent per-source unique destination ports
- derive a rough scan fingerprint from flags and rate

### `DDoSDetector`

Consumes packet observations and detects:

- SYN flood
- ICMP/UDP-like floods as high-rate heuristics
- packet bursts that exceed configured packet thresholds

This is intentionally heuristic, not a full IDS-grade packet-inspection engine.

### `LoginAnomalyDetector`

Consumes successful authentication observations and detects:

- login from non-trusted IPs
- unusual countries relative to baseline
- successful login outside configured working hours

This is the baseline-aware detector in the stack.

### `PrivilegeDetector`

Consumes history observations and detects suspicious commands such as:

- `sudo`
- `chmod +s`
- `setcap`
- `usermod`
- `passwd`
- sudoers edits
- persistence-like activity

Its job is to create the post-auth escalation signals that later correlation can chain with brute force or suspicious login events.

### `ExfiltrationDetector`

Consumes history plus outbound session context and looks for:

- archive creation
- upload commands
- outbound encrypted transfer
- data staging before network movement

This detector is what supports the narrative shape:

`archive creation -> outbound transfer -> possible exfiltration`

### `ProcessDetector`

Consumes new process observations and detects process command lines associated with:

- `nc -e`
- suspicious `curl` or `wget`
- inline Python launchers
- miners
- reverse-shell style execution

### `PackageDetector`

Consumes package observations and detects:

- installation of offensive tooling
- unexpected removal or change activity

This is useful when attackers install tooling after initial access.

### `HistoryDetector`

Consumes shell history and detects:

- destructive commands
- log wiping
- stealth behavior
- persistence hints

This detector overlaps slightly with `PrivilegeDetector`, but the separation is deliberate:

- `PrivilegeDetector` focuses on escalation and capability changes
- `HistoryDetector` focuses on destructive and stealth operator behavior

### `FileIntegrityDetector`

Consumes file-integrity observations and turns a protected-path hash change into a high-severity event.

## MITRE mapping

### [app/ai/mitre_mapper.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/ai/mitre_mapper.py)

MITRE mapping is handled after detection, not during collection.

This file keeps an explicit event-type to ATT&CK mapping table so alerts can carry:

- T1110 Brute Force
- T1595 Active Scanning
- T1078 Valid Accounts
- T1059 Command and Scripting Interpreter
- T1041 Exfiltration Over C2 Channel

and related techniques based on event type.

This explicit lookup is preferable here to opaque model inference because:

- mappings are deterministic
- analysts can audit them
- detector contracts remain stable

## Runtime orchestration

### [app/runtime.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/runtime.py)

This file is the execution backbone of the system.

### Constructor behavior

`AegisRuntime.__init__` wires the entire platform together:

- loads settings once
- instantiates every collector
- instantiates every detector
- instantiates the correlation engine
- instantiates Telegram alert delivery
- instantiates the threat-intelligence updater
- reserves a background task handle

This is effectively the dependency graph assembly point.

### Startup behavior

`startup()` does two things:

1. if `threat_sync_enabled` is true, it runs a sync before looping
2. it spawns the async background loop

Why sync first:

- the first detections can already benefit from locally stored threat context
- startup order stays deterministic

### Shutdown behavior

`shutdown()` cancels the background task and suppresses the expected `CancelledError`.

This keeps FastAPI shutdown clean and avoids leaving orphaned tasks behind.

### Background loop behavior

`_loop()` runs forever and:

1. calls `run_once()`
2. catches exceptions at the top loop boundary
3. logs failures without killing the process
4. sleeps for `scheduler_interval_seconds`

This is a deliberate reliability pattern. One collector or detector failure should not terminate the whole monitoring service.

### `run_once()` behavior

`run_once()` is the core pipeline implementation.

Detailed sequence:

1. create an empty `all_events` list
2. iterate over every collector
3. call `collector.collect()`
4. iterate over every returned observation
5. pass the observation to every detector
6. extend `all_events` with any resulting `SuspiciousEvent`
7. return early if no events were produced
8. open a DB session
9. store each `SuspiciousEvent` as `EventRecord`
10. flush each record so DB-generated IDs are available immediately
11. create a corresponding `AlertRecord` for the per-event alert body
12. send high-risk per-event Telegram notifications
13. call correlation on the new batch of `EventRecord`
14. if correlation returns a result, store a final correlated `AlertRecord`
15. send the correlated alert through Telegram

Design consequence:

- event persistence happens before correlation output is stored
- correlated alerts can refer back to durable events
- API consumers always read persisted records instead of ephemeral in-memory state

### Event alert threshold

`_send_event_alerts()` only sends Telegram notifications for events where `risk_score >= 85`.

This prevents Telegram from becoming a noisy copy of the raw event stream.

## Correlation and AI reasoning

### [app/ai/correlation_engine.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/ai/correlation_engine.py)

This file is the heart of AegisAI.

### Constructor behavior

The constructor creates:

- `buffer`
  a `deque(maxlen=50)` containing recent `SuspiciousEvent` objects
- `llm`
  an instance of `LLMEngine`
- `history`
  an `AttackHistoryStore`
- `retrieval`
  a `RetrievalPipeline`

The buffer exists so correlation can look beyond the current collector batch and form a short rolling attack chain.

### `correlate(...)` behavior

This method performs the following steps:

1. return `None` immediately if no new records arrived
2. rebuild `SuspiciousEvent` objects from `EventRecord`
3. append new events into the rolling in-memory buffer
4. suppress low-signal single events if there is only one new event and its `risk_score < 80`
5. build an `attack_chain` from the last six buffered event types
6. flatten raw evidence lines into prompt-safe text
7. derive `actor_key`, usually from `source_ip`
8. load recent history for that actor from SQLite
9. retrieve threat-intelligence context through the RAG pipeline
10. create the event summary and MITRE summary text
11. ask the LLM engine for the final narrative
12. calculate final severity, confidence, and risk
13. write a new attacker-memory record back into history
14. return a `CorrelatedThreat`

### Severity logic

Current correlated severity logic is intentionally simple:

- `critical` if any event is already critical
- `critical` if the derived attack chain length is at least 4
- otherwise `high`

### Confidence and risk logic

Current scoring logic:

- start from the max event confidence and max event risk
- add a bounded bonus based on attack-chain length
- clamp confidence to `99`
- clamp risk to `100`

This means correlation can elevate otherwise separate events into a higher-priority final alert.

### History usage

Correlation reads history from `AttackHistoryStore.recent_for_actor(...)` and writes history using `record(...)`.

This gives the platform memory for:

- recurring source IPs
- repeated attack styles
- historical chain summaries

### Output shape

The returned `CorrelatedThreat` contains:

- title
- narrative
- severity
- confidence
- risk_score
- `event_ids`
- `mitre_techniques`
- `raw_evidence`
- analyst-facing recommendations
- retrieved threat context records
- historical context records

That object is then formatted for alerting and persistence.

## LLM engine

### [app/ai/llm_engine.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/ai/llm_engine.py)

This file is intentionally narrow. It owns prompt delivery to Ollama and fallback generation.

### Request path

`analyze(...)`:

1. checks `llm_enabled`
2. returns fallback immediately if disabled
3. builds a prompt through `build_prompt(...)`
4. creates an Ollama payload with:
   - `model`
   - `prompt`
   - `stream=false`
5. sends an HTTP POST using `httpx.AsyncClient`
6. returns `response` text from the Ollama JSON body
7. falls back if the response body is empty
8. falls back on any exception

### Fallback path

`_fallback_analysis(...)` returns a deterministic SOC-style narrative containing:

- summary
- evidence
- historical context
- threat-intelligence context
- MITRE
- short recommendations

This fallback is important because it keeps the rest of the pipeline stable even when inference is unavailable.

## Prompt design

### [app/ai/prompts.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/ai/prompts.py)

Prompt construction is separated from transport.

That file is responsible for:

- combining event summaries
- combining evidence excerpts
- inserting historical context
- inserting retrieved threat context
- inserting MITRE IDs
- producing a single prompt string for the model

This separation is useful because prompt policy can evolve independently from HTTP client logic.

## Threat intelligence and RAG

### Why the RAG layer exists

The base model should not be treated as the only source of cybersecurity knowledge. The RAG layer exists to inject local and recently synchronized security context into analysis.

### Pipeline shape

1. threat collectors gather source material
2. cleaner removes noise
3. parser and normalizer shape documents consistently
4. chunker splits long content
5. embedder generates embeddings
6. vector store persists embeddings and metadata
7. retriever performs semantic search
8. context builder formats retrieved chunks into prompt-safe context
9. correlation consumes the final retrieval output

### Relevant modules

- collectors:
  [app/threat_intelligence/collectors](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/threat_intelligence/collectors)
- processors:
  [app/threat_intelligence/processors](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/threat_intelligence/processors)
- vector store:
  [app/threat_intelligence/vectorstore](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/threat_intelligence/vectorstore)
- RAG orchestration:
  [app/threat_intelligence/rag](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/threat_intelligence/rag)
- updater:
  [app/threat_intelligence/updater.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/threat_intelligence/updater.py)

### Graceful degradation in the RAG layer

The RAG path was deliberately hardened so the platform still starts in constrained environments.

Current resilience behavior:

- embedding model loading is lazy
- Chroma client import is delayed until needed
- retrieval returns an empty result on failure instead of crashing the runtime
- threat sync logs warnings and returns safely when dependencies fail

This is why the platform can still run in fallback mode while the full AI stack is not yet ready.

## Alerting

### [app/alerts/formatter.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/alerts/formatter.py)

This module converts structured event and correlated-threat objects into concise SOC-friendly alert bodies.

### [app/alerts/telegram.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/alerts/telegram.py)

This module delivers alert text to Telegram when enabled.

Alerting policy is intentionally separated from detector logic so:

- detection can remain transport-agnostic
- future outputs such as email, Slack, or web UI notifications can be added without rewriting detectors

## API layer

### [app/api/routes.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/api/routes.py)

The API is read-oriented and intentionally thin.

Endpoints:

- `/health`
  returns service readiness
- `/events`
  returns stored `EventRecord` data
- `/alerts`
  returns stored `AlertRecord` data
- `/stats`
  returns counts of total events, total alerts, and critical events
- `/history`
  returns attacker history
- `/threats`
  aliases alert output
- `/attacks`
  aliases history output
- `/connections`
  filters event output to records whose `source == "connections"`

Implementation pattern:

- route handlers do not trigger fresh collection
- route handlers read from runtime-backed persistence
- `_serialize_record(...)` strips SQLAlchemy internals and ISO-formats timestamps

This keeps the API predictable and safe to poll.

## Demo application

### [app/testing/vulnerable_webapp/app.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/app/testing/vulnerable_webapp/app.py)

The bundled Flask app is intentionally weak.

It exists to generate controlled evidence for:

- web login brute force
- credential stuffing
- repeated failed auth attempts

Properties:

- static credentials
- detailed file logging
- no rate limiting
- dedicated log path configurable through environment

It is not a secure app and is included only for testing and demonstrations.

## Deployment artifacts

### [install.sh](/home/legesya/project/Ai-Autonom-Threat-Analyzer/install.sh)

This is the default installer.

In docker mode it:

1. installs base OS packages
2. installs Docker and Compose
3. runs `installation.py`
4. runs `docker compose up -d --build`
5. pulls the requested Ollama model inside `aegisai-ollama`

In local mode it:

1. installs base OS packages
2. creates `.venv`
3. installs Python dependencies
4. installs Ollama on the host
5. pulls the requested model on the host
6. initializes the local DB

### [installation.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/installation.py)

This file generates ready-to-use configuration for either docker or local mode.

It:

- parses `.env.example`
- applies mode-specific defaults
- writes `.env`
- writes `config/baseline.json`
- creates storage directories
- creates the SQLite file

It does not install Docker, Ollama, or system packages.

### [setup.py](/home/legesya/project/Ai-Autonom-Threat-Analyzer/setup.py)

This file is an interactive wizard.

It asks for:

- Telegram settings
- trusted IPs
- trusted users
- working hours
- interfaces
- thresholds
- sensitive paths
- allowed countries
- SSH ports
- web app ports

Then it writes:

- `.env`
- `config/baseline.json`
- `data/aegisai.db`

Its role is configuration convenience, not deployment orchestration.

### [Dockerfile](/home/legesya/project/Ai-Autonom-Threat-Analyzer/Dockerfile)

Builds the Python runtime image used by the platform.

### [docker-compose.yml](/home/legesya/project/Ai-Autonom-Threat-Analyzer/docker-compose.yml)

Defines four services:

- `aegisai-core`
  main API and monitoring runtime
- `aegisai-chroma`
  vector database container
- `aegisai-ollama`
  local inference endpoint
- `aegisai-vuln-webapp`
  test login application

Important deployment choices:

- `aegisai-core` mounts host logs
- `aegisai-core` uses host networking
- Ollama model data is persisted under `data/ollama`
- Chroma persistence is mounted

### [systemd/aegisai.service](/home/legesya/project/Ai-Autonom-Threat-Analyzer/systemd/aegisai.service)

Wraps the Docker Compose stack for boot-time startup on Ubuntu systems.

## Why this design is production-style

The implementation is intentionally split into narrow layers:

- configuration defines policy
- collectors define evidence acquisition
- detectors define explainable judgments
- persistence defines durable state
- correlation defines attack-sequence reasoning
- RAG defines contextual enrichment
- LLM code defines narrative generation only
- alerting defines outbound human notification
- API defines machine-readable access
- installers define deployment bootstrap

That separation gives the platform the properties needed for a serious monitoring service:

- debuggable behavior
- deterministic detection logic
- bounded AI input
- offline-capable local operation
- graceful degradation when AI dependencies are missing
- clear paths for future expansion into richer UI and investigation workflows
