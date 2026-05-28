from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"


def ask(prompt: str, default: str = "") -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def validate_csv_numbers(value: str) -> str:
    for item in [part.strip() for part in value.split(",") if part.strip()]:
        int(item)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactive AegisAI configuration wizard.")
    parser.add_argument("--mode", choices=["docker", "local"], help="Configuration mode for generated paths.")
    return parser


def resolve_mode(cli_mode: str | None) -> str:
    if cli_mode:
        return cli_mode
    while True:
        mode = ask("Deployment mode (docker/local)", "docker").lower()
        if mode in {"docker", "local"}:
            return mode
        print("Please choose 'docker' or 'local'.")


def build_env_content(
    mode: str,
    telegram_bot_token: str,
    telegram_chat_id: str,
    trusted_ips: str,
    trusted_users: str,
    working_hours: str,
    interfaces: str,
    brute_force_threshold: str,
    sensitive_dirs: str,
    allowed_countries: str,
    ssh_ports: str,
    webapp_ports: str,
) -> str:
    if mode == "docker":
        database_url = "sqlite:////app/data/aegisai.db"
        chroma_path = "/app/data/chroma"
        raw_log_dir = "/app/logs"
        webapp_log_file = "/app/logs/vulnerable_webapp.log"
        auth_log_paths = "/host/var/log/auth.log,/host/var/log/secure"
        history_files = "/root/.bash_history,/root/.zsh_history"
        package_log_paths = "/host/var/log/dpkg.log,/host/var/log/apt/history.log"
        ollama_url = "http://localhost:11434/api/generate"
    else:
        database_url = f"sqlite:///{BASE_DIR / 'data' / 'aegisai.db'}"
        chroma_path = str(BASE_DIR / "data" / "chroma")
        raw_log_dir = str(LOG_DIR)
        webapp_log_file = str(LOG_DIR / "vulnerable_webapp.log")
        auth_log_paths = "/var/log/auth.log,/var/log/secure"
        history_files = f"{Path.home() / '.bash_history'},{Path.home() / '.zsh_history'}"
        package_log_paths = "/var/log/dpkg.log,/var/log/apt/history.log"
        ollama_url = "http://localhost:11434/api/generate"

    return f"""APP_NAME=AegisAI
ENVIRONMENT=production
LOG_LEVEL=INFO
HOST_USER_HOME={Path.home()}
DATABASE_URL={database_url}
CHROMA_PATH={chroma_path}
RAW_LOG_DIR={raw_log_dir}
WEBAPP_LOG_FILE={webapp_log_file}
AUTH_LOG_PATHS={auth_log_paths}
HISTORY_FILES={history_files}
PACKAGE_LOG_PATHS={package_log_paths}
MONITORED_INTERFACES={interfaces}
SENSITIVE_PATHS={sensitive_dirs}
TRUSTED_LOGIN_IPS={trusted_ips}
TRUSTED_ADMIN_USERS={trusted_users}
ALLOWED_COUNTRIES={allowed_countries}
NORMAL_WORKING_HOURS={working_hours}
SSH_PORTS={ssh_ports}
WEBAPP_PORTS={webapp_ports}
HIGH_RISK_PORTS=21,22,23,3389,4444,5555,8080
PACKET_WINDOW_SECONDS=10
BRUTE_FORCE_THRESHOLD={brute_force_threshold}
BRUTE_FORCE_WINDOW_SECONDS=300
DDOS_PACKET_THRESHOLD=300
DDOS_COUNTER_DECAY_PER_TICK=300
SCAN_UNIQUE_PORT_THRESHOLD=12
BEACONING_MIN_REPEATS=4
LARGE_TRANSFER_THRESHOLD_BYTES=50000000
SCHEDULER_INTERVAL_SECONDS=10
RETRIEVER_TOP_K=4
TELEGRAM_ENABLED={"true" if telegram_bot_token and telegram_chat_id else "false"}
TELEGRAM_BOT_TOKEN={telegram_bot_token}
TELEGRAM_CHAT_ID={telegram_chat_id}
OLLAMA_URL={ollama_url}
OLLAMA_MODEL=llama3
OLLAMA_TIMEOUT_SECONDS=600
LLM_ENABLED=true
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
THREAT_SYNC_ENABLED=true
THREAT_SYNC_INTERVAL_HOURS=24
"""


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)

    mode = resolve_mode(args.mode)
    telegram_bot_token = ask("Telegram bot token", "")
    telegram_chat_id = ask("Telegram chat ID", "")
    trusted_ips = ask("Normal login IP addresses (comma separated)", "127.0.0.1")
    trusted_users = ask("Trusted admin usernames", "root,ubuntu")
    working_hours = ask("Normal working hours", "08:00-18:00")
    interfaces = ask("Network interfaces to monitor", "eth0")
    brute_force_threshold = ask("Brute force threshold", "5")
    sensitive_dirs = ask("Sensitive directories/files", "/etc/passwd,/etc/shadow,/etc/sudoers,/etc/crontab")
    allowed_countries = ask("Allowed countries", "ID,SG,US")
    ssh_ports = validate_csv_numbers(ask("SSH ports", "22"))
    webapp_ports = validate_csv_numbers(ask("Web app ports", "5000"))

    env_content = build_env_content(
        mode=mode,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        trusted_ips=trusted_ips,
        trusted_users=trusted_users,
        working_hours=working_hours,
        interfaces=interfaces,
        brute_force_threshold=brute_force_threshold,
        sensitive_dirs=sensitive_dirs,
        allowed_countries=allowed_countries,
        ssh_ports=ssh_ports,
        webapp_ports=webapp_ports,
    )
    ENV_PATH.write_text(env_content, encoding="utf-8")

    sqlite3.connect(BASE_DIR / "data" / "aegisai.db").close()

    default_config = {
        "mode": mode,
        "trusted_ips": trusted_ips.split(","),
        "trusted_users": trusted_users.split(","),
        "allowed_countries": allowed_countries.split(","),
        "interfaces": interfaces.split(","),
        "working_hours": working_hours,
        "ssh_ports": ssh_ports.split(","),
        "webapp_ports": webapp_ports.split(","),
    }
    (CONFIG_DIR / "baseline.json").write_text(json.dumps(default_config, indent=2), encoding="utf-8")
    print(f"Configuration written to {ENV_PATH}")
    print(f"Baseline written to {CONFIG_DIR / 'baseline.json'}")


if __name__ == "__main__":
    main()
