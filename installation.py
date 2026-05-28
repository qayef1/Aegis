from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ENV_EXAMPLE_PATH = BASE_DIR / ".env.example"
ENV_PATH = BASE_DIR / ".env"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def write_env_file(path: Path, values: dict[str, str]) -> None:
    lines = [f"{key}={value}" for key, value in values.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_env(args: argparse.Namespace) -> dict[str, str]:
    env = parse_env_file(ENV_EXAMPLE_PATH)
    env.update(
        {
            "APP_NAME": "AegisAI",
            "ENVIRONMENT": "production",
            "LOG_LEVEL": "INFO",
            "HOST_USER_HOME": str(Path.home()),
            "MONITORED_INTERFACES": args.interfaces,
            "TRUSTED_LOGIN_IPS": args.trusted_ips,
            "TRUSTED_ADMIN_USERS": args.trusted_users,
            "ALLOWED_COUNTRIES": args.allowed_countries,
            "NORMAL_WORKING_HOURS": args.working_hours,
            "SSH_PORTS": args.ssh_ports,
            "WEBAPP_PORTS": args.webapp_ports,
            "BRUTE_FORCE_THRESHOLD": str(args.brute_force_threshold),
            "DDOS_COUNTER_DECAY_PER_TICK": "300",
            "TELEGRAM_ENABLED": "true" if args.telegram_bot_token and args.telegram_chat_id else "false",
            "TELEGRAM_BOT_TOKEN": args.telegram_bot_token,
            "TELEGRAM_CHAT_ID": args.telegram_chat_id,
            "OLLAMA_MODEL": args.ollama_model,
            "LLM_ENABLED": "true",
            "THREAT_SYNC_ENABLED": "true",
        }
    )

    if args.mode == "local":
        env.update(
            {
                "DATABASE_URL": f"sqlite:///{BASE_DIR / 'data' / 'aegisai.db'}",
                "CHROMA_PATH": str(BASE_DIR / "data" / "chroma"),
                "RAW_LOG_DIR": str(LOG_DIR),
                "WEBAPP_LOG_FILE": str(LOG_DIR / "vulnerable_webapp.log"),
                "AUTH_LOG_PATHS": "/var/log/auth.log,/var/log/secure",
                "PACKAGE_LOG_PATHS": "/var/log/dpkg.log,/var/log/apt/history.log",
                "HISTORY_FILES": f"{Path.home() / '.bash_history'},{Path.home() / '.zsh_history'}",
                "OLLAMA_URL": "http://localhost:11434/api/generate",
                "OLLAMA_TIMEOUT_SECONDS": "600",
            }
        )
    else:
        env.update(
            {
                "DATABASE_URL": "sqlite:////app/data/aegisai.db",
                "CHROMA_PATH": "/app/data/chroma",
                "RAW_LOG_DIR": "/app/logs",
                "WEBAPP_LOG_FILE": "/app/logs/vulnerable_webapp.log",
                "AUTH_LOG_PATHS": "/host/var/log/auth.log,/host/var/log/secure",
                "PACKAGE_LOG_PATHS": "/host/var/log/dpkg.log,/host/var/log/apt/history.log",
                "HISTORY_FILES": "/root/.bash_history,/root/.zsh_history",
                "OLLAMA_URL": "http://localhost:11434/api/generate",
                "OLLAMA_TIMEOUT_SECONDS": "600",
            }
        )
    return env


def write_baseline(args: argparse.Namespace) -> None:
    baseline = {
        "trusted_ips": [item for item in args.trusted_ips.split(",") if item],
        "trusted_users": [item for item in args.trusted_users.split(",") if item],
        "allowed_countries": [item for item in args.allowed_countries.split(",") if item],
        "interfaces": [item for item in args.interfaces.split(",") if item],
        "working_hours": args.working_hours,
        "ssh_ports": [item for item in args.ssh_ports.split(",") if item],
        "webapp_ports": [item for item in args.webapp_ports.split(",") if item],
    }
    (CONFIG_DIR / "baseline.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def init_storage() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    sqlite3.connect(DATA_DIR / "aegisai.db").close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate ready-to-use AegisAI configuration.")
    parser.add_argument("--mode", choices=["docker", "local"], default="docker")
    parser.add_argument("--interfaces", default="eth0")
    parser.add_argument("--trusted-ips", default="127.0.0.1")
    parser.add_argument("--trusted-users", default="root,ubuntu")
    parser.add_argument("--allowed-countries", default="ID,SG,US")
    parser.add_argument("--working-hours", default="08:00-18:00")
    parser.add_argument("--ssh-ports", default="22")
    parser.add_argument("--webapp-ports", default="5000")
    parser.add_argument("--brute-force-threshold", type=int, default=5)
    parser.add_argument("--ollama-model", default="llama3")
    parser.add_argument("--telegram-bot-token", default="")
    parser.add_argument("--telegram-chat-id", default="")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    init_storage()
    env = build_env(args)
    write_env_file(ENV_PATH, env)
    write_baseline(args)
    print(f"Wrote {ENV_PATH}")
    print(f"Wrote {CONFIG_DIR / 'baseline.json'}")
    print(f"Initialized {DATA_DIR / 'aegisai.db'}")


if __name__ == "__main__":
    main()
