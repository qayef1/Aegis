from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "AegisAI"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = f"sqlite:///{BASE_DIR / 'data' / 'aegisai.db'}"
    chroma_path: str = str(BASE_DIR / "data" / "chroma")
    raw_log_dir: str = str(BASE_DIR / "logs")
    webapp_log_file: str = str(BASE_DIR / "logs" / "vulnerable_webapp.log")
    auth_log_paths: str = "/var/log/auth.log,/var/log/secure"
    history_files: str = "~/.bash_history,~/.zsh_history"
    package_log_paths: str = "/var/log/dpkg.log,/var/log/apt/history.log"
    monitored_interfaces: str = "eth0"
    sensitive_paths: str = "/etc/passwd,/etc/shadow,/etc/sudoers,/etc/crontab"
    trusted_admin_users: str = "root,ubuntu"
    trusted_login_ips: str = "127.0.0.1"
    allowed_countries: str = "ID,SG,US"
    normal_working_hours: str = "08:00-18:00"
    ssh_ports: str = "22"
    webapp_ports: str = "5000"
    high_risk_ports: str = "21,22,23,3389,4444,5555,8080"
    packet_window_seconds: int = 10
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    ddos_packet_threshold: int = 300
    ddos_counter_decay_per_tick: int = 300
    scan_unique_port_threshold: int = 12
    beaconing_min_repeats: int = 4
    large_transfer_threshold_bytes: int = 50_000_000
    scheduler_interval_seconds: int = 10
    retriever_top_k: int = 4
    llm_enabled: bool = True
    ollama_url: str = "http://ollama:11434/api/generate"
    ollama_model: str = "llama3"
    ollama_timeout_seconds: int = 600
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_min_risk_score: int = 75
    telegram_max_alerts_per_tick: int = 20
    threat_sync_enabled: bool = True
    threat_sync_interval_hours: int = 24

    @computed_field
    @property
    def auth_log_path_list(self) -> List[str]:
        return [item.strip() for item in self.auth_log_paths.split(",") if item.strip()]

    @computed_field
    @property
    def package_log_path_list(self) -> List[str]:
        return [item.strip() for item in self.package_log_paths.split(",") if item.strip()]

    @computed_field
    @property
    def history_file_list(self) -> List[str]:
        return [str(Path(item.strip()).expanduser()) for item in self.history_files.split(",") if item.strip()]

    @computed_field
    @property
    def monitored_interface_list(self) -> List[str]:
        return [item.strip() for item in self.monitored_interfaces.split(",") if item.strip()]

    @computed_field
    @property
    def sensitive_path_list(self) -> List[str]:
        return [item.strip() for item in self.sensitive_paths.split(",") if item.strip()]

    @computed_field
    @property
    def trusted_admin_user_list(self) -> List[str]:
        return [item.strip() for item in self.trusted_admin_users.split(",") if item.strip()]

    @computed_field
    @property
    def trusted_login_ip_list(self) -> List[str]:
        return [item.strip() for item in self.trusted_login_ips.split(",") if item.strip()]

    @computed_field
    @property
    def allowed_country_list(self) -> List[str]:
        return [item.strip().upper() for item in self.allowed_countries.split(",") if item.strip()]

    @computed_field
    @property
    def ssh_port_list(self) -> List[int]:
        return [int(item.strip()) for item in self.ssh_ports.split(",") if item.strip()]

    @computed_field
    @property
    def webapp_port_list(self) -> List[int]:
        return [int(item.strip()) for item in self.webapp_ports.split(",") if item.strip()]

    @computed_field
    @property
    def high_risk_port_list(self) -> List[int]:
        return [int(item.strip()) for item in self.high_risk_ports.split(",") if item.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
