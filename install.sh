#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="docker"
OLLAMA_MODEL="llama3"
INSTALL_SYSTEMD="false"
SKIP_MODEL_PULL="false"
SKIP_COMPOSE_UP="false"

log() {
  printf '[AegisAI] %s\n' "$1"
}

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --mode docker|local      Deployment mode. Default: docker
  --model NAME             Ollama model to pull. Default: llama3
  --install-systemd        Install and enable the bundled systemd unit
  --skip-model-pull        Skip pulling the Ollama model
  --skip-compose-up        Skip docker compose up in docker mode
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --model)
      OLLAMA_MODEL="$2"
      shift 2
      ;;
    --install-systemd)
      INSTALL_SYSTEMD="true"
      shift
      ;;
    --skip-model-pull)
      SKIP_MODEL_PULL="true"
      shift
      ;;
    --skip-compose-up)
      SKIP_COMPOSE_UP="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "docker" && "$MODE" != "local" ]]; then
  echo "--mode must be docker or local" >&2
  exit 1
fi

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

install_apt_packages() {
  log "Installing OS dependencies"
  $SUDO apt-get update
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    gcc \
    libpcap-dev \
    net-tools \
    iproute2
}

install_docker_stack() {
  log "Installing Docker and Compose"
  $SUDO apt-get update
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose
  $SUDO systemctl enable --now docker
}

compose_command() {
  if docker compose version >/dev/null 2>&1; then
    printf 'docker compose'
  elif command -v docker-compose >/dev/null 2>&1; then
    printf 'docker-compose'
  else
    echo "Docker Compose is not installed" >&2
    exit 1
  fi
}

install_host_ollama() {
  if ! command -v ollama >/dev/null 2>&1; then
    log "Installing Ollama on host"
    curl -fsSL https://ollama.com/install.sh | sh
  fi
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now ollama || true
  fi
}

generate_config() {
  log "Generating ready-to-use configuration"
  python3 "$PROJECT_DIR/installation.py" --mode "$MODE" --ollama-model "$OLLAMA_MODEL"
}

bootstrap_local_python() {
  log "Creating Python virtual environment"
  python3 -m venv "$PROJECT_DIR/.venv"
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.venv/bin/activate"
  pip install --upgrade pip
  pip install -r "$PROJECT_DIR/requirements.txt"
}

bootstrap_local_runtime() {
  bootstrap_local_python
  install_host_ollama
  if [[ "$SKIP_MODEL_PULL" != "true" ]]; then
    log "Pulling Ollama model $OLLAMA_MODEL"
    ollama pull "$OLLAMA_MODEL"
  fi
  log "Initializing database"
  "$PROJECT_DIR/.venv/bin/python" -c "from app.database.db import init_db; init_db()"
}

bootstrap_docker_runtime() {
  install_docker_stack
  if [[ "$SKIP_COMPOSE_UP" != "true" ]]; then
    log "Building and starting docker stack"
    read -r -a COMPOSE_CMD <<< "$(compose_command)"
    $SUDO "${COMPOSE_CMD[@]}" -f "$PROJECT_DIR/docker-compose.yml" --project-directory "$PROJECT_DIR" up -d --build
  fi
  if [[ "$SKIP_MODEL_PULL" != "true" ]]; then
    log "Pulling Ollama model $OLLAMA_MODEL inside container"
    $SUDO docker exec aegisai-ollama ollama pull "$OLLAMA_MODEL"
  fi
}

install_systemd_unit() {
  log "Installing systemd service"
  $SUDO install -m 0644 "$PROJECT_DIR/systemd/aegisai.service" /etc/systemd/system/aegisai.service
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now aegisai.service
}

main() {
  cd "$PROJECT_DIR"
  install_apt_packages
  generate_config
  if [[ "$MODE" == "docker" ]]; then
    bootstrap_docker_runtime
  else
    bootstrap_local_runtime
  fi
  if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
    install_systemd_unit
  fi
  log "Installation complete"
  if [[ "$MODE" == "docker" ]]; then
    log "API should be reachable at http://localhost:8000/health after containers become healthy"
  else
    log "Run local services with .venv when needed. Ollama should now be available on localhost:11434"
  fi
}

main
