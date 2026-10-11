#!/usr/bin/env bash
# ==================================================================
#  CTF Learning Tree — one-shot запуск.
#  Собирает фронтенд (frontend/dist) и поднимает Go-сервер на :8090.
#
#  Использование:
#     ./run.sh                 # собрать и запустить на :8090
#     PORT=9000 ./run.sh       # другой порт
#     SKIP_FRONTEND=1 ./run.sh # не пересобирать SPA (использовать готовый dist)
# ==================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PORT="${PORT:-8090}"
CONTENT_DIR="${CONTENT_DIR:-content}"
DATA_DIR="${DATA_DIR:-data}"

# --- Проверка инструментов ---------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "ОШИБКА: не найден 'go'. Установите Go ≥ 1.23: https://go.dev/dl/" >&2
  exit 1
fi

# --- Сборка фронтенда --------------------------------------------
if [[ "${SKIP_FRONTEND:-0}" == "1" ]]; then
  echo "==> Пропускаю сборку фронтенда (SKIP_FRONTEND=1)"
else
  if ! command -v npm >/dev/null 2>&1; then
    echo "ОШИБКА: не найден 'npm'. Установите Node.js ≥ 18: https://nodejs.org/" >&2
    exit 1
  fi
  echo "==> Сборка фронтенда (frontend/dist)…"
  (
    cd frontend
    if [[ ! -d node_modules ]]; then
      echo "    npm install…"
      npm install
    fi
    npm run build
  )
fi

# --- Запуск сервера ----------------------------------------------
echo "==> Запуск сервера на http://localhost:${PORT}"
echo "    CONTENT_DIR=${CONTENT_DIR}  DATA_DIR=${DATA_DIR}"
exec env PORT="${PORT}" CONTENT_DIR="${CONTENT_DIR}" DATA_DIR="${DATA_DIR}" \
  go run ./cmd/server
