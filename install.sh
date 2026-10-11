#!/usr/bin/env bash
# ==================================================================
#  CTF Learning Tree — установка в одну строку.
#
#      curl -fsSL https://raw.githubusercontent.com/Serebr1k-code/cybersec-course/main/install.sh | sudo bash
#
#  Что делает скрипт:
#    1. Проверяет, что запущен от root, определяет ОС (Debian/Ubuntu/Arch)
#       и автоматически выбирает пакетный менеджер (apt или pacman) в PKG_MGR.
#    2. Ставит недостающие зависимости: git, curl, Go (>=1.23), Node.js (>=18).
#    3. Клонирует/обновляет проект в /opt/cybersec-course.
#    4. Собирает бэкенд (bin/learningtree) и SPA (frontend/dist).
#    5. Ставит systemd-юнит cybersec-course (автозапуск, Restart=always).
#    6. Печатает итоговый URL.
#
#  Скрипт идемпотентен: повторный запуск обновляет код, пересобирает
#  и перезапускает сервис.
#
#  Переопределяемые переменные окружения:
#    PORT=41837            порт HTTP-сервера
#    INSTALL_DIR=/opt/cybersec-course
#    GO_VERSION=1.23.4     версия Go для загрузки тарболом
#    REPO_URL=https://github.com/Serebr1k-code/cybersec-course.git
#    BRANCH=main
# ==================================================================
set -euo pipefail

# ---------- Настройки ---------------------------------------------
PORT="${PORT:-41837}"
INSTALL_DIR="${INSTALL_DIR:-/opt/cybersec-course}"
SERVICE_NAME="${SERVICE_NAME:-cybersec-course}"
REPO_URL="${REPO_URL:-https://github.com/Serebr1k-code/cybersec-course.git}"
BRANCH="${BRANCH:-main}"
GO_VERSION="${GO_VERSION:-1.23.4}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=23
NODE_MIN_MAJOR=18
NODE_FALLBACK_VERSION="${NODE_FALLBACK_VERSION:-20.18.1}"
PKG_MGR=""   # выставляется в detect_os(): "apt" | "pacman"

# ---------- Цветной вывод -----------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_INFO=$'\033[1;34m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
else
  C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
fi
step() { printf '\n%s==>%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_OK" "$C_RESET" "$*"; }
warn() { printf '%s  !!%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
die()  { printf '%s ОШИБКА:%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2; exit 1; }

# ---------- Требуем root ------------------------------------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "запустите скрипт от root:  curl -fsSL <url> | sudo bash"
fi

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"

# ---------- Определение ОС ----------------------------------------
detect_os() {
  step "Определяю операционную систему"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_CODENAME="${VERSION_CODENAME:-}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  else
    OS_ID="unknown"; OS_LIKE=""; OS_CODENAME=""; OS_PRETTY="unknown"
  fi
  ok "ОС: $OS_PRETTY (id=$OS_ID, like=${OS_LIKE:-none})"

  # Выбираем пакетный менеджер: apt для Debian/Ubuntu, pacman для Arch.
  if [[ "$OS_ID" == "arch" || "$OS_LIKE" == *arch* ]]; then
    PKG_MGR="pacman"
  elif [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" || "$OS_LIKE" == *debian* || "$OS_LIKE" == *ubuntu* ]]; then
    PKG_MGR="apt"
  else
    die "поддерживаются только Debian/Ubuntu/Arch-семейства (обнаружено: $OS_ID). Установите Go>=1.23 и Node>=18 вручную и запустите build."
  fi
  ok "Пакетный менеджер: $PKG_MGR"
}

apt_install() {
  # apt_install <pkg...> — тихая установка пакетов.
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "$@"
}

pacman_install() {
  # pacman_install <pkg...> — установка пакетов через pacman (Arch).
  pacman -Sy --noconfirm --needed "$@"
}

pkg_install() {
  # pkg_install <pkg...> — роутинг через выбранный PKG_MGR.
  if [[ "$PKG_MGR" == "pacman" ]]; then
    pacman_install "$@"
  else
    apt_install "$@"
  fi
}

# ---------- Сравнение версий (major.minor) ------------------------
ver_ge() {
  # ver_ge <текущая> <min_major> <min_minor>  -> 0, если >=
  local cur="$1" min_major="$2" min_minor="$3"
  local major minor
  major="${cur%%.*}"
  minor="${cur#*.}"; minor="${minor%%.*}"
  major="${major:-0}"; minor="${minor:-0}"
  (( major > min_major )) && return 0
  (( major == min_major && minor >= min_minor )) && return 0
  return 1
}

go_installed_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v="$(go version 2>/dev/null | awk '{print $3}')"   # go1.26.1
  v="${v#go}"
  ver_ge "$v" "$GO_MIN_MAJOR" "$GO_MIN_MINOR"
}

node_installed_ok() {
  command -v node >/dev/null 2>&1 || return 1
  local v
  v="$(node -v 2>/dev/null)"                          # v20.11.0
  v="${v#v}"
  ver_ge "$v" "$NODE_MIN_MAJOR" 0
}

install_node_tarball() {
  # Универсальный fallback: официальный тарбол Node (без NodeSource).
  local ver="$NODE_FALLBACK_VERSION"
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "неизвестная архитектура для Node: $(uname -m)" ;;
  esac
  local dir="/usr/local/node-v${ver}-linux-${arch}"
  local tarball="/tmp/node-v${ver}-linux-${arch}.tar.gz"
  curl -fsSL "https://nodejs.org/dist/v${ver}/node-v${ver}-linux-${arch}.tar.gz" -o "$tarball" \
    || die "не удалось скачать Node ${ver}"
  rm -rf "$dir"
  tar -C /usr/local -xzf "$tarball"
  rm -f "$tarball"
  ln -sf "${dir}/bin/node" /usr/local/bin/node
  ln -sf "${dir}/bin/npm"  /usr/local/bin/npm
  ln -sf "${dir}/bin/npx"  /usr/local/bin/npx
  hash -r || true
}

# ---------- Установка зависимостей --------------------------------
install_prereqs() {
  step "Проверяю базовые утилиты (git, curl, ca-certificates, tar)"
  local base_missing=()
  command -v git >/dev/null 2>&1 || base_missing+=(git)
  command -v curl >/dev/null 2>&1 || base_missing+=(curl)
  command -v tar >/dev/null 2>&1 || base_missing+=(tar)
  if [[ ! -e /etc/ssl/certs/ca-certificates.crt ]]; then
    # Имя пакета сертификатов зависит от дистрибутива.
    if [[ "$PKG_MGR" == "pacman" ]]; then
      base_missing+=(ca-certificates-utils)
    else
      base_missing+=(ca-certificates)
    fi
  fi
  if (( ${#base_missing[@]} )); then
    ok "устанавливаю: ${base_missing[*]}"
    pkg_install "${base_missing[@]}"
  else
    ok "базовые утилиты на месте"
  fi

  # --- Go ---------------------------------------------------------
  step "Проверяю Go (нужен >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR})"
  if go_installed_ok; then
    ok "Go уже установлен: $(go version)"
  else
    if [[ "$PKG_MGR" == "pacman" ]]; then
      warn "Go не найден или слишком старый — ставлю go через pacman"
      pacman_install go || true
    else
      warn "Go не найден или слишком старый — пробую apt"
      apt_install golang-go || true
    fi
    if go_installed_ok; then
      ok "Go установлен через ${PKG_MGR}: $(go version)"
    else
      warn "${PKG_MGR} не дал Go>=${GO_MIN_MAJOR}.${GO_MIN_MINOR} — качаю официальный тарбол ${GO_VERSION}"
      local arch
      case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "неизвестная архитектура: $(uname -m)" ;;
      esac
      local tarball="/tmp/go${GO_VERSION}.linux-${arch}.tar.gz"
      curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o "$tarball" \
        || die "не удалось скачать Go ${GO_VERSION}"
      rm -rf /usr/local/go
      tar -C /usr/local -xzf "$tarball"
      rm -f "$tarball"
      export PATH="/usr/local/go/bin:$PATH"
      hash -r || true
      go_installed_ok || die "Go всё ещё недоступен после установки"
      ok "Go установлен: $(go version)"
    fi
  fi

  # --- Node.js + npm ---------------------------------------------
  step "Проверяю Node.js (нужен >= ${NODE_MIN_MAJOR}) и npm"
  if node_installed_ok && command -v npm >/dev/null 2>&1; then
    ok "Node уже установлен: $(node -v), npm $(npm -v)"
  else
    if [[ "$PKG_MGR" == "pacman" ]]; then
      warn "Node.js не найден или слишком старый — ставлю nodejs+npm через pacman"
      pacman_install nodejs npm || true
      if ! (node_installed_ok && command -v npm >/dev/null 2>&1); then
        warn "pacman дал слишком старый Node — качаю официальный тарбол Node ${NODE_FALLBACK_VERSION}"
        install_node_tarball
      fi
    else
      warn "Node.js не найден или слишком старый — ставлю через apt"
      apt_install nodejs npm || true
      if ! (node_installed_ok && command -v npm >/dev/null 2>&1); then
        warn "apt дал слишком старый Node — подключаю NodeSource (20.x)"
        curl -fsSL https://deb.nodesource.com/setup_20.x -o /tmp/nodesource_setup.sh \
          || die "не удалось скачать NodeSource setup"
        bash /tmp/nodesource_setup.sh
        rm -f /tmp/nodesource_setup.sh
        apt_install nodejs
      fi
    fi
    node_installed_ok || die "Node.js >= ${NODE_MIN_MAJOR} не установился"
    command -v npm >/dev/null 2>&1 || die "npm не установился"
    ok "Node.js установлен: $(node -v), npm $(npm -v)"
  fi
}

# ---------- Получение исходников ----------------------------------
fetch_project() {
  step "Получаю исходники в $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"

  if command -v git >/dev/null 2>&1; then
    if [[ -d "$INSTALL_DIR/.git" ]]; then
      ok "репозиторий уже есть — обновляю (git fetch/reset)"
      git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
      git -C "$INSTALL_DIR" fetch --depth 1 origin "$BRANCH"
      git -C "$INSTALL_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
      git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
    else
      ok "клонирую $REPO_URL (--depth 1)"
      rm -rf "$INSTALL_DIR"
      git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    fi
  else
    warn "git недоступен — скачиваю тарбол ветки $BRANCH"
    local tb="/tmp/cybersec-course.tar.gz"
    curl -fsSL "https://github.com/Serebr1k-code/cybersec-course/archive/refs/heads/${BRANCH}.tar.gz" -o "$tb" \
      || die "не удалось скачать тарбол проекта"
    rm -rf "$INSTALL_DIR" /tmp/cybersec-course-*
    mkdir -p /tmp/cybersec-course-extract
    tar -C /tmp/cybersec-course-extract -xzf "$tb"
    local extracted
    extracted="$(find /tmp/cybersec-course-extract -mindepth 1 -maxdepth 1 -type d | head -n1)"
    [[ -n "$extracted" ]] || die "архив проекта пуст/повреждён"
    mv "$extracted" "$INSTALL_DIR"
    rm -rf /tmp/cybersec-course-extract "$tb"
  fi
  ok "исходники готовы: $INSTALL_DIR"
}

# ---------- Сборка -------------------------------------------------
build_project() {
  step "Собираю бэкенд (Go)"
  ( cd "$INSTALL_DIR" && CGO_ENABLED=0 go build -o bin/learningtree ./cmd/server )
  ok "готово: $INSTALL_DIR/bin/learningtree"

  step "Собираю фронтенд (Node/Vite)"
  (
    cd "$INSTALL_DIR/frontend"
    if [[ -f package-lock.json ]]; then
      npm ci --no-audit --no-fund
    else
      npm install --no-audit --no-fund
    fi
    npm run build
  )
  ok "готово: $INSTALL_DIR/frontend/dist"

  mkdir -p "$INSTALL_DIR/data"
}

# ---------- systemd -------------------------------------------------
install_service() {
  step "Устанавливаю systemd-юнит ${SERVICE_NAME}.service"
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl не найден (не systemd-система?) — юнит не активирую"
    warn "ручной запуск: $INSTALL_DIR/bin/learningtree -addr :${PORT} -content content -data data -static frontend/dist"
    return 0
  fi

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=CTF Learning Tree (cybersec-course)
Documentation=https://github.com/Serebr1k-code/cybersec-course
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/learningtree -addr :${PORT} -content content -data data -static frontend/dist
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  ok "юнит записан: /etc/systemd/system/${SERVICE_NAME}.service"

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_NAME}.service"
  ok "сервис включён и запущен"
}

# ---------- Итог ----------------------------------------------------
finish() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ip="${ip:-127.0.0.1}"
  step "Готово!"
  echo "  Локально:  http://localhost:${PORT}/"
  echo "  По сети:   http://${ip}:${PORT}/"
  if command -v systemctl >/dev/null 2>&1; then
    echo "  Сервис:    systemctl status ${SERVICE_NAME}"
    echo "  Логи:      journalctl -u ${SERVICE_NAME} -f"
  fi
  echo "  Каталог:   ${INSTALL_DIR}"
}

# ---------- main ----------------------------------------------------
main() {
  step "CTF Learning Tree — установщик (порт ${PORT}, каталог ${INSTALL_DIR})"
  detect_os
  install_prereqs
  fetch_project
  build_project
  install_service
  finish
}
main "$@"
