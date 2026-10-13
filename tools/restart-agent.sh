#!/usr/bin/env bash
#
# restart-agent.sh — idempotent restart of the local pentestcode runtime.
#
# Restarts the two user units that make up the agent stack, waits for the
# headless server to accept connections on 127.0.0.1:4096, then prints the
# attach URL. Safe to run repeatedly from a normal (non-root) user shell.
#
#   systemctl --user restart pentestcode-serve      # headless server (port 4096)
#   <poll 127.0.0.1:4096 up to ~30s>
#   systemctl --user restart opencode-telegram      # telegram bridge
#   print: pentestcode attach http://127.0.0.1:4096
#
# This script does NOT require root and does NOT touch anything outside the
# two user units. It is idempotent: running it again simply restarts again.

set -u

HOST="127.0.0.1"
PORT="4096"
TIMEOUT=30
SERVE_UNIT="pentestcode-serve"
TG_UNIT="opencode-telegram"

log()  { printf '[restart-agent] %s\n' "$*"; }
die()  { printf '[restart-agent] ERROR: %s\n' "$*" >&2; exit 1; }

# Fail early with a clear message if the user systemd bus is unavailable.
command -v systemctl >/dev/null 2>&1 || die "systemctl not found in PATH"
systemctl --user is-system-running >/dev/null 2>&1 || true

# ---- 1. restart the headless server -------------------------------------
log "restarting ${SERVE_UNIT} ..."
if ! systemctl --user restart "${SERVE_UNIT}"; then
    die "failed to restart ${SERVE_UNIT} (check: systemctl --user status ${SERVE_UNIT})"
fi

# ---- 2. wait for the port to accept connections -------------------------
# Prefer a real TCP connect; fall back to bash /dev/tcp if nc is missing.
port_open() {
    if command -v nc >/dev/null 2>&1; then
        nc -z -w1 "${HOST}" "${PORT}" >/dev/null 2>&1
    else
        ( exec 3<>"/dev/tcp/${HOST}/${PORT}" ) >/dev/null 2>&1
    fi
}

log "waiting for ${HOST}:${PORT} (up to ${TIMEOUT}s) ..."
ready=0
for _ in $(seq 1 "${TIMEOUT}"); do
    if port_open; then
        ready=1
        break
    fi
    sleep 1
done

if [ "${ready}" -ne 1 ]; then
    # The unit may be crash-looping (Restart=always, RestartSec=3).
    log "WARNING: ${HOST}:${PORT} did not accept a connection within ${TIMEOUT}s."
    log "         current unit state:"
    systemctl --user --no-pager --lines=0 status "${SERVE_UNIT}" 2>/dev/null | sed 's/^/         /' || true
    # Do not abort: still bring the bridge back up and print the URL so the
    # user can attach manually once the server finishes starting.
else
    log "${HOST}:${PORT} is accepting connections."
fi

# ---- 3. restart the telegram bridge -------------------------------------
log "restarting ${TG_UNIT} ..."
if ! systemctl --user restart "${TG_UNIT}"; then
    die "failed to restart ${TG_UNIT} (check: systemctl --user status ${TG_UNIT})"
fi

# ---- 4. done ------------------------------------------------------------
log "done."
printf '\npentestcode attach http://%s:%s\n' "${HOST}" "${PORT}"
