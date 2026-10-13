#!/usr/bin/env bash
#
# db-maintain.sh -- prune + VACUUM + restart the local pentestcode session store.
#
# Why this exists
# ---------------
# The pentestcode session store is an event-sourced SQLite DB. Every session /
# subagent writes a `message.part.updated.1` row per streamed chunk into `event`
# (aggregate_id = session id, data = full JSON payload). Long lab-authoring
# subagents blow it up to tens of GB. The DB runs with PRAGMA auto_vacuum=0 and
# an empty freelist, so the file NEVER shrinks on its own -- only an offline
# VACUUM reclaims the space.
#
# Why it prunes in BATCHES (not one big transaction)
# --------------------------------------------------
# SQLite is in WAL mode. A DELETE writes the new image of every modified page to
# the WAL before commit. Deleting ~825k `event` rows modifies almost every page
# of a ~14 GB table, so a SINGLE transaction needs ~14 GB of WAL space. On a 99%
# full disk that fails with "database or disk is full" and rolls back. This script
# therefore deletes one bounded batch of sessions at a time (each batch = its own
# transaction) and runs wal_checkpoint(TRUNCATE) between batches so the WAL never
# grows beyond one batch. Each batch is atomic; the whole run is resumable.
#
# What it does (in order)
#   1. Refuses to run while the server is up (unless you pass --stop).
#   2. Truncates any leftover WAL so we start from a known-free state.
#   3. Makes a safety copy IF the disk has room (otherwise warns and skips).
#   4. Prints before counts; FK-safe prunes SUBAGENT sessions only, ALWAYS keeping
#      every top-level session (parent_id IS NULL) plus the newest --keep subagents.
#   5. VACUUM + WAL checkpoint to actually shrink the file.
#   6. Prints size before/after and df -h /home.
#   7. Restarts the server and prints the attach command.
#
# Usage:
#   systemctl --user stop pentestcode-serve     # stop first (recommended)
#   tools/db-maintain.sh [--keep N] [--batch-sessions N] [--no-backup]
#
#   tools/db-maintain.sh --stop --keep 3        # one-shot: stop, prune, restart
#
# Options:
#   --keep N            also keep the N most recently updated SUBAGENT sessions
#                       (default 3).  Top-level sessions are ALWAYS kept.
#   --batch-sessions N  delete at most N sessions per transaction batch (default 20)
#   --stop         stop the running server first (opt-in; default refuses)
#   --no-backup    skip the safety copy even if space allows
#   -h, --help     show this help
#
set -euo pipefail

SERVICE="${PENTESTCODE_SERVICE:-pentestcode-serve}"
HOST="127.0.0.1"
PORT="${PENTESTCODE_PORT:-4096}"
KEEP=3
BATCH_SESSIONS=20
STOP_FIRST=0
DO_BACKUP=1

log()  { printf '[db-maintain] %s\n' "$*"; }
warn() { printf '[db-maintain] WARNING: %s\n' "$*" >&2; }
die()  { printf '[db-maintain] ERROR: %s\n' "$*" >&2; exit 1; }

human() { awk -v b="${1:-0}" 'BEGIN{split("B KB MB GB TB PB",u," ");i=1;while(b>=1024&&i<6){b/=1024;i++}printf "%.1f%s",b,u[i]}'; }

usage() { sed -n '2,47p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --keep)     [ $# -ge 2 ] || die "--keep requires a number"; KEEP="$2"; shift 2 ;;
    --keep=*)   KEEP="${1#*=}"; shift ;;
    --batch-sessions) [ $# -ge 2 ] || die "--batch-sessions requires a number"; BATCH_SESSIONS="$2"; shift 2 ;;
    --batch-sessions=*) BATCH_SESSIONS="${1#*=}"; shift ;;
    --batch-mb)   warn "--batch-mb is deprecated and ignored (batching is now by session count; use --batch-sessions)"; shift; if [ $# -ge 1 ] && [[ "$1" =~ ^[0-9]+$ ]]; then shift; fi ;;
    --batch-mb=*) warn "--batch-mb is deprecated and ignored (batching is now by session count; use --batch-sessions)"; shift ;;
    --stop)     STOP_FIRST=1; shift ;;
    --no-backup) DO_BACKUP=0; shift ;;
    -h|--help)  usage; exit 0 ;;
    *)          die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$KEEP" =~ ^[0-9]+$ ]] && [ "$KEEP" -ge 1 ] || die "--keep must be a positive integer"
[[ "$BATCH_SESSIONS" =~ ^[0-9]+$ ]] && [ "$BATCH_SESSIONS" -ge 1 ] || die "--batch-sessions must be a positive integer"

# --- resolve the DB path (ask the CLI, fall back to the default) -------------
DB="$(pentestcode db path 2>/dev/null || true)"
DB="${DB:-$HOME/.local/share/pentestcode/pentestcode.db}"
[ -f "$DB" ] || die "DB not found: $DB"
command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 not found in PATH"

log "DB path: $DB"

# KEEP set = EVERY top-level session (parent_id IS NULL).  The live coordinator /
# TUI session is typically OLD, so it falls OUTSIDE any "newest N" window and
# would be deleted by a time-based keep-set -- keeping all parent_id-NULL rows is
# what makes it impossible to purge the running session.  We ALSO keep the $KEEP
# most recently updated SUBAGENT sessions (parent_id IS NOT NULL) so a recently
# resumed child survives; every other subagent is purged.
KEEP_SQL="SELECT id FROM session WHERE parent_id IS NULL"
KEEP_SQL="$KEEP_SQL UNION SELECT id FROM (SELECT id FROM session WHERE parent_id IS NOT NULL ORDER BY time_updated DESC LIMIT $KEEP)"

# --- SAFETY ASSERT (never purge the coordinator) ---------------------------
# Verify the computed keep-set covers EVERY top-level (parent_id IS NULL)
# session.  A future edit that breaks this would silently delete the live
# coordinator session, so ABORT before any destructive step.
TOPLEVEL_TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM session WHERE parent_id IS NULL;")
TOPLEVEL_KEPT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM session WHERE parent_id IS NULL AND id IN ($KEEP_SQL);")
if [ "$TOPLEVEL_KEPT" != "$TOPLEVEL_TOTAL" ]; then
  die "SAFETY ASSERT FAILED: keep-set covers only $TOPLEVEL_KEPT of $TOPLEVEL_TOTAL top-level (parent_id IS NULL) sessions -- refusing to purge (this would delete the live coordinator session)."
fi
log "Safety assert OK: all $TOPLEVEL_TOTAL top-level session(s) are protected."

port_listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$"
  else
    (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null
  fi
}
unit_active() { systemctl --user is-active --quiet "$SERVICE" 2>/dev/null; }

counts() {
  sqlite3 -column -header "$DB" "
    SELECT 'sessions'       AS table_name, COUNT(*) AS rows FROM session
    UNION ALL SELECT 'events',          COUNT(*) FROM event
    UNION ALL SELECT 'event_sequence',  COUNT(*) FROM event_sequence
    UNION ALL SELECT 'messages',        COUNT(*) FROM message
    UNION ALL SELECT 'parts',           COUNT(*) FROM part;"
}

checkpoint() { sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true; }

# delete one batch of sessions (children first) inside a single transaction
run_batch() {
  local ids="" id
  for id in "$@"; do ids+=",'${id//\'/\'\'}'"; done
  ids="${ids#,}"
  sqlite3 "$DB" <<SQL
PRAGMA foreign_keys=ON;
BEGIN IMMEDIATE;
DELETE FROM event                 WHERE aggregate_id IN ($ids);
DELETE FROM event_sequence        WHERE aggregate_id IN ($ids);
DELETE FROM part                  WHERE session_id   IN ($ids);
DELETE FROM message               WHERE session_id   IN ($ids);
DELETE FROM session_message       WHERE session_id   IN ($ids);
DELETE FROM session_input         WHERE session_id   IN ($ids);
DELETE FROM session_context_epoch WHERE session_id   IN ($ids);
DELETE FROM todo                  WHERE session_id   IN ($ids);
DELETE FROM session_share         WHERE session_id   IN ($ids);
DELETE FROM session               WHERE id           IN ($ids);
COMMIT;
SQL
  checkpoint
}

# ===========================================================================
# 1. Verify the server is STOPPED
# ===========================================================================
RUNNING=0
if port_listening; then RUNNING=1; fi
if unit_active;    then RUNNING=1; fi

if [ "$RUNNING" = 1 ]; then
  if [ "$STOP_FIRST" = 1 ]; then
    log "Stopping $SERVICE (--stop requested) ..."
    systemctl --user stop "$SERVICE" || die "failed to stop $SERVICE"
    for _ in $(seq 1 30); do
      if ! port_listening; then break; fi
      sleep 1
    done
    if port_listening; then
      die "$HOST:$PORT is still listening after 'systemctl --user stop $SERVICE'"
    fi
    log "Server stopped."
  else
    cat >&2 <<EOF
[db-maintain] ERROR: the pentestcode server is still RUNNING
[db-maintain]   $HOST:$PORT is listening and/or the unit '$SERVICE' is active.
[db-maintain]
[db-maintain] Stop it first, then re-run:
[db-maintain]     systemctl --user stop $SERVICE
[db-maintain]     $0 --keep $KEEP
[db-maintain]
[db-maintain] (Or re-run with --stop to have this script stop it for you:
[db-maintain]     $0 --stop --keep $KEEP )
EOF
    exit 1
  fi
fi

# ===========================================================================
# 2. Start from a known-free state: truncate any leftover WAL
# ===========================================================================
BEFORE_BYTES=$(stat -c %s "$DB")
log "Truncating any leftover WAL ..."
checkpoint

# ===========================================================================
# 3. Safety copy (only if there is room)
# ===========================================================================
WAL_BYTES=$(stat -c %s "$DB-wal" 2>/dev/null || echo 0)
DBDIR=$(dirname "$DB")
FREE_BYTES=$(df -Pk "$DBDIR" | awk 'NR==2 {print $4*1024}')
NEED_BYTES=$((BEFORE_BYTES + WAL_BYTES))
MARGIN_BYTES=$((1024*1024*1024))   # keep 1 GiB headroom

log "DB size: $(human "$BEFORE_BYTES")   free on $DBDIR: $(human "$FREE_BYTES")"

if [ "$DO_BACKUP" = 1 ]; then
  if [ "$FREE_BYTES" -ge $((NEED_BYTES + MARGIN_BYTES)) ]; then
    BAK="${DB}.bak-$(date +%Y%m%d-%H%M%S)"
    log "Creating consistent safety copy -> $BAK"
    if sqlite3 "$DB" ".backup '$BAK'"; then
      log "Safety copy OK: $(human "$(stat -c %s "$BAK")")"
    else
      rm -f "$BAK"; warn "safety copy FAILED -- continuing without it"
    fi
  else
    warn "not enough free space for a safety copy (need ~$(human "$NEED_BYTES"), have $(human "$FREE_BYTES")) -- SKIPPING backup."
    warn "proceeding WITHOUT a backup; make sure you have another copy."
  fi
else
  log "--no-backup: skipping safety copy."
fi

# ===========================================================================
# 4. Prune everything except the kept sessions (batched, FK-safe, resumable)
# ===========================================================================
log "Row counts BEFORE:"
counts

log "Keeping $TOPLEVEL_TOTAL top-level session(s) + the $KEEP most recent subagent(s):"
sqlite3 -column -header "$DB" "
  SELECT id, datetime(time_created/1000,'unixepoch','localtime') AS created,
         CASE WHEN parent_id IS NULL THEN 'top-level' ELSE 'subagent' END AS kind
  FROM session WHERE id IN ($KEEP_SQL) ORDER BY (parent_id IS NOT NULL), time_created DESC;"

PURGE_TSV=$(mktemp /tmp/db-maintain-purge.XXXXXX)
trap 'rm -f "$PURGE_TSV"' EXIT

# Purge candidates = SUBAGENT sessions (parent_id IS NOT NULL) not in the
# keep-set.  NOTE: deliberately NO SUM(LENGTH(e.data)) -- that aggregate over
# the multi-GB `event` table is pathologically slow (it scans ~all of it per
# session) and was the cause of the apparent hang.  We select session ids only.
sqlite3 -separator '|' "$DB" "
  SELECT id FROM session
  WHERE parent_id IS NOT NULL AND id NOT IN ($KEEP_SQL)
  ORDER BY time_created ASC;" > "$PURGE_TSV"

TOTAL=$(wc -l < "$PURGE_TSV")
log "Sessions to purge: $TOTAL   (batch size: ${BATCH_SESSIONS} sessions/transaction)"

batch=(); done_n=0; batch_n=0
flush_batch() {
  [ "${#batch[@]}" -eq 0 ] && return 0
  batch_n=$((batch_n + 1))
  run_batch "${batch[@]}"
  done_n=$((done_n + ${#batch[@]}))
  printf '[db-maintain]   batch %d: %d sessions (cumulative %d/%d)\n' "$batch_n" "${#batch[@]}" "$done_n" "$TOTAL"
  batch=()
}
while IFS='|' read -r sid _; do
  [ -z "$sid" ] && continue
  if [ "${#batch[@]}" -ge "$BATCH_SESSIONS" ]; then
    flush_batch
  fi
  batch+=("$sid")
done < "$PURGE_TSV"
flush_batch

log "Row counts AFTER:"
counts

FKCHECK=$(sqlite3 "$DB" "PRAGMA foreign_key_check;")
if [ -z "$FKCHECK" ]; then log "  foreign_key_check: clean"; else warn "  foreign_key_check reported: $FKCHECK"; fi

# ===========================================================================
# 5. VACUUM + WAL checkpoint (actually reclaim the disk)
# ===========================================================================
log "Running VACUUM (rewrites the file; may take a while) ..."
sqlite3 "$DB" "PRAGMA foreign_keys=ON; VACUUM; PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
log "Integrity: $(sqlite3 "$DB" 'PRAGMA integrity_check;' | head -1)"

# ===========================================================================
# 6. Report sizes
# ===========================================================================
AFTER_BYTES=$(stat -c %s "$DB")
log "DB size: $(human "$BEFORE_BYTES") -> $(human "$AFTER_BYTES")  (reclaimed $(human "$((BEFORE_BYTES - AFTER_BYTES))"))"
df -h /home

# ===========================================================================
# 7. Restart the server
# ===========================================================================
log "Starting $SERVICE ..."
systemctl --user start "$SERVICE" || die "failed to start $SERVICE"
for _ in $(seq 1 30); do
  if port_listening; then break; fi
  sleep 1
done
echo
if port_listening; then
  log "Server is up on $HOST:$PORT."
  echo "pentestcode attach http://${HOST}:${PORT}"
else
  warn "unit started but $HOST:$PORT is not listening yet."
  warn "check: systemctl --user status $SERVICE"
  exit 1
fi
