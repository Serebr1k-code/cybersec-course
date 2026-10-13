#!/usr/bin/env bash
# ==================================================================
#  lab-record.sh — capture REAL tool output into a lab fixture bundle.
#
#  The lab engine never invents tool output: external tools (nmap, curl,
#  gobuster, unzip, …) are replayed from fixtures captured ONCE on a real
#  machine/container. This helper turns a real command run into the exact JSON
#  fragments a bundle needs.
#
#  Usage
#  -----
#    # 1) a skeleton bundle to start from
#    tools/lab-record.sh skeleton my-lab-id
#
#    # 2) capture a tool case: match-regex, example-argv, then the real command
#    tools/lab-record.sh case '-sV\s+{{target}}' 'nmap -sV 10.10.10.5' \
#        -- nmap -sV 10.10.10.5
#
#    # 3) capture a seed file (stored base64, so binary is exact)
#    tools/lab-record.sh file /home/student/task/evidence.dat ./evidence.dat
#
#  Notes
#  -----
#  * Run the real command in a throwaway container/VM, NOT against production.
#  * Normalise volatile values (timestamps, session ids) with sed before saving,
#    or leave them — the point is fidelity, not reproducibility.
#  * `{{var}}` placeholders in the match/output are substituted by the engine
#    from the bundle's `vars` object.
#  * Paste the emitted fragments into content/labs/<id>.json, then run
#    `go run ./tools/labvalidate -content ./content`.
# ==================================================================
set -euo pipefail

die() { echo "lab-record: $*" >&2; exit 1; }

# JSON-escape arbitrary text (never hand-roll this).
json_escape() { python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))'; }

cmd_skeleton() {
  local id="${1:?usage: lab-record.sh skeleton <lab-id>}"
  cat <<EOF
{
  "id": "$id",
  "workdir": "/home/student/task",
  "hostname": "lab",
  "vars": {},
  "expect": { "file": "/home/student/task/found.txt", "contains": "nto{...}" },
  "fs": [
    { "path": "/home/student/task", "type": "dir" },
    { "path": "/home/student/task/task.md", "text": "TODO" }
  ],
  "tools": {}
}
EOF
}

cmd_case() {
  local match="${1:?usage: lab-record.sh case <match-regex> <example-argv> -- <cmd...>}"
  local example="${2:?}"
  shift 2
  [ "${1:-}" = "--" ] || die "expected '--' before the real command"
  shift
  [ "$#" -ge 1 ] || die "no command given"

  local out
  out="$("$@" 2>&1 || true)"
  printf '    {\n      "match": %s,\n      "example": %s,\n      "output": %s\n    }\n' \
    "$(printf '%s' "$match" | json_escape)" \
    "$(printf '%s' "$example" | json_escape)" \
    "$(printf '%s\n' "$out" | json_escape)"
}

cmd_file() {
  local fspath="${1:?usage: lab-record.sh file <fs-path> <local-file>}"
  local localf="${2:?}"
  [ -f "$localf" ] || die "no such file: $localf"
  local b64
  b64="$(base64 -w0 "$localf")"
  printf '    { "path": %s, "b64": %s }\n' \
    "$(printf '%s' "$fspath" | json_escape)" \
    "$(printf '%s' "$b64" | json_escape)"
}

case "${1:-}" in
  skeleton) shift; cmd_skeleton "$@" ;;
  case)     shift; cmd_case "$@" ;;
  file)     shift; cmd_file "$@" ;;
  -h|--help|help|"") sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown subcommand: $1 (try: skeleton | case | file)" ;;
esac
