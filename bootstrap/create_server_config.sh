#!/usr/bin/env bash
#
# create_server_config.sh — generate a minimal viable dnsmc server config.yaml
# with randomized camouflage (MOTD + player sample).
#
# Usage:
#   create_server_config.sh [passphrase] [-o OUTPUT] [-f|--force] [--server-only] [-h|--help]
#   create_server_config.sh -p <passphrase> [-o OUTPUT] [-f|--force] [--server-only]
#
#   passphrase            Positional shared secret for security.passphrase.
#                         If omitted, a random 6-char [a-z0-9] one is generated.
#   -p, --passphrase PW   Same as positional arg (flag wins if both given).
#   -o, --output FILE     Output path (default: <repo-root>/config.yaml).
#   -f, --force           Overwrite OUTPUT if it already exists.
#   --server-only         Emit only the server: block (omit listen, security, upstreams).
#   --motd-file FILE      Server-name list (default: sibling server_names.txt).
#   --players-file FILE   Player-name list (default: sibling player_names.txt).
#
# Picks 1 random MOTD from server_names.txt and 4-8 random player names from
# player_names.txt. Fixed protocol 26.1.2/775. Minimal config only — everything
# else falls back to sane server defaults (see internal/config/config.go).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

MOTD_FILE="${SCRIPT_DIR}/server_names.txt"
PLAYERS_FILE="${SCRIPT_DIR}/player_names.txt"
OUTPUT="${ROOT_DIR}/config.yaml"
FORCE=0
SERVER_ONLY=0
PASSPHRASE=""
POSITIONAL_PASSPHRASE=""

usage() {
  sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -f|--force) FORCE=1; shift ;;
    --server-only) SERVER_ONLY=1; shift ;;
    -o|--output) OUTPUT="${2:?missing value for $1}"; shift 2 ;;
    -p|--passphrase) PASSPHRASE="${2:?missing value for $1}"; shift 2 ;;
    --motd-file) MOTD_FILE="$2"; shift 2 ;;
    --players-file) PLAYERS_FILE="$2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "error: unknown flag: $1 (see --help)" >&2; exit 2 ;;
    *)  # first positional arg = passphrase
      if [[ -z "${POSITIONAL_PASSPHRASE}" ]]; then
        POSITIONAL_PASSPHRASE="$1"
      else
        echo "error: unexpected extra argument: $1 (see --help)" >&2; exit 2
      fi
      shift ;;
  esac
done

if [[ -z "${PASSPHRASE}" && -n "${POSITIONAL_PASSPHRASE}" ]]; then
  PASSPHRASE="${POSITIONAL_PASSPHRASE}"
fi

# --- guards ---------------------------------------------------------------
[[ -f "${MOTD_FILE}" ]] || { echo "error: motd list not found: ${MOTD_FILE}" >&2; exit 1; }
[[ -f "${PLAYERS_FILE}" ]] || { echo "error: player list not found: ${PLAYERS_FILE}" >&2; exit 1; }
[[ -s "${MOTD_FILE}" ]] || { echo "error: motd list is empty: ${MOTD_FILE}" >&2; exit 1; }
[[ -s "${PLAYERS_FILE}" ]] || { echo "error: player list is empty: ${PLAYERS_FILE}" >&2; exit 1; }

if [[ -e "${OUTPUT}" && "${FORCE}" -ne 1 ]]; then
  echo "error: ${OUTPUT} already exists (use -f/--force to overwrite)" >&2
  exit 1
fi

# --- passphrase -----------------------------------------------------------
PASS_SOURCE="given"
if [[ -z "${PASSPHRASE}" ]]; then
  # NB: pipefail is on; tr always gets SIGPIPE once head is full, so mask it.
  PASSPHRASE="$(set +o pipefail; tr -dc 'a-z0-9' </dev/urandom | head -c 6)"
  PASS_SOURCE="generated"
fi

# --- random helpers (shuf preferred, RANDOM fallback) ----------------------
pick_one() { # $1 = file
  if command -v shuf >/dev/null 2>&1; then
    shuf -n 1 "$1"
  else
    local total line
    total="$(wc -l < "$1")"
    line=$((RANDOM % total + 1))
    sed -n "${line}p" "$1"
  fi
}

pick_n() { # $1 = file, $2 = count
  if command -v shuf >/dev/null 2>&1; then
    shuf -n "$2" "$1"
  else
    # portable fallback: random sort via awk + sort (unique input assumed)
    awk 'BEGIN { srand() } { print rand() "\t" $0 }' "$1" | sort -n | cut -f2- | head -n "$2"
  fi
}

new_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  elif [[ -f /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    python3 -c 'import uuid; print(uuid.uuid4())'
  fi
}

# --- picks ----------------------------------------------------------------
MOTD="$(pick_one "${MOTD_FILE}")"
COUNT=$((RANDOM % 5 + 4)) # 4-8

mapfile -t PLAYERS < <(pick_n "${PLAYERS_FILE}" "${COUNT}")
if [[ "${#PLAYERS[@]}" -eq 0 ]]; then
  echo "error: failed to pick player names" >&2; exit 1
fi

# --- yaml quoting (double-quote style) ------------------------------------
yaml_dq() {
  local s="${1}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "${s}"
}

# --- emit minimal config ---------------------------------------------------
{
  if [[ "${SERVER_ONLY}" -eq 0 ]]; then
    echo 'listen: "0.0.0.0:25565"'
  fi
  echo 'server:'
  echo "  motd: $(yaml_dq "${MOTD}")"
  echo '  versionName: "26.1.2"'
  echo '  versionProtocol: 775'
  echo '  maxPlayers: 20'
  echo "  onlinePlayers: ${#PLAYERS[@]}"
  echo '  sample:'
  for name in "${PLAYERS[@]}"; do
    echo "    - name: $(yaml_dq "${name}")"
    echo "      id: \"$(new_uuid)\""
  done
  if [[ "${SERVER_ONLY}" -eq 0 ]]; then
    echo 'security:'
    echo "  passphrase: $(yaml_dq "${PASSPHRASE}")"
    echo '  rateLimit: 100'
    echo '  maxConnections: 1024'
    echo 'upstreams:'
    echo '  - name: cloudflare-tcp'
    echo '    type: tcp'
    echo '    addr: "1.1.1.1:53"'
    echo '    priority: 5'
    echo '    timeout: 2s'
    echo '  - name: cloudflare-doh'
    echo '    type: doh'
    echo '    url: "https://cloudflare-dns.com/dns-query"'
    echo '    priority: 10'
    echo '    timeout: 2s'
  fi
} > "${OUTPUT}"

echo "wrote ${OUTPUT}"
echo "motd: ${MOTD}"
echo "players (${#PLAYERS[@]}): ${PLAYERS[*]}"
echo "passphrase (${PASS_SOURCE}): ${PASSPHRASE}"
