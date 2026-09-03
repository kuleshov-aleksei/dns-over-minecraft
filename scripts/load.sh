#!/usr/bin/env bash
# Generate light DNS test load against a running local DNS client service
# (dnsmc -C), which forwards queries to a running dnsmc server. Intended for
# stats debugging on the server (logging.performance / logging.analytics).
#
# Assumes both instances are already running, e.g.:
#   make run-server
#   make client-service CLIENT_LISTEN=127.0.0.1:5300
#
# To make every query reach the server (so repeated domains show up as cache
# hits there), set `client.cache.disabled: true` in config.client.yaml.
#
# Env vars (with defaults):
#   RESOLVER   DNS resolver address (the client service)   (127.0.0.1)
#   PORT       DNS port                                     (5300)
#   QUERIES    number of queries to send                    (20)
#   DELAY      seconds between queries                      (0.2)
#   DIG        dig binary to use                            (dig)
set -euo pipefail

RESOLVER="${RESOLVER:-127.0.0.1}"
PORT="${PORT:-5300}"
QUERIES="${QUERIES:-20}"
DELAY="${DELAY:-0.2}"
DIG="${DIG:-dig}"

DOMAINS=("google.com" "example.com" "github.com" "habr.ru" "encamy.com" "encamy.com" "example.com")
QTYPES=(   "A"         "A"           "A"          "A"        "TXT"      "TXT"      "AAAA")

if ! command -v "$DIG" >/dev/null 2>&1; then
  echo "error: $DIG not found (install dnsutils/bind-utils, or set DIG=kdig/drill)" >&2
  exit 1
fi

echo "load: $QUERIES queries -> $RESOLVER:$PORT (every ${DELAY}s) via $DIG"
for ((i = 0; i < QUERIES; i++)); do
  idx=$((i % ${#DOMAINS[@]}))
  name="${DOMAINS[$idx]}"
  qtype="${QTYPES[$idx]}"
  if ! "$DIG" "@$RESOLVER" -p "$PORT" "$name" "$qtype" +short >/dev/null 2>&1; then
    echo "load: query #$((i + 1)) ($name $qtype) failed" >&2
  fi
  sleep "$DELAY"
done
echo "load: done"