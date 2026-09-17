#!/usr/bin/env bash
set -euo pipefail
umask 077

# Small operator-facing wrapper around the XConnect One binary.
#
# The wrapper deliberately does not read Vault, Portal sessions, or long-lived
# credentials. A Zero-issued one-time invitation is accepted only through
# stdin so it does not need to appear in shell history or a process list.

SCRIPT_NAME="$(basename "$0")"
COMMAND="${1:-help}"
if [[ "$#" -gt 0 ]]; then shift; fi

CLI_PATH="${XCONNECT_BIN:-}"
STATE_DIR="${XCONNECT_STATE_DIR:-}"
HANDOFF="${XCONNECT_HANDOFF:-}"
GATEWAY_ID="${XCONNECT_GATEWAY_ID:-}"
NETWORK_ID="${XCONNECT_NETWORK_ID:-}"
DEVICE_ID="${XCONNECT_DEVICE_ID:-}"
DEVICE_NAME="${XCONNECT_DEVICE_NAME:-}"
CONTROLLER="${XCONNECT_CONTROLLER:-}"
INVITE_FROM_STDIN=0
BOOTSTRAP=0
PRIVATE_TARGET="${XCONNECT_PRIVATE_TARGET:-}"
PRIVATE_URL="${XCONNECT_PRIVATE_URL:-}"

die() {
  echo "${SCRIPT_NAME}: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  one gateway-init --controller URL --gateway-id ID
  one join --gateway-id ID --handoff FILE --invite-stdin
  one sync [--state-dir DIR]
  one status [--state-dir DIR]
  one diagnose [--state-dir DIR]
  one verify --handoff FILE [--private-target IP] [--private-url URL]
  one down [--state-dir DIR]

Environment:
  XCONNECT_BIN          trusted xconnect binary path
  XCONNECT_GATEWAY_BIN  trusted xconnect-gateway binary path
  XCONNECT_CONTROLLER   Accounts controller URL for gateway-init
  XCONNECT_STATE_DIR    One-owned state directory
  XCONNECT_GATEWAY_ID   selected Gateway ID
  XCONNECT_NETWORK_ID   selected network ID when no handoff is supplied
  XCONNECT_HANDOFF      signed desktop handoff JSON

join reads exactly one short-lived xconnect://join/... invitation from stdin:
  pbpaste | one join --gateway-id gw-uat-tw-xconnect \
    --handoff /path/to/handoff.json --invite-stdin

The invitation is never written to disk. Vault and Portal credentials stay
outside this wrapper and must be used by the control-plane operator to issue
the invitation.
EOF
}

find_tool() {
  local name="$1"
  local candidate
  for candidate in \
    "/opt/homebrew/bin/$name" \
    "/usr/local/bin/$name" \
    "/usr/bin/$name" \
    "/bin/$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  command -v "$name" 2>/dev/null || true
}

resolve_cli() {
  if [[ -z "$CLI_PATH" ]]; then
    CLI_PATH="$(find_tool xconnect)"
  fi
  [[ -x "$CLI_PATH" ]] || die "xconnect binary not found; set XCONNECT_BIN"
}

resolve_gateway_cli() {
  if [[ -z "${GATEWAY_CLI_PATH:-}" ]]; then
    GATEWAY_CLI_PATH="${XCONNECT_GATEWAY_BIN:-}"
  fi
  if [[ -z "$GATEWAY_CLI_PATH" ]]; then
    GATEWAY_CLI_PATH="$(find_tool xconnect-gateway)"
  fi
  [[ -x "$GATEWAY_CLI_PATH" ]] || die "xconnect-gateway binary not found; set XCONNECT_GATEWAY_BIN"
}

resolve_defaults() {
  local os host
  os="$(uname -s)"
  if [[ -z "$STATE_DIR" ]]; then
    if [[ "$os" == Darwin ]]; then
      STATE_DIR=/var/lib/xconnect-one
    elif [[ "$os" == Linux ]]; then
      STATE_DIR=/var/lib/xconnect-one
    else
      die "unsupported host OS: $os"
    fi
  fi
  if [[ -z "$DEVICE_ID" ]]; then
    if [[ "$os" == Darwin ]] && command -v scutil >/dev/null 2>&1; then
      host="$(scutil --get LocalHostName 2>/dev/null || true)"
    else
      host="$(hostname -s 2>/dev/null || hostname)"
    fi
    host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
    [[ "$host" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "invalid host name: $host"
    if [[ "$os" == Darwin ]]; then
      DEVICE_ID="one-macos-${host}.local"
    elif [[ "$os" == Linux ]]; then
      DEVICE_ID="one-linux-${host}"
    else
      DEVICE_ID="one-${host}"
    fi
  fi
  [[ -n "$DEVICE_NAME" ]] || DEVICE_NAME="XConnect One $DEVICE_ID"
}

require_jq() {
  JQ_PATH="$(find_tool jq)"
  [[ -x "$JQ_PATH" ]] || die 'jq is required when --handoff is used'
}

read_handoff() {
  [[ -n "$HANDOFF" ]] || return 0
  [[ -f "$HANDOFF" ]] || die "handoff not found: $HANDOFF"
  require_jq

  local handoff_gateway handoff_network handoff_host handoff_port handoff_kind
  handoff_gateway="$("$JQ_PATH" -er '.gateway_id' "$HANDOFF")"
  handoff_network="$("$JQ_PATH" -er '.network_id' "$HANDOFF")"
  handoff_host="$("$JQ_PATH" -er '.gateway_endpoint.host' "$HANDOFF")"
  handoff_port="$("$JQ_PATH" -er '.gateway_endpoint.port' "$HANDOFF")"
  handoff_kind="$("$JQ_PATH" -er '.gateway_endpoint.transport' "$HANDOFF")"

  [[ -n "$GATEWAY_ID" ]] || GATEWAY_ID="$handoff_gateway"
  [[ "$GATEWAY_ID" == "$handoff_gateway" ]] || die 'selected Gateway does not match handoff'
  [[ -n "$NETWORK_ID" ]] || NETWORK_ID="$handoff_network"
  [[ "$NETWORK_ID" == "$handoff_network" ]] || die 'selected network does not match handoff'
  [[ "$handoff_kind" == vless-xhttp && "$handoff_port" == 443 ]] || \
    die 'handoff must use VLESS/XHTTP TCP 443'
  [[ "$handoff_host" == tw-xconnect.svc.plus ]] || \
    die 'handoff Gateway host is not tw-xconnect.svc.plus'
}

parse_options() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --cli|--xconnect-bin) CLI_PATH="${2:?missing value for $1}"; shift 2 ;;
      --gateway-cli|--xconnect-gateway-bin) GATEWAY_CLI_PATH="${2:?missing value for $1}"; shift 2 ;;
      --controller) CONTROLLER="${2:?missing value for $1}"; shift 2 ;;
      --state-dir) STATE_DIR="${2:?missing value for $1}"; shift 2 ;;
      --handoff) HANDOFF="${2:?missing value for $1}"; shift 2 ;;
      --gateway-id) GATEWAY_ID="${2:?missing value for $1}"; shift 2 ;;
      --network-id) NETWORK_ID="${2:?missing value for $1}"; shift 2 ;;
      --device-id) DEVICE_ID="${2:?missing value for $1}"; shift 2 ;;
      --name) DEVICE_NAME="${2:?missing value for $1}"; shift 2 ;;
      --invite-stdin) INVITE_FROM_STDIN=1; shift ;;
      --bootstrap) BOOTSTRAP=1; shift ;;
      --private-target) PRIVATE_TARGET="${2:?missing value for $1}"; shift 2 ;;
      --private-url) PRIVATE_URL="${2:?missing value for $1}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

gateway_init() {
  parse_options "$@"
  resolve_gateway_cli
  resolve_defaults
  [[ -n "$CONTROLLER" ]] || die '--controller is required (or set XCONNECT_CONTROLLER)'
  [[ -n "$GATEWAY_ID" ]] || die '--gateway-id is required (or set XCONNECT_GATEWAY_ID)'
  echo "[1/1] gateway init: gateway=$GATEWAY_ID controller=$CONTROLLER"
  sudo -v
  sudo install -d -m 0700 "$STATE_DIR"
  sudo "$GATEWAY_CLI_PATH" init \
    --state-dir "$STATE_DIR" \
    --controller "$CONTROLLER" \
    --gateway-id "$GATEWAY_ID"
  echo 'PASS: XConnect Gateway local identity initialized.'
}

run_cli() {
  local subcommand="$1"; shift
  resolve_cli
  resolve_defaults
  sudo "$CLI_PATH" "$subcommand" --state-dir "$STATE_DIR" "$@"
}

join() {
  parse_options "$@"
  resolve_cli
  resolve_defaults
  read_handoff
  [[ -n "$GATEWAY_ID" ]] || die '--gateway-id is required (or set XCONNECT_GATEWAY_ID)'
  [[ -n "$NETWORK_ID" ]] || die '--network-id is required or provide --handoff'
  [[ "$INVITE_FROM_STDIN" == 1 ]] || die 'join requires --invite-stdin to keep the invite out of shell history'

  local invite
  IFS= read -r invite || true
  [[ "$invite" == xconnect://join/* ]] || die 'stdin must contain one xconnect://join/... invitation'
  trap 'unset invite' EXIT

  sudo -v
  sudo install -d -m 0700 "$STATE_DIR"
  echo "[1/4] join: device=$DEVICE_ID network=$NETWORK_ID gateway=$GATEWAY_ID"
  if [[ "$BOOTSTRAP" == 1 ]]; then
    sudo "$CLI_PATH" join --bootstrap --state-dir "$STATE_DIR" \
      --device-id "$DEVICE_ID" --name "$DEVICE_NAME" --network-id "$NETWORK_ID" "$invite"
  else
    sudo "$CLI_PATH" join --state-dir "$STATE_DIR" \
      --device-id "$DEVICE_ID" --name "$DEVICE_NAME" --network-id "$NETWORK_ID" "$invite"
  fi
  echo '[2/4] sync: apply signed config and send ACK'
  sudo "$CLI_PATH" sync --state-dir "$STATE_DIR"
  echo '[3/4] status'
  sudo "$CLI_PATH" status --state-dir "$STATE_DIR"
  echo '[4/4] diagnose'
  sudo "$CLI_PATH" diagnose --state-dir "$STATE_DIR"
  echo 'PASS: XConnect One enrolled and local runtime applied.'
}

verify() {
  parse_options "$@"
  resolve_cli
  resolve_defaults
  read_handoff
  run_cli status
  run_cli diagnose

  if [[ -n "$HANDOFF" ]]; then
    local gateway_key handshake now age wg_path
    gateway_key="$("$JQ_PATH" -er '.gateway_public_key' "$HANDOFF")"
    wg_path="$(find_tool wg)"
    [[ -x "$wg_path" ]] || die 'wg is required for handshake verification'
    handshake="$(sudo "$wg_path" show xconone0 latest-handshakes | awk -v peer="$gateway_key" '$1 == peer {print $2; exit}')"
    now="$(date +%s)"
    [[ "$handshake" =~ ^[0-9]+$ ]] || die 'Gateway peer handshake not found'
    age=$((now - handshake))
    (( age >= 0 && age < 300 )) || die "Gateway peer handshake is stale: age=${age}s"
    echo "handshake=OK age=${age}s"
  fi

  if [[ -n "$PRIVATE_TARGET" ]]; then
    ping -c 3 -W 1000 "$PRIVATE_TARGET" >/dev/null
    echo "ping=OK target=$PRIVATE_TARGET"
  fi
  if [[ -n "$PRIVATE_URL" ]]; then
    curl --fail --silent --show-error --max-time 10 "$PRIVATE_URL" >/dev/null
    echo "http=OK url=$PRIVATE_URL"
  fi
  echo 'PASS: XConnect One verification completed.'
}

case "$COMMAND" in
  help|-h|--help) usage ;;
  gateway-init|init-gateway) gateway_init "$@" ;;
  join) join "$@" ;;
  verify) verify "$@" ;;
  sync|status|diagnose|down)
    parse_options "$@"
    run_cli "$COMMAND"
    ;;
  *) die "unknown command: $COMMAND (use --help)" ;;
esac
