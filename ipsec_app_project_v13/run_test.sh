#!/usr/bin/env bash
set -euo pipefail

# v13 simple execution wrapper
# - Auto-selects PC-A/PC-B config from the local IPv4 address.
# - Builds ipsec_app automatically if it is missing.
# - Never auto-generates a PSK before a test, because both peers must use
#   exactly the same PSK file/value.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP="${IPSEC_APP:-$SCRIPT_DIR/ipsec_app}"
CONFIG_OVERRIDE="${IPSEC_CONFIG:-}"
NO_SUDO="${RUN_TEST_NO_SUDO:-0}"

usage() {
    cat <<'USAGE'
Usage:
  ./run_test.sh baseline [CASE_ID]
  ./run_test.sh cross [START] [LIMIT]
  ./run_test.sh exhaustive [START] [LIMIT]
  ./run_test.sh custom IKE_PROPOSAL ESP_PROPOSAL [CUSTOM_ID] [CHILD_KE]
  ./run_test.sh custom-matrix MATRIX_FILE [CASE_ID]

  ./run_test.sh count baseline|cross|exhaustive
  ./run_test.sh check baseline|cross|exhaustive
  ./run_test.sh cleanup
  ./run_test.sh psk [PSK_FILE]

Optional global config override:
  ./run_test.sh --config configs/pc_a_initiator.conf baseline
  ./run_test.sh --config configs/pc_b_responder.conf cross 1 100

Recommended examples:
  ./run_test.sh baseline
  ./run_test.sh baseline BASE-001
  ./run_test.sh cross
  ./run_test.sh cross 101 100
  ./run_test.sh exhaustive
  ./run_test.sh exhaustive 1001 500
  ./run_test.sh custom aes256-sha384-prfsha384-ecp384 aes256gcm16
  ./run_test.sh count exhaustive

Defaults:
  cross       START=1 LIMIT=100
  exhaustive  START=1 LIMIT=100

Notes:
  * Run the responder first, then the initiator.
  * PC-A and PC-B must use the same START/LIMIT and the same custom proposals.
  * The PSK is NOT generated automatically for tests. Generate it once and
    copy the same ipsec_test.psk to the other peer.
USAGE
}

fatal() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

config_value() {
    local file="$1"
    local key="$2"
    awk -F= -v key="$key" '
        $0 !~ /^[[:space:]]*#/ && $1 == key {
            value = substr($0, index($0, "=") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            print value
            exit
        }
    ' "$file"
}

select_config() {
    if [[ -n "$CONFIG_OVERRIDE" ]]; then
        [[ -f "$CONFIG_OVERRIDE" ]] || fatal "config file not found: $CONFIG_OVERRIDE"
        printf '%s\n' "$CONFIG_OVERRIDE"
        return
    fi

    local cfg_a="configs/pc_a_initiator.conf"
    local cfg_b="configs/pc_b_responder.conf"
    [[ -f "$cfg_a" ]] || fatal "missing $cfg_a"
    [[ -f "$cfg_b" ]] || fatal "missing $cfg_b"

    local ip_a ip_b
    ip_a="$(config_value "$cfg_a" local_ip)"
    ip_b="$(config_value "$cfg_b" local_ip)"

    local local_ips
    local_ips="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"

    if grep -Fxq "$ip_a" <<<"$local_ips"; then
        printf '%s\n' "$cfg_a"
        return
    fi
    if grep -Fxq "$ip_b" <<<"$local_ips"; then
        printf '%s\n' "$cfg_b"
        return
    fi

    fatal "unable to auto-select config. Use --config FILE. Expected local IP $ip_a or $ip_b"
}

ensure_app() {
    if [[ -x "$APP" ]]; then
        return
    fi

    if [[ "$APP" != "$SCRIPT_DIR/ipsec_app" ]]; then
        fatal "IPSEC_APP is not executable: $APP"
    fi

    printf '[INFO] ipsec_app not found; building with make...\n'
    command -v make >/dev/null 2>&1 || fatal "make command not found"
    make
    [[ -x "$APP" ]] || fatal "build completed but ipsec_app was not created"
}

resolve_psk_path() {
    local config="$1"
    local path
    path="$(config_value "$config" psk_file)"
    [[ -n "$path" ]] || fatal "psk_file is not defined in $config"

    if [[ "$path" = /* ]]; then
        printf '%s\n' "$path"
    else
        printf '%s/%s\n' "$SCRIPT_DIR" "${path#./}"
    fi
}

check_psk() {
    local config="$1"
    local psk
    psk="$(resolve_psk_path "$config")"
    if [[ ! -s "$psk" ]]; then
        cat >&2 <<EOF_PSK
ERROR: PSK file is missing or empty: $psk
Generate it on ONE peer:
  ./run_test.sh psk
Then copy the SAME file/value to the other peer before running a test.
EOF_PSK
        exit 1
    fi
}

run_privileged() {
    if [[ "$NO_SUDO" == "1" || "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        command -v sudo >/dev/null 2>&1 || fatal "sudo command not found"
        sudo "$@"
    fi
}

# Optional global --config FILE must come before the command.
if [[ "${1:-}" == "--config" ]]; then
    [[ $# -ge 3 ]] || { usage; exit 2; }
    CONFIG_OVERRIDE="$2"
    shift 2
fi

COMMAND="${1:-}"
[[ -n "$COMMAND" ]] || { usage; exit 2; }
shift

case "$COMMAND" in
    -h|--help|help)
        usage
        ;;

    psk)
        ensure_app
        PSK_FILE="${1:-ipsec_test.psk}"
        [[ $# -le 1 ]] || fatal "psk accepts at most one PSK file argument"
        "$APP" --generate-psk "$PSK_FILE"
        printf '[IMPORTANT] Copy the SAME PSK file to the other peer.\n'
        ;;

    baseline)
        [[ $# -le 1 ]] || fatal "baseline syntax: baseline [CASE_ID]"
        CONFIG="$(select_config)"
        ensure_app
        check_psk "$CONFIG"
        printf '[INFO] config=%s mode=baseline\n' "$CONFIG"
        ARGS=(--config "$CONFIG" --mode baseline)
        if [[ $# -eq 1 ]]; then
            ARGS+=(--case "$1")
        fi
        run_privileged "$APP" "${ARGS[@]}"
        ;;

    cross)
        [[ $# -le 2 ]] || fatal "cross syntax: cross [START] [LIMIT]"
        START="${1:-1}"
        LIMIT="${2:-100}"
        is_positive_integer "$START" || fatal "START must be an integer >= 1"
        is_positive_integer "$LIMIT" || fatal "LIMIT must be an integer >= 1"
        CONFIG="$(select_config)"
        ensure_app
        check_psk "$CONFIG"
        printf '[INFO] config=%s mode=cross start=%s limit=%s\n' "$CONFIG" "$START" "$LIMIT"
        run_privileged "$APP" --config "$CONFIG" --mode cross --start "$START" --limit "$LIMIT"
        ;;

    exhaustive)
        [[ $# -le 2 ]] || fatal "exhaustive syntax: exhaustive [START] [LIMIT]"
        START="${1:-1}"
        LIMIT="${2:-100}"
        is_positive_integer "$START" || fatal "START must be an integer >= 1"
        is_positive_integer "$LIMIT" || fatal "LIMIT must be an integer >= 1"
        CONFIG="$(select_config)"
        ensure_app
        check_psk "$CONFIG"
        printf '[INFO] config=%s mode=exhaustive start=%s limit=%s\n' "$CONFIG" "$START" "$LIMIT"
        run_privileged "$APP" --config "$CONFIG" --mode exhaustive --start "$START" --limit "$LIMIT"
        ;;

    custom)
        [[ $# -ge 2 && $# -le 4 ]] || fatal "custom syntax: custom IKE_PROPOSAL ESP_PROPOSAL [CUSTOM_ID] [CHILD_KE]"
        IKE="$1"
        ESP="$2"
        CUSTOM_ID="${3:-CUSTOM-001}"
        CHILD_KE="${4:-}"
        CONFIG="$(select_config)"
        ensure_app
        check_psk "$CONFIG"
        printf '[INFO] config=%s mode=custom id=%s\n' "$CONFIG" "$CUSTOM_ID"
        printf '[INFO] IKE=%s\n[INFO] ESP=%s\n' "$IKE" "$ESP"
        ARGS=(--config "$CONFIG" --mode custom --ike "$IKE" --esp "$ESP" --custom-id "$CUSTOM_ID")
        if [[ -n "$CHILD_KE" ]]; then
            ARGS+=(--child-ke "$CHILD_KE")
        fi
        run_privileged "$APP" "${ARGS[@]}"
        ;;

    custom-matrix)
        [[ $# -ge 1 && $# -le 2 ]] || fatal "custom-matrix syntax: custom-matrix MATRIX_FILE [CASE_ID]"
        MATRIX="$1"
        [[ -f "$MATRIX" ]] || fatal "matrix file not found: $MATRIX"
        CONFIG="$(select_config)"
        ensure_app
        check_psk "$CONFIG"
        ARGS=(--config "$CONFIG" --mode custom --matrix "$MATRIX")
        if [[ $# -eq 2 ]]; then
            ARGS+=(--case "$2")
        fi
        printf '[INFO] config=%s mode=custom matrix=%s\n' "$CONFIG" "$MATRIX"
        run_privileged "$APP" "${ARGS[@]}"
        ;;

    count)
        [[ $# -eq 1 ]] || fatal "count syntax: count baseline|cross|exhaustive"
        MODE="$1"
        case "$MODE" in baseline|cross|exhaustive) ;; *) fatal "unsupported count mode: $MODE" ;; esac
        CONFIG="$(select_config)"
        ensure_app
        "$APP" --config "$CONFIG" --mode "$MODE" --count-only
        ;;

    check)
        [[ $# -eq 1 ]] || fatal "check syntax: check baseline|cross|exhaustive"
        MODE="$1"
        case "$MODE" in baseline|cross|exhaustive) ;; *) fatal "unsupported check mode: $MODE" ;; esac
        CONFIG="$(select_config)"
        ensure_app
        run_privileged "$APP" --check --config "$CONFIG" --mode "$MODE"
        ;;

    cleanup)
        [[ $# -eq 0 ]] || fatal "cleanup does not accept additional arguments"
        CONFIG="$(select_config)"
        ensure_app
        printf '[INFO] config=%s cleanup target SA only\n' "$CONFIG"
        run_privileged "$APP" --cleanup --config "$CONFIG"
        ;;

    *)
        usage >&2
        fatal "unknown command: $COMMAND"
        ;;
esac
