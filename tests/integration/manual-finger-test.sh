#!/usr/bin/env bash
# =============================================================================
# manual-finger-test.sh: Real Finger Verification Script for USER on vostro-laptop
# =============================================================================
# Starts a private system D-Bus and the Native AOT goodix-fprintd daemon,
# then guides the user through real sensor touch scenarios:
#   Scenario 1: Enrolled finger -> verify-match
#   Scenario 2: Unenrolled finger -> retry-scan -> verify-no-match
#   Scenario 3: Start -> VerifyStop -> restart
#
# Flags:
#   --check-only   Non-interactive check of Scenario 3 (no touch required)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="/tmp/goodix-fp/manual-test"
mkdir -p "${WORK_DIR}"
chmod 0777 "${WORK_DIR}"

BIN="${WORK_DIR}/goodix-fprintd"
if [[ ! -f "${BIN}" ]]; then
    if [[ -f "${SCRIPT_DIR}/../../src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/goodix-fprintd" ]]; then
        BIN="${SCRIPT_DIR}/../../src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/goodix-fprintd"
    elif [[ -f "/tmp/goodix-fp/bus-test/goodix-fprintd" ]]; then
        BIN="/tmp/goodix-fp/bus-test/goodix-fprintd"
    elif command -v goodix-fprintd >/dev/null 2>&1; then
        BIN="$(command -v goodix-fprintd)"
    else
        echo "[-] Error: goodix-fprintd binary not found." >&2
        exit 1
    fi
fi
chmod +x "${BIN}"

MATCHER="${HOME}/.local/share/goodix-fp/libgoodix_tod_53xc.so"
if [[ ! -f "${MATCHER}" ]]; then
    MATCHER="/usr/lib/goodix-fp/libgoodix_tod_53xc.so"
fi
if [[ ! -f "${MATCHER}" ]]; then
    echo "[-] Error: Matcher blob not found." >&2
    exit 1
fi

REAL_TEMPLATE="${HOME}/.local/share/goodix-fp/templates/right-index.tgla"
if [[ ! -f "${REAL_TEMPLATE}" ]]; then
    echo "[-] Error: Template ${REAL_TEMPLATE} not found." >&2
    exit 1
fi

STATE_DIR="${WORK_DIR}/state"
rm -rf "${STATE_DIR}"
mkdir -p "${STATE_DIR}"

# 1. Private bus config
BUS_CONF="${WORK_DIR}/test-bus.conf"
BUS_SOCK="${WORK_DIR}/bus.sock"
cat > "${BUS_CONF}" << "EOF"
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/tmp/goodix-fp/manual-test/bus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="signal"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow receive_sender="*" eavesdrop="true"/>
  </policy>
</busconfig>
EOF

echo "[*] Starting private dbus-daemon..."
rm -f "${BUS_SOCK}" "${WORK_DIR}/addr.txt"
dbus-daemon --config-file="${BUS_CONF}" --print-address > "${WORK_DIR}/addr.txt" &
DBUS_PID=$!

cleanup() {
    echo ""
    echo "[*] Stopping manual test environment..."
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    if [[ -n "${DBUS_PID:-}" ]] && kill -0 "${DBUS_PID}" 2>/dev/null; then
        kill "${DBUS_PID}" 2>/dev/null || true
        wait "${DBUS_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

while [[ ! -s "${WORK_DIR}/addr.txt" || ! -S "${BUS_SOCK}" ]]; do
    sleep 0.05
done
chmod 0666 "${BUS_SOCK}"

export DBUS_SYSTEM_BUS_ADDRESS="$(cat "${WORK_DIR}/addr.txt")"
export GOODIX_FPRINTD_STATE_DIR="${STATE_DIR}"
export GOODIX_FPRINTD_TEST_POLICY="allow-self"
export GOODIX_FPRINTD_MATCHER="${MATCHER}"

echo "[*] Importing template into test state store..."
"${BIN}" import --user "${USER:-vladimir}" --finger right-index-finger --file "${REAL_TEMPLATE}"

# Python venv
VENV_DIR="${WORK_DIR}/venv"
if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install dbus-next -q
fi

echo "[*] Launching goodix-fprintd daemon..."
"${BIN}" daemon > "${WORK_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

for i in {1..50}; do
    if busctl --address="${DBUS_SYSTEM_BUS_ADDRESS}" list 2>/dev/null | grep -q "net.reactivated.Fprint"; then
        break
    fi
    sleep 0.1
done

if ! busctl --address="${DBUS_SYSTEM_BUS_ADDRESS}" list 2>/dev/null | grep -q "net.reactivated.Fprint"; then
    echo "[-] Error: Daemon failed to start. Logs:" >&2
    cat "${WORK_DIR}/daemon.log" >&2
    exit 1
fi

CLIENT_PY="${SCRIPT_DIR}/manual-test-client.py"
if [[ ! -f "${CLIENT_PY}" ]]; then
    CLIENT_PY="${WORK_DIR}/manual-test-client.py"
fi

"${VENV_DIR}/bin/python3" "${CLIENT_PY}" "$@"
