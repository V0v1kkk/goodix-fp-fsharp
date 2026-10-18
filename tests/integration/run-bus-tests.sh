#!/usr/bin/env bash
# =============================================================================
# run-bus-tests.sh: Integration test harness for Goodix fprintd D-Bus Bridge
# =============================================================================
# Starts a private system dbus-daemon, provisions a test template store,
# runs the Native AOT goodix-fprintd bridge daemon against the real sensor,
# and verifies all methods, signals, errors, rights, and cancellation.
#
# Usage:
#   ./tests/integration/run-bus-tests.sh           # Run locally on current machine
#   ./tests/integration/run-bus-tests.sh --remote  # Deploy to vostro-laptop and run
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REMOTE_HOST="vostro-laptop"
REMOTE_MODE=0

if [[ "${1:-}" == "--remote" ]]; then
    REMOTE_MODE=1
fi

# -----------------------------------------------------------------------------
# REMOTE DISPATCH MODE
# -----------------------------------------------------------------------------
if [[ "${REMOTE_MODE}" -eq 1 ]]; then
    echo "================================================================="
    echo "  Deploying and executing integration tests on ${REMOTE_HOST}..."
    echo "================================================================="

    # 1. Build Native AOT goodix-fprintd locally if needed
    PUBLISH_DIR="${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish"
    BIN_LOCAL="${PUBLISH_DIR}/goodix-fprintd"

    if [[ ! -f "${BIN_LOCAL}" ]]; then
        echo "[*] Building Native AOT goodix-fprintd..."
        dotnet publish "${REPO_ROOT}/src/GoodixFp.Daemon/GoodixFp.Daemon.fsproj" \
            -c Release \
            -r linux-x64 \
            --self-contained
    fi

    # 2. Prepare remote deployment folder
    ssh "${REMOTE_HOST}" "mkdir -p /tmp/goodix-fp/bus-test"

    # 3. Copy files to remote
    echo "[*] Copying binary and test scripts to ${REMOTE_HOST}:/tmp/goodix-fp/bus-test/..."
    scp "${BIN_LOCAL}" "${REMOTE_HOST}:/tmp/goodix-fp/bus-test/goodix-fprintd"
    scp "${SCRIPT_DIR}/run-bus-tests.py" "${REMOTE_HOST}:/tmp/goodix-fp/bus-test/run-bus-tests.py"
    scp "${SCRIPT_DIR}/run-bus-tests.sh" "${REMOTE_HOST}:/tmp/goodix-fp/bus-test/run-bus-tests.sh"

    # 4. Execute on remote
    echo "[*] Running integration tests on ${REMOTE_HOST}..."
    ssh -t "${REMOTE_HOST}" "chmod +x /tmp/goodix-fp/bus-test/run-bus-tests.sh /tmp/goodix-fp/bus-test/goodix-fprintd && /tmp/goodix-fp/bus-test/run-bus-tests.sh"
    exit $?
fi

# -----------------------------------------------------------------------------
# LOCAL EXECUTION MODE (runs on vostro-laptop)
# -----------------------------------------------------------------------------
WORK_DIR="/tmp/goodix-fp/bus-test"
mkdir -p "${WORK_DIR}"
chmod 0755 /tmp/goodix-fp 2>/dev/null || true
chmod 0777 "${WORK_DIR}"

BIN="${WORK_DIR}/goodix-fprintd"
if [[ ! -f "${BIN}" ]]; then
    if [[ -f "${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/goodix-fprintd" ]]; then
        BIN="${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/goodix-fprintd"
    elif command -v goodix-fprintd >/dev/null 2>&1; then
        BIN="$(command -v goodix-fprintd)"
    else
        echo "[-] Error: goodix-fprintd binary not found." >&2
        exit 1
    fi
fi

chmod +x "${BIN}"
echo "[*] Using goodix-fprintd binary: ${BIN}"

# Check for real proprietary matcher blob
MATCHER_PATH="${HOME}/.local/share/goodix-fp/libgoodix_tod_53xc.so"
if [[ ! -f "${MATCHER_PATH}" ]]; then
    MATCHER_PATH="/usr/lib/goodix-fp/libgoodix_tod_53xc.so"
fi
if [[ ! -f "${MATCHER_PATH}" ]]; then
    echo "[-] Error: Matcher blob libgoodix_tod_53xc.so not found." >&2
    exit 1
fi
echo "[*] Using matcher blob: ${MATCHER_PATH}"

# Check for real template to import
REAL_TEMPLATE="${HOME}/.local/share/goodix-fp/templates/right-index.tgla"
if [[ ! -f "${REAL_TEMPLATE}" ]]; then
    echo "[-] Error: Real template right-index.tgla not found at ${REAL_TEMPLATE}" >&2
    exit 1
fi
echo "[*] Using real template: ${REAL_TEMPLATE}"

STATE_DIR="${WORK_DIR}/state"
rm -rf "${STATE_DIR}"
mkdir -p "${STATE_DIR}"

# 1. Generate private bus configuration
BUS_CONF="${WORK_DIR}/test-bus.conf"
BUS_SOCK="${WORK_DIR}/bus.sock"
cat > "${BUS_CONF}" << "EOF"
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/tmp/goodix-fp/bus-test/bus.sock</listen>
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

# 2. Start private dbus-daemon
echo "[*] Starting private dbus-daemon..."
rm -f "${BUS_SOCK}" "${WORK_DIR}/addr.txt"
dbus-daemon --config-file="${BUS_CONF}" --print-address > "${WORK_DIR}/addr.txt" &
DBUS_PID=$!

cleanup() {
    echo ""
    echo "[*] Cleaning up integration test environment..."
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

# Wait for bus address and socket to be ready
while [[ ! -s "${WORK_DIR}/addr.txt" || ! -S "${BUS_SOCK}" ]]; do
    sleep 0.05
done
chmod 0666 "${BUS_SOCK}"

export DBUS_SYSTEM_BUS_ADDRESS="$(cat "${WORK_DIR}/addr.txt")"
echo "[*] Private D-Bus ready at: ${DBUS_SYSTEM_BUS_ADDRESS}"

# 3. Import real template into test state directory
export GOODIX_FPRINTD_STATE_DIR="${STATE_DIR}"
echo "[*] Importing template into ${STATE_DIR}..."
"${BIN}" import --user vladimir --finger right-index-finger --file "${REAL_TEMPLATE}"

# Verify imported template
"${BIN}" list --user vladimir

# 4. Prepare Python venv with dbus-next
VENV_DIR="${WORK_DIR}/venv"
if [[ ! -d "${VENV_DIR}" ]]; then
    echo "[*] Creating temporary Python venv with dbus-next..."
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install dbus-next -q
fi

# 5. Launch goodix-fprintd daemon with test policy and 3s timeout
echo "[*] Launching goodix-fprintd daemon..."
export GOODIX_FPRINTD_TEST_POLICY="allow-self"
export GOODIX_FPRINTD_VERIFY_TIMEOUT_MS="3000"
export GOODIX_FPRINTD_MATCHER="${MATCHER_PATH}"

"${BIN}" daemon > "${WORK_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for net.reactivated.Fprint name acquisition
echo "[*] Waiting for D-Bus service registration..."
for i in {1..50}; do
    if busctl --address="${DBUS_SYSTEM_BUS_ADDRESS}" list 2>/dev/null | grep -q "net.reactivated.Fprint"; then
        echo "[+] Service net.reactivated.Fprint acquired on private bus."
        break
    fi
    sleep 0.1
done

if ! busctl --address="${DBUS_SYSTEM_BUS_ADDRESS}" list 2>/dev/null | grep -q "net.reactivated.Fprint"; then
    echo "[-] Error: Daemon failed to acquire bus name. Logs:" >&2
    cat "${WORK_DIR}/daemon.log" >&2
    exit 1
fi

# 6. Execute test suite
TEST_PY="${WORK_DIR}/run-bus-tests.py"
if [[ ! -f "${TEST_PY}" ]]; then
    TEST_PY="${SCRIPT_DIR}/run-bus-tests.py"
fi

echo "[*] Running bus integration tests..."
"${VENV_DIR}/bin/python3" "${TEST_PY}"
TEST_EXIT=$?

exit ${TEST_EXIT}
