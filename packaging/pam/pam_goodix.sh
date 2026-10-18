#!/usr/bin/env bash
# PAM authentication script for Goodix 27c6:538d
# Usage in /etc/pam.d/sudo or system-local-login:
# auth sufficient pam_exec.so stdout /usr/local/bin/goodix-fp-pam

set -u

# -----------------------------------------------------------------------------
# 1. Resolve Target User from PAM or Environment
# -----------------------------------------------------------------------------
TARGET_USER="${PAM_USER:-${SUDO_USER:-${USER:-$(id -un)}}}"

if [[ -z "${TARGET_USER}" || "${TARGET_USER}" == "root" ]]; then
    # If authenticating as root or user is unknown, try SUDO_USER or LOGNAME
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        TARGET_USER="${SUDO_USER}"
    fi
fi

if [[ -z "${TARGET_USER}" ]]; then
    # Cannot determine user; fail cleanly to let password auth proceed
    exit 1
fi

# -----------------------------------------------------------------------------
# 2. Locate User's Home Directory
# -----------------------------------------------------------------------------
USER_HOME=""
if command -v getent >/dev/null 2>&1; then
    USER_HOME="$(getent passwd "${TARGET_USER}" 2>/dev/null | cut -d: -f6)"
fi

if [[ -z "${USER_HOME}" && -d "/home/${TARGET_USER}" ]]; then
    USER_HOME="/home/${TARGET_USER}"
fi

# -----------------------------------------------------------------------------
# 3. Search Candidate Directories for Enrolled Biometric Templates (*.tgla)
# -----------------------------------------------------------------------------
TEMPLATE_DIR=""

CANDIDATES=()
if [[ -n "${GOODIX_TEMPLATE_DIR:-}" ]]; then
    CANDIDATES+=("${GOODIX_TEMPLATE_DIR}")
fi

if [[ -n "${USER_HOME}" ]]; then
    CANDIDATES+=("${USER_HOME}/.local/share/goodix-fp/templates")
fi

CANDIDATES+=(
    "/var/lib/goodix-fp/templates/${TARGET_USER}"
    "/var/lib/goodix-fp/templates"
    "/etc/goodix-fp/templates/${TARGET_USER}"
    "/etc/goodix-fp/templates"
)

for candidate in "${CANDIDATES[@]}"; do
    if [[ -d "${candidate}" ]]; then
        shopt -s nullglob
        templates=("${candidate}"/*.tgla)
        shopt -u nullglob
        if [[ ${#templates[@]} -gt 0 ]]; then
            TEMPLATE_DIR="${candidate}"
            break
        fi
    fi
done

if [[ -z "${TEMPLATE_DIR}" ]]; then
    # No enrolled templates found for this user.
    # Exit 1 silently so PAM immediately proceeds to standard password authentication.
    exit 1
fi

# -----------------------------------------------------------------------------
# 4. Locate goodix-fp Driver Executable
# -----------------------------------------------------------------------------
GOODIX_BIN="${GOODIX_BIN:-/usr/local/bin/goodix-fp}"

if [[ ! -x "${GOODIX_BIN}" ]]; then
    if command -v goodix-fp >/dev/null 2>&1; then
        GOODIX_BIN="$(command -v goodix-fp)"
    elif [[ -x "/usr/bin/goodix-fp" ]]; then
        GOODIX_BIN="/usr/bin/goodix-fp"
    elif [[ -x "/opt/goodix-fp/goodix-fp" ]]; then
        GOODIX_BIN="/opt/goodix-fp/goodix-fp"
    fi
fi

if [[ ! -x "${GOODIX_BIN}" ]]; then
    # Driver binary is not executable or not installed
    echo "[goodix-pam] Warning: goodix-fp binary not found at ${GOODIX_BIN}" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# 5. Perform Biometric Verification
# -----------------------------------------------------------------------------
# Prompt user via stdout (pam_exec.so stdout forwards this to the terminal / locker)
echo "Place finger on fingerprint sensor to authenticate as ${TARGET_USER}..."

# Execute verification in quiet mode, passing the detected template directory
"${GOODIX_BIN}" verify --template-dir "${TEMPLATE_DIR}" --quiet
EXIT_CODE=$?

if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo "Fingerprint matched."
    exit 0
else
    # Non-zero return code signals PAM to fall through to password authentication
    exit 1
fi
