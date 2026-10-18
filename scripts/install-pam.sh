#!/usr/bin/env bash
# =============================================================================
# install-pam.sh: Helper to install and safely test Goodix PAM authentication
# =============================================================================
#
# Features:
#   - Full backup of /etc/pam.d/sudo with timestamp and restoration support
#   - Dry-run mode (--dry-run) to preview changes without modifying system
#   - Safe in-place patching of /etc/pam.d/sudo (idempotent, won't duplicate)
#   - Clear step-by-step guidance to test with sudo before closing the shell
#   - One-command rollback (--restore)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PAM_WRAPPER_SRC="${REPO_ROOT}/packaging/pam/pam_goodix.sh"
PAM_WRAPPER_DEST="/usr/local/bin/goodix-fp-pam"
GOODIX_BIN_DEST="/usr/local/bin/goodix-fp"
PAM_TARGET_FILE="/etc/pam.d/sudo"
PAM_ENTRY="auth        sufficient  pam_exec.so stdout /usr/local/bin/goodix-fp-pam"

DRY_RUN=0
RESTORE_MODE=0
TEST_MODE=0

print_usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --dry-run       Preview changes and actions without modifying system files
  --restore       Restore original /etc/pam.d/sudo from backup and remove wrapper
  --test          Run standalone test of /usr/local/bin/goodix-fp-pam
  -h, --help      Show this help message

Examples:
  $0 --dry-run    # Preview what will be installed
  sudo $0         # Install PAM wrapper and configure /etc/pam.d/sudo
  sudo $0 --restore # Roll back changes to /etc/pam.d/sudo
EOF
}

# -----------------------------------------------------------------------------
# Parse Arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --restore|--uninstall)
            RESTORE_MODE=1
            shift
            ;;
        --test)
            TEST_MODE=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Privilege Detection Helper
# -----------------------------------------------------------------------------
SUDO=""
if [[ "$EUID" -ne 0 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        SUDO="[dry-run sudo]"
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "[-] Error: Root privileges required. Please run with sudo or as root." >&2
        exit 1
    fi
fi

# -----------------------------------------------------------------------------
# Test Mode
# -----------------------------------------------------------------------------
if [[ "$TEST_MODE" -eq 1 ]]; then
    echo "[*] Testing Goodix PAM wrapper..."
    TEST_BIN="${PAM_WRAPPER_DEST}"
    if [[ ! -x "${TEST_BIN}" ]]; then
        TEST_BIN="${PAM_WRAPPER_SRC}"
    fi

    if [[ ! -x "${TEST_BIN}" ]]; then
        echo "[-] Error: PAM wrapper not found or not executable at ${TEST_BIN}" >&2
        exit 1
    fi

    TARGET_USER="${SUDO_USER:-${USER:-$(id -un)}}"
    echo "[*] Invoking ${TEST_BIN} for user '${TARGET_USER}'..."
    PAM_USER="${TARGET_USER}" "${TEST_BIN}"
    EXIT_CODE=$?
    echo "[*] Exit code: ${EXIT_CODE}"
    if [[ ${EXIT_CODE} -eq 0 ]]; then
        echo "[+] Biometric verification SUCCEEDED (Exit 0)."
    else
        echo "[-] Biometric verification FAILED or timed out (Exit ${EXIT_CODE})."
    fi
    exit ${EXIT_CODE}
fi

# -----------------------------------------------------------------------------
# Restore Mode
# -----------------------------------------------------------------------------
if [[ "$RESTORE_MODE" -eq 1 ]]; then
    echo "[*] Looking for /etc/pam.d/sudo backups..."
    BACKUP_FILE=""
    if [[ -f "/etc/pam.d/sudo.goodix.orig" ]]; then
        BACKUP_FILE="/etc/pam.d/sudo.goodix.orig"
    else
        LATEST_BAK=$(ls -t /etc/pam.d/sudo.goodix.bak.* 2>/dev/null | head -n 1 || true)
        if [[ -n "${LATEST_BAK}" ]]; then
            BACKUP_FILE="${LATEST_BAK}"
        fi
    fi

    if [[ -z "${BACKUP_FILE}" || ! -f "${BACKUP_FILE}" ]]; then
        echo "[-] No backup file found matching /etc/pam.d/sudo.goodix.*" >&2
        echo "    Checking if /etc/pam.d/sudo can be cleaned manually..."
        if grep -q "goodix-fp-pam" "${PAM_TARGET_FILE}" 2>/dev/null; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                echo "[dry-run] Would remove 'goodix-fp-pam' line from ${PAM_TARGET_FILE}"
            else
                $SUDO sed -i '/goodix-fp-pam/d' "${PAM_TARGET_FILE}"
                echo "[+] Removed goodix-fp-pam entry from ${PAM_TARGET_FILE}."
            fi
        else
            echo "[i] ${PAM_TARGET_FILE} does not contain goodix-fp-pam entry."
        fi
    else
        echo "[*] Restoring ${PAM_TARGET_FILE} from ${BACKUP_FILE}..."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Would copy ${BACKUP_FILE} -> ${PAM_TARGET_FILE}"
        else
            $SUDO cp "${BACKUP_FILE}" "${PAM_TARGET_FILE}"
            $SUDO chmod 0644 "${PAM_TARGET_FILE}"
            echo "[+] Successfully restored ${PAM_TARGET_FILE}."
        fi
    fi

    if [[ -f "${PAM_WRAPPER_DEST}" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Would remove wrapper ${PAM_WRAPPER_DEST}"
        else
            $SUDO rm -f "${PAM_WRAPPER_DEST}"
            echo "[+] Removed ${PAM_WRAPPER_DEST}."
        fi
    fi

    echo "[+] Restore complete. PAM authentication reset to original state."
    exit 0
fi

# -----------------------------------------------------------------------------
# Install Pre-flight Checks
# -----------------------------------------------------------------------------
echo "================================================================="
echo "  Goodix 27c6:538d PAM sudo Installation Helper"
echo "================================================================="

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[!] RUNNING IN DRY-RUN MODE: No changes will be written to disk."
fi

# 1. Check PAM wrapper script
if [[ ! -f "${PAM_WRAPPER_SRC}" ]]; then
    echo "[-] Error: PAM wrapper script not found at ${PAM_WRAPPER_SRC}" >&2
    exit 1
fi

# 2. Check goodix-fp executable
if [[ ! -x "${GOODIX_BIN_DEST}" ]]; then
    # Look for built binary in repo
    CANDIDATE_BINS=(
        "${REPO_ROOT}/src/GoodixFp.Cli/bin/Release/net10.0/linux-x64/publish/GoodixFp.Cli"
        "${REPO_ROOT}/src/GoodixFp.Cli/bin/Release/net10.0/GoodixFp.Cli"
        "${REPO_ROOT}/src/GoodixFp.Cli/bin/Debug/net10.0/GoodixFp.Cli"
    )
    FOUND_BIN=""
    for c in "${CANDIDATE_BINS[@]}"; do
        if [[ -x "$c" ]]; then
            FOUND_BIN="$c"
            break
        fi
    done

    if [[ -n "${FOUND_BIN}" ]]; then
        echo "[*] Found compiled goodix-fp binary at: ${FOUND_BIN}"
        echo "[*] Installing binary to ${GOODIX_BIN_DEST}..."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Would copy ${FOUND_BIN} -> ${GOODIX_BIN_DEST} (chmod 0755)"
        else
            $SUDO cp "${FOUND_BIN}" "${GOODIX_BIN_DEST}"
            $SUDO chmod 0755 "${GOODIX_BIN_DEST}"
            echo "[+] Installed ${GOODIX_BIN_DEST}."
        fi
    else
        echo "[!] Notice: ${GOODIX_BIN_DEST} is not yet installed."
        echo "    You can publish and install it using: dotnet publish -c Release src/GoodixFp.Cli"
    fi
else
    echo "[+] Verified goodix-fp binary present at ${GOODIX_BIN_DEST}."
fi

# 3. Check udev rules
if [[ ! -f "/etc/udev/rules.d/70-goodix-fp.rules" ]]; then
    echo "[!] Notice: /etc/udev/rules.d/70-goodix-fp.rules not detected."
    if [[ -x "${REPO_ROOT}/scripts/setup-udev.sh" ]]; then
        echo "[*] Running scripts/setup-udev.sh to configure USB device permissions..."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] Would execute ${REPO_ROOT}/scripts/setup-udev.sh"
        else
            $SUDO "${REPO_ROOT}/scripts/setup-udev.sh"
        fi
    fi
else
    echo "[+] Verified udev rules present at /etc/udev/rules.d/70-goodix-fp.rules."
fi

# 4. Check for enrolled templates
CURRENT_USER="${SUDO_USER:-${USER:-$(id -un)}}"
USER_HOME=""
if command -v getent >/dev/null 2>&1; then
    USER_HOME="$(getent passwd "${CURRENT_USER}" 2>/dev/null | cut -d: -f6)"
fi
[[ -z "${USER_HOME}" ]] && USER_HOME="/home/${CURRENT_USER}"

TEMPLATES_FOUND=0
for dir in \
    "${USER_HOME}/.local/share/goodix-fp/templates" \
    "/var/lib/goodix-fp/templates/${CURRENT_USER}" \
    "/var/lib/goodix-fp/templates"; do
    if [[ -d "$dir" ]]; then
        shopt -s nullglob
        tfiles=("$dir"/*.tgla)
        shopt -u nullglob
        if [[ ${#tfiles[@]} -gt 0 ]]; then
            TEMPLATES_FOUND=${#tfiles[@]}
            echo "[+] Found ${TEMPLATES_FOUND} enrolled template(s) in $dir."
            break
        fi
    fi
done

if [[ ${TEMPLATES_FOUND} -eq 0 ]]; then
    echo "[!] WARNING: No enrolled fingerprint templates found for user '${CURRENT_USER}'."
    echo "    PAM will safely fall back to password authentication until you enroll."
    echo "    To enroll a finger after installation, run:"
    echo "        goodix-fp enroll index_right"
fi

# -----------------------------------------------------------------------------
# Install PAM Wrapper Script
# -----------------------------------------------------------------------------
echo "[*] Installing PAM wrapper script to ${PAM_WRAPPER_DEST}..."
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] Would copy ${PAM_WRAPPER_SRC} -> ${PAM_WRAPPER_DEST} (chmod 0755)"
else
    $SUDO cp "${PAM_WRAPPER_SRC}" "${PAM_WRAPPER_DEST}"
    $SUDO chmod 0755 "${PAM_WRAPPER_DEST}"
    echo "[+] Successfully installed ${PAM_WRAPPER_DEST}."
fi

# -----------------------------------------------------------------------------
# Backup /etc/pam.d/sudo
# -----------------------------------------------------------------------------
if [[ ! -f "${PAM_TARGET_FILE}" ]]; then
    echo "[-] Error: PAM target file not found at ${PAM_TARGET_FILE}" >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_TIMESTAMP_FILE="${PAM_TARGET_FILE}.goodix.bak.${TIMESTAMP}"
BACKUP_ORIG_FILE="${PAM_TARGET_FILE}.goodix.orig"

if [[ ! -f "${BACKUP_ORIG_FILE}" ]]; then
    echo "[*] Creating pristine baseline backup: ${BACKUP_ORIG_FILE}..."
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] Would copy ${PAM_TARGET_FILE} -> ${BACKUP_ORIG_FILE}"
    else
        $SUDO cp "${PAM_TARGET_FILE}" "${BACKUP_ORIG_FILE}"
        $SUDO chmod 0644 "${BACKUP_ORIG_FILE}"
    fi
fi

echo "[*] Creating timestamped backup: ${BACKUP_TIMESTAMP_FILE}..."
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] Would copy ${PAM_TARGET_FILE} -> ${BACKUP_TIMESTAMP_FILE}"
else
    $SUDO cp "${PAM_TARGET_FILE}" "${BACKUP_TIMESTAMP_FILE}"
    $SUDO chmod 0644 "${BACKUP_TIMESTAMP_FILE}"
fi

# -----------------------------------------------------------------------------
# Patch /etc/pam.d/sudo
# -----------------------------------------------------------------------------
if grep -q "goodix-fp-pam" "${PAM_TARGET_FILE}"; then
    echo "[+] Goodix PAM wrapper is already registered in ${PAM_TARGET_FILE}."
else
    echo "[*] Adding Goodix fingerprint auth to ${PAM_TARGET_FILE}..."
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] Would insert into ${PAM_TARGET_FILE}:"
        echo "          ${PAM_ENTRY}"
    else
        TEMP_PAM="$(mktemp)"
        # If file begins with #%PAM-1.0 header, insert immediately below it
        if grep -q '^#%PAM-1.0' "${PAM_TARGET_FILE}"; then
            awk -v entry="${PAM_ENTRY}" '
                /^#%PAM-1.0/ {
                    print $0;
                    print "# Goodix 27c6:538d Fingerprint Authentication";
                    print entry;
                    next;
                }
                { print $0; }
            ' "${PAM_TARGET_FILE}" > "${TEMP_PAM}"
        else
            # Otherwise prepend to top
            {
                echo "# Goodix 27c6:538d Fingerprint Authentication"
                echo "${PAM_ENTRY}"
                cat "${PAM_TARGET_FILE}"
            } > "${TEMP_PAM}"
        fi

        # Verify new file is non-empty and contains entry before replacing
        if [[ -s "${TEMP_PAM}" ]] && grep -q "goodix-fp-pam" "${TEMP_PAM}"; then
            $SUDO cp "${TEMP_PAM}" "${PAM_TARGET_FILE}"
            $SUDO chmod 0644 "${PAM_TARGET_FILE}"
            rm -f "${TEMP_PAM}"
            echo "[+] Successfully patched ${PAM_TARGET_FILE}."
        else
            rm -f "${TEMP_PAM}"
            echo "[-] Error generating patched PAM file. Aborting without modifying system." >&2
            exit 1
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Crucial Verification and Safety Guidance
# -----------------------------------------------------------------------------
echo ""
echo "========================================================================="
echo "  CRITICAL SAFETY NOTICE - PLEASE READ CAREFULLY!"
echo "========================================================================="
echo "  DO NOT CLOSE THIS TERMINAL WINDOW UNTIL YOU TEST SUDO AUTHENTICATION!"
echo ""
echo "  1. Keep this terminal session open as your safety fallback."
echo "  2. Open a NEW, separate terminal window."
echo "  3. In the new window, reset sudo credentials and run:"
echo "         sudo -k && sudo true"
echo ""
echo "  4. What should happen:"
echo "     - If fingerprint is enrolled: Touch sensor to authenticate."
echo "     - If verification matches: sudo succeeds immediately!"
echo "     - If verification fails or times out: Standard password prompt appears."
echo ""
echo "  5. If anything goes wrong or sudo fails:"
echo "     Return to THIS terminal and run:"
echo "         sudo ${SCRIPT_DIR}/install-pam.sh --restore"
echo "========================================================================="
echo ""
