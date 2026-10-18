#!/usr/bin/env bash
# =============================================================================
# install-fprintd-bridge.sh: Installer for Goodix F# fprintd D-Bus Bridge
# =============================================================================
# Connects Goodix 53xc/53xd F# driver to stock fprintd D-Bus API without
# modifying PAM files or greeter/DMS configurations.
#
# Modes:
#   --dry-run (default)  Preview planned actions and unified diffs of system files
#   --apply              Install bridge files, drop-in, and reload systemd (requires root)
#   --remove             Rollback bridge, restore stock fprintd (requires root)
#   --purge              Optional flag with --remove to also delete template store
#
# Options:
#   --matcher <path>            Path to proprietary libgoodix_tod_53xc.so blob
#   --binary <path>             Path to compiled GoodixFp.Daemon (goodix-fprintd) binary
#   --import-template <u <file> Import an existing TGLA template into /var/lib/goodix-fp
#   -h, --help                  Show this help text
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Target installation destinations (per contract)
DEST_DIR="/usr/lib/goodix-fp"
DEST_BIN="${DEST_DIR}/goodix-fprintd"
DEST_MATCHER="${DEST_DIR}/libgoodix_tod_53xc.so"

STATE_DIR="/var/lib/goodix-fp"
TEMPLATES_DIR="${STATE_DIR}/templates"
INSTALLER_STATE_DIR="${STATE_DIR}/installer-state"
MANIFEST_FILE="${INSTALLER_STATE_DIR}/install.manifest"
DROPIN_BACKUP="${INSTALLER_STATE_DIR}/10-goodix-fsharp.conf.bak"

DROPIN_DIR="/etc/systemd/system/fprintd.service.d"
DROPIN_TARGET="${DROPIN_DIR}/10-goodix-fsharp.conf"
DROPIN_SRC="${REPO_ROOT}/packaging/fprintd/10-goodix-fsharp.conf"

MODE="dry-run"
PURGE=0
MATCHER_ARG=""
BINARY_ARG=""
IMPORT_USER=""
IMPORT_FILE=""

print_usage() {
    cat <<EOF
Usage: $0 [MODE] [OPTIONS]

Modes:
  --dry-run                      Preview planned actions and file diffs (default, non-root)
  --apply                        Execute installation and configuration (requires root)
  --remove                       Rollback bridge and restore stock fprintd (requires root)

Options:
  --purge                        With --remove: delete /var/lib/goodix-fp templates
  --matcher <path>               Path to libgoodix_tod_53xc.so matcher blob
  --binary <path>                Path to pre-built goodix-fprintd binary
  --import-template <user> <file> Import TGLA template for user to right-index-finger
  -h, --help                     Show this help message

Examples:
  # 1. Preview changes (can run as normal user)
  $0 --dry-run

  # 2. Apply bridge installation
  sudo $0 --apply --matcher ~/.local/share/goodix-fp/libgoodix_tod_53xc.so

  # 3. Apply and import existing right-index.tgla template
  sudo $0 --apply --import-template vladimir ~/.local/share/goodix-fp/templates/right-index.tgla

  # 4. Rollback to stock fprintd
  sudo $0 --remove
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --apply)
            MODE="apply"
            shift
            ;;
        --remove|--rollback|--uninstall)
            MODE="remove"
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        --matcher)
            if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
                echo "[-] Error: --matcher requires a file path." >&2
                exit 1
            fi
            MATCHER_ARG="$2"
            shift 2
            ;;
        --binary)
            if [[ $# -lt 2 || "$2" =~ ^-- ]]; then
                echo "[-] Error: --binary requires a file path." >&2
                exit 1
            fi
            BINARY_ARG="$2"
            shift 2
            ;;
        --import-template)
            if [[ $# -lt 3 || "$2" =~ ^-- || "$3" =~ ^-- ]]; then
                echo "[-] Error: --import-template requires <user> and <path>." >&2
                exit 1
            fi
            IMPORT_USER="$2"
            IMPORT_FILE="$3"
            shift 3
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "[-] Error: Unknown argument '$1'" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

# Root privilege validation
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[-] Error: Mode '--${MODE}' requires root privileges." >&2
        echo "    Please run with: sudo $0 --${MODE}" >&2
        exit 1
    fi
}

# Pacman ownership check to prevent accidental clobbering of system packages
check_pacman_ownership() {
    local target="$1"
    if [[ -e "${target}" ]] && command -v pacman >/dev/null 2>&1; then
        if pacman -Qo "${target}" >/dev/null 2>&1; then
            local owner
            owner=$(pacman -Qo "${target}" 2>&1)
            echo "[-] Error: Target file '${target}' is owned by a pacman package:" >&2
            echo "    ${owner}" >&2
            echo "    Refusing to overwrite package-managed file." >&2
            exit 1
        fi
    fi
}

# Check if fprintd package is present
check_fprintd_package() {
    if command -v pacman >/dev/null 2>&1; then
        if ! pacman -Q fprintd >/dev/null 2>&1; then
            if [[ "${MODE}" == "apply" ]]; then
                echo "[-] Error: Package 'fprintd' is not installed." >&2
                echo "    The bridge requires stock 'fprintd' for pam_fprintd.so and D-Bus/Polkit policy files." >&2
                echo "    Please execute the following transaction first (never run automatically by installer):" >&2
                echo "        sudo pacman -S --needed fprintd" >&2
                exit 1
            else
                echo "[!] Notice: Package 'fprintd' is not currently installed on this system."
                echo "    The bridge requires stock 'fprintd' for pam_fprintd.so and D-Bus/Polkit policies."
                echo "    Suggested manual transaction before running --apply:"
                echo "        sudo pacman -S --needed fprintd"
                echo ""
            fi
        else
            local fprintd_ver
            fprintd_ver=$(pacman -Q fprintd 2>/dev/null || echo "installed")
            echo "[+] Detected required base package: ${fprintd_ver}"
        fi
    fi
}

# Locate binary source
find_binary() {
    if [[ -n "${BINARY_ARG}" ]]; then
        if [[ -L "${BINARY_ARG}" ]]; then
            echo "[-] Error: Provided binary path '${BINARY_ARG}' is a symlink. Only regular files accepted." >&2
            exit 1
        fi
        if [[ ! -f "${BINARY_ARG}" ]]; then
            echo "[-] Error: Provided binary path '${BINARY_ARG}' does not exist or is not a regular file." >&2
            exit 1
        fi
        echo "${BINARY_ARG}"
        return 0
    fi

    local candidates=(
        "${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/goodix-fprintd"
        "${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/linux-x64/publish/GoodixFp.Daemon"
        "${REPO_ROOT}/publish-daemon/goodix-fprintd"
        "${REPO_ROOT}/publish-daemon/GoodixFp.Daemon"
        "${REPO_ROOT}/goodix-fprintd"
        "${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/goodix-fprintd"
        "${REPO_ROOT}/src/GoodixFp.Daemon/bin/Release/net10.0/GoodixFp.Daemon"
        "${DEST_BIN}"
    )

    for cand in "${candidates[@]}"; do
        if [[ -f "${cand}" && ! -L "${cand}" ]]; then
            echo "${cand}"
            return 0
        fi
    done

    echo ""
}

# Locate matcher blob
find_matcher() {
    if [[ -n "${MATCHER_ARG}" ]]; then
        if [[ -L "${MATCHER_ARG}" ]]; then
            echo "[-] Error: Provided matcher blob path '${MATCHER_ARG}' is a symlink. Only regular files accepted." >&2
            exit 1
        fi
        if [[ ! -f "${MATCHER_ARG}" ]]; then
            echo "[-] Error: Provided matcher blob path '${MATCHER_ARG}' does not exist or is not a regular file." >&2
            exit 1
        fi
        echo "${MATCHER_ARG}"
        return 0
    fi

    local user_home="${HOME}"
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    fi

    local candidates=(
        "${user_home}/.local/share/goodix-fp/libgoodix_tod_53xc.so"
        "/usr/local/lib/goodix-fp/libgoodix_tod_53xc.so"
        "${DEST_MATCHER}"
    )

    for cand in "${candidates[@]}"; do
        if [[ -f "${cand}" && ! -L "${cand}" ]]; then
            echo "${cand}"
            return 0
        fi
    done

    echo ""
}

# =============================================================================
# MODE: DRY-RUN
# =============================================================================
do_dry_run() {
    echo "================================================================="
    echo "  Goodix F# fprintd Bridge — Installation Plan (Dry Run)"
    echo "================================================================="
    echo ""

    check_fprintd_package

    echo "[*] Step 1: Daemon binary resolution"
    local bin_src
    bin_src=$(find_binary)
    if [[ -n "${bin_src}" ]]; then
        echo "    Source:      ${bin_src}"
        echo "    Destination: ${DEST_BIN} (mode: 0755, owner: root:root)"
    else
        echo "    Source:      [NOT BUILT YET] (compile via: dotnet publish src/GoodixFp.Daemon/GoodixFp.Daemon.fsproj -c Release -r linux-x64 --self-contained)"
        echo "    Destination: ${DEST_BIN} (mode: 0755, owner: root:root)"
    fi
    echo ""

    echo "[*] Step 2: Proprietary matcher blob resolution"
    local matcher_src
    matcher_src=$(find_matcher)
    if [[ -n "${matcher_src}" ]]; then
        echo "    Source:      ${matcher_src} (verified regular file, non-symlink)"
        echo "    Destination: ${DEST_MATCHER} (mode: 0644, owner: root:root)"
    else
        echo "    Source:      [NOT FOUND] (specify with --matcher <path> or place in ~/.local/share/goodix-fp/libgoodix_tod_53xc.so)"
        echo "    Destination: ${DEST_MATCHER} (mode: 0644, owner: root:root)"
    fi
    echo ""

    echo "[*] Step 3: Biometric template store directory"
    echo "    Directory:   ${TEMPLATES_DIR} (mode: 0700, owner: root:root)"
    echo "    State Dir:   ${INSTALLER_STATE_DIR} (mode: 0700, owner: root:root)"
    echo ""

    echo "[*] Step 4: Systemd service drop-in configuration"
    echo "    Target:      ${DROPIN_TARGET} (mode: 0644, owner: root:root)"
    echo "    Unified diff to be applied:"
    echo "-----------------------------------------------------------------"
    if [[ -f "${DROPIN_TARGET}" ]]; then
        diff -u --label="${DROPIN_TARGET} (current)" --label="${DROPIN_TARGET} (proposed)" "${DROPIN_TARGET}" "${DROPIN_SRC}" || true
    else
        diff -u --label="/dev/null" --label="${DROPIN_TARGET}" /dev/null "${DROPIN_SRC}" || true
    fi
    echo "-----------------------------------------------------------------"
    echo ""

    echo "[*] Step 5: System activation commands"
    echo "    1. systemctl daemon-reload"
    echo "    2. systemctl restart fprintd.service"
    echo ""

    if [[ -n "${IMPORT_FILE}" ]]; then
        echo "[*] Step 6: Template import"
        echo "    User:   ${IMPORT_USER}"
        echo "    Source: ${IMPORT_FILE}"
        echo "    Action: goodix-fprintd import --user ${IMPORT_USER} --finger right-index-finger --file ${IMPORT_FILE}"
        echo ""
    fi

    echo "[*] Safety verification:"
    echo "    - /etc/pam.d will NOT be modified"
    echo "    - Greeter / lock screen auth factors will NOT be toggled automatically"
    echo "    - Pacman package files will NOT be overwritten"
    echo ""
    echo "To apply this configuration, run:"
    echo "    sudo $0 --apply ${MATCHER_ARG:+--matcher \"${MATCHER_ARG}\"} ${BINARY_ARG:+--binary \"${BINARY_ARG}\"} ${IMPORT_USER:+--import-template \"${IMPORT_USER}\" \"${IMPORT_FILE}\"}"
    echo "================================================================="
}

# =============================================================================
# MODE: APPLY
# =============================================================================
do_apply() {
    check_root

    echo "================================================================="
    echo "  Applying Goodix F# fprintd Bridge Installation"
    echo "================================================================="

    check_fprintd_package

    local bin_src
    bin_src=$(find_binary)
    if [[ -z "${bin_src}" ]]; then
        echo "[-] Error: Daemon binary could not be found." >&2
        echo "    Please build it first or specify --binary <path>:" >&2
        echo "        dotnet publish src/GoodixFp.Daemon/GoodixFp.Daemon.fsproj -c Release -r linux-x64 --self-contained" >&2
        exit 1
    fi

    local matcher_src
    matcher_src=$(find_matcher)
    if [[ -z "${matcher_src}" ]]; then
        echo "[-] Error: Proprietary matcher blob libgoodix_tod_53xc.so not found." >&2
        echo "    Please specify with --matcher <path>." >&2
        exit 1
    fi

    # Enforce regular file check on source files
    if [[ -L "${bin_src}" || ! -f "${bin_src}" ]]; then
        echo "[-] Error: Binary '${bin_src}' is a symlink or not a regular file." >&2
        exit 1
    fi
    if [[ -L "${matcher_src}" || ! -f "${matcher_src}" ]]; then
        echo "[-] Error: Matcher '${matcher_src}' is a symlink or not a regular file." >&2
        exit 1
    fi

    # Pacman ownership guard
    check_pacman_ownership "${DEST_BIN}"
    check_pacman_ownership "${DEST_MATCHER}"
    check_pacman_ownership "${DROPIN_TARGET}"

    # Prepare directories
    echo "[*] Creating directories..."
    install -d -m 0755 "${DEST_DIR}"
    install -d -m 0700 "${STATE_DIR}"
    install -d -m 0700 "${TEMPLATES_DIR}"
    install -d -m 0700 "${INSTALLER_STATE_DIR}"
    install -d -m 0755 "${DROPIN_DIR}"

    # Backup existing drop-in if present
    if [[ -f "${DROPIN_TARGET}" ]]; then
        echo "[*] Backing up existing drop-in to ${DROPIN_BACKUP}..."
        cp -a "${DROPIN_TARGET}" "${DROPIN_BACKUP}"
    fi

    # Install binary (0755 root:root)
    echo "[*] Installing binary to ${DEST_BIN}..."
    install -m 0755 -o root -g root "${bin_src}" "${DEST_BIN}"

    # Install matcher blob (0644 root:root)
    echo "[*] Installing matcher blob to ${DEST_MATCHER}..."
    install -m 0644 -o root -g root "${matcher_src}" "${DEST_MATCHER}"

    # Install systemd drop-in (0644 root:root)
    echo "[*] Installing systemd drop-in to ${DROPIN_TARGET}..."
    install -m 0644 -o root -g root "${DROPIN_SRC}" "${DROPIN_TARGET}"

    # Record installer state manifest
    cat > "${MANIFEST_FILE}" <<EOF
# Goodix F# fprintd bridge installer state
INSTALLED_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
BINARY="${DEST_BIN}"
MATCHER="${DEST_MATCHER}"
DROPIN="${DROPIN_TARGET}"
STATE_DIR="${STATE_DIR}"
EOF
    chmod 0600 "${MANIFEST_FILE}"

    # Reload systemd
    echo "[*] Reloading systemd daemon..."
    systemctl daemon-reload

    # Restart fprintd.service
    echo "[*] Restarting fprintd.service..."
    systemctl restart fprintd.service || {
        echo "[!] Warning: systemctl restart fprintd.service returned non-zero. Check journalctl -u fprintd.service."
    }

    # Optional template import
    if [[ -n "${IMPORT_FILE}" ]]; then
        echo "[*] Importing template for user '${IMPORT_USER}' from '${IMPORT_FILE}'..."
        if [[ -L "${IMPORT_FILE}" || ! -f "${IMPORT_FILE}" ]]; then
            echo "[-] Error: Template file '${IMPORT_FILE}' is invalid or a symlink. Skipping import." >&2
        else
            "${DEST_BIN}" import --user "${IMPORT_USER}" --finger right-index-finger --file "${IMPORT_FILE}"
            echo "[+] Template successfully imported."
        fi
    fi

    echo ""
    echo "================================================================="
    echo "  Installation Successful!"
    echo "================================================================="
    echo "Next steps:"
    echo "  1. Verify enrolled fingerprints:"
    echo "     fprintd-list ${SUDO_USER:-vladimir}"
    echo "  2. Test sensor authentication:"
    echo "     fprintd-verify ${SUDO_USER:-vladimir}"
    echo "  3. When ready, enable fingerprint factor in DankGreeter and DMS."
    echo "================================================================="
}

# =============================================================================
# MODE: REMOVE (ROLLBACK)
# =============================================================================
do_remove() {
    check_root

    echo "================================================================="
    echo "  Rolling back Goodix F# fprintd Bridge"
    echo "================================================================="

    echo "[*] Stopping fprintd.service..."
    systemctl stop fprintd.service 2>/dev/null || true

    # Drop-in removal or restoration
    if [[ -f "${DROPIN_BACKUP}" ]]; then
        echo "[*] Restoring previous drop-in from ${DROPIN_BACKUP}..."
        cp -a "${DROPIN_BACKUP}" "${DROPIN_TARGET}"
        rm -f "${DROPIN_BACKUP}"
    elif [[ -f "${DROPIN_TARGET}" ]]; then
        echo "[*] Removing drop-in ${DROPIN_TARGET}..."
        rm -f "${DROPIN_TARGET}"
        rmdir "${DROPIN_DIR}" 2>/dev/null || true
    fi

    # Remove installed binaries and blobs
    if [[ -f "${DEST_BIN}" ]]; then
        echo "[*] Removing ${DEST_BIN}..."
        rm -f "${DEST_BIN}"
    fi

    if [[ -f "${DEST_MATCHER}" ]]; then
        echo "[*] Removing ${DEST_MATCHER}..."
        rm -f "${DEST_MATCHER}"
    fi

    rmdir "${DEST_DIR}" 2>/dev/null || true

    # Systemd daemon reload
    echo "[*] Reloading systemd daemon..."
    systemctl daemon-reload

    # Check if stock fprintd is available and start it if enabled
    if command -v pacman >/dev/null 2>&1 && pacman -Q fprintd >/dev/null 2>&1; then
        if systemctl is-enabled fprintd.service >/dev/null 2>&1; then
            echo "[*] Restarting stock fprintd.service..."
            systemctl restart fprintd.service || true
        fi
    fi

    # Handle template store
    if [[ "${PURGE}" -eq 1 ]]; then
        echo "[*] Purging state directory ${STATE_DIR}..."
        rm -rf "${STATE_DIR}"
    else
        rm -f "${MANIFEST_FILE}"
        rmdir "${INSTALLER_STATE_DIR}" 2>/dev/null || true
        if [[ -d "${TEMPLATES_DIR}" ]]; then
            echo "[+] Biometric template store preserved at ${TEMPLATES_DIR}."
            echo "    (Pass --purge to remove template store during removal)"
        fi
    fi

    echo ""
    echo "================================================================="
    echo "  Rollback Complete!"
    echo "================================================================="
}

case "${MODE}" in
    dry-run)
        do_dry_run
        ;;
    apply)
        do_apply
        ;;
    remove)
        do_remove
        ;;
esac
