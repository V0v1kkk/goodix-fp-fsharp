#!/usr/bin/env bash
set -euo pipefail

# setup-udev.sh: Install udev rules for Goodix Fingerprint Sensor 27c6:538d

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RULES_SRC="${REPO_ROOT}/packaging/udev/70-goodix-fp.rules"
RULES_DEST="/etc/udev/rules.d/70-goodix-fp.rules"

if [[ ! -f "${RULES_SRC}" ]]; then
    echo "[-] Error: udev rules file not found at ${RULES_SRC}" >&2
    exit 1
fi

SUDO=""
if [[ "$EUID" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "[-] Error: Root privileges required to copy to /etc/udev/rules.d/" >&2
        exit 1
    fi
fi

echo "[*] Copying ${RULES_SRC} -> ${RULES_DEST}..."
$SUDO cp "${RULES_SRC}" "${RULES_DEST}"
$SUDO chmod 0644 "${RULES_DEST}"

echo "[*] Reloading udev rules..."
$SUDO udevadm control --reload-rules

echo "[*] Triggering udev events for Goodix sensor..."
if ! $SUDO udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --attr-match=idProduct=538d 2>/dev/null; then
    $SUDO udevadm trigger
fi

echo "[+] udev rules successfully installed and reloaded!"
echo "    Device node access is granted to active desktop sessions (uaccess) and members of 'plugdev'."
if [[ -n "${SUDO_USER:-}" ]]; then
    TARGET_USER="${SUDO_USER}"
else
    TARGET_USER="$(id -un)"
fi

if getent group plugdev >/dev/null 2>&1; then
    if ! id -nG "${TARGET_USER}" | grep -qw "plugdev"; then
        echo "[i] Tip: Add '${TARGET_USER}' to the 'plugdev' group for headless/background access:"
        echo "    sudo usermod -aG plugdev ${TARGET_USER}"
    fi
fi
