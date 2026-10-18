#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# goodix-fp-fsharp: Standalone Root Installer
# ==============================================================================
# - Verifies dependencies (libusb-1.0, etc.)
# - Compiles/installs Native AOT binary to /usr/local/bin/goodix-fp
# - Installs udev rules to /etc/udev/rules.d/70-goodix-fp.rules
# - Reloads udev subsystem
# - Verifies device communication via 'goodix-fp probe'
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DEST="/usr/local/bin/goodix-fp"
RULES_DEST="/etc/udev/rules.d/70-goodix-fp.rules"

echo "================================================================="
echo "  Goodix FP Linux Driver & Matcher Installer"
echo "================================================================="

# 1. Enforce root privileges
if [[ "${EUID}" -ne 0 ]]; then
    echo "[-] Error: This installer must be run as root (or with sudo)." >&2
    echo "    Usage: sudo $0" >&2
    exit 1
fi

# 2. Dependency Checks: libusb-1.0
echo "[*] Checking system dependencies..."

has_libusb=0
if command -v ldconfig >/dev/null 2>&1; then
    if ldconfig -p 2>/dev/null | grep -q "libusb-1.0\.so"; then
        has_libusb=1
    fi
fi

if [[ "${has_libusb}" -eq 0 ]]; then
    for candidate in /usr/lib/libusb-1.0.so* \
                     /usr/lib64/libusb-1.0.so* \
                     /usr/lib/*-linux-gnu/libusb-1.0.so* \
                     /usr/local/lib/libusb-1.0.so* \
                     /lib/libusb-1.0.so* \
                     /lib64/libusb-1.0.so*; do
        if [[ -e "${candidate}" ]]; then
            has_libusb=1
            break
        fi
    done
fi

if [[ "${has_libusb}" -eq 0 ]]; then
    echo "[-] Error: libusb-1.0 is required but was not found on your system." >&2
    echo "    Please install libusb using your distribution package manager:" >&2
    echo "      - Arch Linux: sudo pacman -S libusb" >&2
    echo "      - Ubuntu/Debian: sudo apt install libusb-1.0-0 libusb-1.0-0-dev" >&2
    echo "      - Fedora: sudo dnf install libusb1 libusb1-devel" >&2
    exit 1
fi
echo "[+] libusb-1.0 dependency found."

# 3. Locate or build Native AOT binary
BIN_SRC="${SCRIPT_DIR}/src/GoodixFp.Cli/bin/Release/net10.0/linux-x64/publish/GoodixFp.Cli"

if [[ ! -f "${BIN_SRC}" ]]; then
    echo "[*] Pre-compiled Native AOT binary not found at:"
    echo "    ${BIN_SRC}"
    if command -v dotnet >/dev/null 2>&1; then
        echo "[*] .NET SDK detected. Compiling Native AOT binary..."
        (
            cd "${SCRIPT_DIR}"
            unset CFLAGS CXXFLAGS LDFLAGS
            dotnet publish src/GoodixFp.Cli/GoodixFp.Cli.fsproj \
                -c Release \
                -r linux-x64 \
                --self-contained \
                -o "${SCRIPT_DIR}/src/GoodixFp.Cli/bin/Release/net10.0/linux-x64/publish"
        )
    else
        echo "[-] Error: Native AOT binary is missing and 'dotnet' SDK is not installed." >&2
        echo "    Please install .NET 10 SDK or build with: dotnet publish src/GoodixFp.Cli/GoodixFp.Cli.fsproj -c Release -r linux-x64 --self-contained" >&2
        exit 1
    fi
fi

if [[ ! -f "${BIN_SRC}" ]]; then
    echo "[-] Error: Failed to find or generate binary at ${BIN_SRC}" >&2
    exit 1
fi

# 4. Copy binary to /usr/local/bin/goodix-fp
echo "[*] Installing binary to ${BIN_DEST}..."
install -Dm755 "${BIN_SRC}" "${BIN_DEST}"
echo "[+] Installed ${BIN_DEST} successfully."

# 5. Install udev rules
RULES_SRC="${SCRIPT_DIR}/packaging/udev/70-goodix-fp.rules"
if [[ ! -f "${RULES_SRC}" ]]; then
    RULES_SRC="${SCRIPT_DIR}/packaging/archlinux/70-goodix-fp.rules"
fi

if [[ -f "${RULES_SRC}" ]]; then
    echo "[*] Installing udev rules to ${RULES_DEST}..."
    install -Dm644 "${RULES_SRC}" "${RULES_DEST}"
    echo "[+] Installed udev rules successfully."
else
    echo "[!] Warning: udev rules file not found, skipping udev rules installation."
fi

# 6. Reload udev subsystem
if command -v udevadm >/dev/null 2>&1; then
    echo "[*] Reloading udev rules and triggering USB events..."
    udevadm control --reload-rules || true
    udevadm trigger --subsystem-match=usb || true
    echo "[+] udev subsystem reloaded."
else
    echo "[!] Warning: 'udevadm' not available; please reload udev manually or reboot."
fi

# 7. Check for vendor matcher library and firmware blob
echo "[*] Checking for Goodix proprietary matcher blob..."
MATCH_FOUND=0
USER_HOME="${HOME}"
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
fi

for cand in "${USER_HOME}/.local/share/goodix-fp/libgoodix_tod_53xc.so" \
            "/usr/local/lib/goodix-fp/libgoodix_tod_53xc.so" \
            "/usr/lib/goodix-fp/libgoodix_tod_53xc.so"; do
    if [[ -f "${cand}" ]]; then
        MATCH_FOUND=1
        echo "[+] Found proprietary matcher library: ${cand}"
        break
    fi
done

if [[ "${MATCH_FOUND}" -eq 0 ]]; then
    echo "[i] Notice: Proprietary matcher blob not detected."
    echo "    To enable biometric template enrollment and 1:1 matching, run:"
    echo "      ./scripts/fetch-goodix-blob.sh"
fi

# 8. Verify installation via 'goodix-fp probe'
echo "[*] Verifying installation with '${BIN_DEST} probe'..."
set +e
"${BIN_DEST}" probe
PROBE_STATUS=$?
set -e

if [[ "${PROBE_STATUS}" -eq 0 ]]; then
    echo "[+] Verification successful: Goodix fingerprint sensor detected and probed!"
else
    echo "[i] Probe completed (exit code ${PROBE_STATUS})."
    echo "    If the sensor was not detected, verify that the device is connected."
    echo "    When plugged in, udev will grant access via the 'uaccess' tag."
    echo "    You can run '${BIN_DEST} probe' anytime to test connectivity."
fi

echo ""
echo "================================================================="
echo "  Installation Complete!"
echo "================================================================="
echo "Commands:"
echo "  goodix-fp probe                     # Test sensor hardware"
echo "  goodix-fp enroll <finger-name>      # Interactive 12-touch enrollment"
echo "  goodix-fp verify                    # Match finger against enrolled templates"
echo "  sudo ./scripts/install-pam.sh       # Configure PAM for sudo fingerprint auth"
echo "  goodix-fp benchmark                 # Run performance benchmark suite"
echo "================================================================="
