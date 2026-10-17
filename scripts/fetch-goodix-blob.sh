#!/usr/bin/env bash
set -euo pipefail

# Dell Canonical Goodix blob fetch & ELF patch script
# Downloads libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb, extracts
# libfprint-tod-goodix-53xc-0.0.6.so, verifies SHA-256, applies the 3-step ELF binary patch,
# and installs the standalone library to $XDG_DATA_HOME/goodix-fp/libgoodix_tod_53xc.so.

DEB_URL="http://dell.archive.canonical.com/updates/pool/public/libf/libfprint-2-tod1-goodix/libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb"
EXPECTED_SO_SHA256="bfa30696fbed9b86cfb5339293d458b9175d05b8895a8644d6b72615ffc9756b"
SO_INTERNAL_PATH="usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-tod-goodix-53xc-0.0.6.so"

TARGET_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/goodix-fp"
TARGET_SO="${TARGET_DIR}/libgoodix_tod_53xc.so"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/goodix-fp"
mkdir -p "${CACHE_DIR}" "${TARGET_DIR}"

DEB_FILE="${CACHE_DIR}/libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb"

# Check if pre-cached deb exists in community-ref or cache
COMMUNITY_REF_DEB="/home/vladimir/AI/Workspaces/DriverReverseEngeneering/community-ref/libfprint-2-tod1-goodix_0.0.6.deb"
if [[ ! -f "${DEB_FILE}" ]]; then
    if [[ -f "${COMMUNITY_REF_DEB}" ]]; then
        echo "[+] Using locally cached deb from ${COMMUNITY_REF_DEB}"
        cp "${COMMUNITY_REF_DEB}" "${DEB_FILE}"
    else
        echo "[+] Downloading ${DEB_URL}..."
        curl -fsSL --retry 3 -o "${DEB_FILE}" "${DEB_URL}" || wget -q -O "${DEB_FILE}" "${DEB_URL}"
    fi
else
    echo "[+] Using existing cached deb at ${DEB_FILE}"
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "[+] Extracting ${SO_INTERNAL_PATH} from debian package..."
cd "${TMP_DIR}"
ar x "${DEB_FILE}"
tar -xf data.tar.xz "./${SO_INTERNAL_PATH}" || tar -xf data.tar.xz "${SO_INTERNAL_PATH}"

RAW_SO="${TMP_DIR}/${SO_INTERNAL_PATH}"
if [[ ! -f "${RAW_SO}" ]]; then
    echo "[-] Error: Failed to find extracted ${SO_INTERNAL_PATH}" >&2
    exit 1
fi

echo "[+] Verifying SHA-256 of extracted vendor library..."
ACTUAL_SHA256=$(sha256sum "${RAW_SO}" | awk '{print $1}')
if [[ "${ACTUAL_SHA256}" != "${EXPECTED_SO_SHA256}" ]]; then
    echo "[-] Error: SHA-256 mismatch!" >&2
    echo "    Expected: ${EXPECTED_SO_SHA256}" >&2
    echo "    Actual:   ${ACTUAL_SHA256}" >&2
    exit 1
fi
echo "[+] SHA-256 checksum verified: ${ACTUAL_SHA256}"

echo "[+] Applying 3-step ELF binary patch in Python..."
python3 - << 'EOF' "${RAW_SO}" "${TARGET_SO}"
import sys
import struct

src_path = sys.argv[1]
dst_path = sys.argv[2]

with open(src_path, "rb") as f:
    buf = bytearray(f.read())

# Step 1: Replace version 2 with 0 in .gnu.version at 0x21ac..0x232f
step1_count = 0
for offset in range(0x21ac, 0x232f, 2):
    ver = struct.unpack_from("<H", buf, offset)[0]
    if ver == 2:
        struct.pack_into("<H", buf, offset, 0)
        step1_count += 1
print(f"  Step 1: Replaced version 2 -> 0 across .gnu.version (count={step1_count})")

# Step 2: Zero vn_next at 0x23ac
struct.pack_into("<I", buf, 0x23ac, 0)
print("  Step 2: Zeroed vn_next at 0x23ac")

# Step 3: In .dynamic at 0x144dd0:
#         entries[0][1] = entries[4][1]
#         DT_VERNEEDNUM = 4
dynamic_offset = 0x144dd0
entry4_val = struct.unpack_from("<Q", buf, dynamic_offset + (4 * 16) + 8)[0]
struct.pack_into("<Q", buf, dynamic_offset + 8, entry4_val)

dt_verneednum_set = False
for i in range(32):
    tag = struct.unpack_from("<Q", buf, dynamic_offset + (i * 16))[0]
    if tag == 0x6fffffff: # DT_VERNEEDNUM
        struct.pack_into("<Q", buf, dynamic_offset + (i * 16) + 8, 4)
        dt_verneednum_set = True
        break

if not dt_verneednum_set:
    raise RuntimeError("Failed to locate DT_VERNEEDNUM in .dynamic section")
print("  Step 3: Repointed entry[0] to entry[4] (libc) and set DT_VERNEEDNUM = 4")

with open(dst_path, "wb") as f:
    f.write(buf)

print(f"[+] Patched library successfully written to: {dst_path}")
EOF

chmod 0755 "${TARGET_SO}"
echo "[+] Done. Standalone patched vendor blob ready at ${TARGET_SO}"
