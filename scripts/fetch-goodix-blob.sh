#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dell Canonical Goodix blob fetch & ELF patch script
# Downloads libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb, extracts
# libfprint-tod-goodix-53xc-0.0.6.so, verifies SHA-256, applies the 3-step ELF binary patch,
# and installs the standalone library to $XDG_DATA_HOME/goodix-fp/libgoodix_tod_53xc.so.

DEB_URL="http://dell.archive.canonical.com/updates/pool/public/libf/libfprint-2-tod1-goodix/libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb"
EXPECTED_SO_SHA256="bfa30696fbed9b86cfb5339293d458b9175d05b8895a8644d6b72615ffc9756b"
SO_INTERNAL_PATH="usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-tod-goodix-53xc-0.0.6.so"

TARGET_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/goodix-fp"
OUT_DIR="${OUT_DIR:-${TARGET_DIR}}"
TARGET_SO="${OUT_DIR}/libgoodix_tod_53xc.so"
TARGET_BIN="${OUT_DIR}/GF5298_GM168SEC_APP_13016.bin"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/goodix-fp"
mkdir -p "${CACHE_DIR}" "${TARGET_DIR}" "${OUT_DIR}"

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

echo "[+] Checking for Windows driver Wbdi.dll to extract Goodix 53xd firmware..."
WBDI_FOUND=""
for candidate in "${WBDI_DLL:-}" \
                 "/home/vladimir/AI/Workspaces/DriverReverseEngeneering/windows-driver/Wbdi.dll" \
                 "${SCRIPT_DIR}/../../windows-driver/Wbdi.dll" \
                 "${CACHE_DIR}/Wbdi.dll"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
        WBDI_FOUND="${candidate}"
        break
    fi
done

if [[ -z "${WBDI_FOUND}" ]]; then
    echo "[-] Warning: Wbdi.dll not found; skipping GF5298_GM168SEC_APP_13016.bin extraction." >&2
else
    echo "[+] Extracting firmware from ${WBDI_FOUND} -> ${TARGET_BIN}..."
    python3 - << 'EOF' "${WBDI_FOUND}" "${TARGET_BIN}"
import sys
import struct
import hashlib

wbdi_path = sys.argv[1]
out_bin = sys.argv[2]

# Precomputed MPEG-2 / POSIX MSB-first CRC table (0x04C11DB7)
poly = 0x04C11DB7
table = []
for i in range(256):
    r = i << 24
    for _ in range(8):
        if r & 0x80000000:
            r = ((r << 1) ^ poly) & 0xffffffff
        else:
            r = (r << 1) & 0xffffffff
    table.append(r)

def goodix_crc32(data: bytes) -> int:
    crc = 0xffffffff
    for b in data:
        idx = ((crc >> 24) ^ b) & 0xff
        crc = ((crc << 8) ^ table[idx]) & 0xffffffff
    return crc

with open(wbdi_path, "rb") as f:
    dll = f.read()

start = 0xdcfe0
length = 24286
res = dll[start : start + length]
if len(res) != length:
    raise ValueError(f"Extracted slice length {len(res)} != {length}")

magic = res[0:26]
if magic != b"\x19GF5298_GM168SEC_APP_13016":
    raise ValueError(f"Magic header mismatch: {magic}")
print("  Magic header verified: \\x19GF5298_GM168SEC_APP_13016")

stored_res_crc = struct.unpack("<I", res[24282:24286])[0]
if stored_res_crc != 0x5eed9d14:
    raise ValueError(f"Stored resource CRC 0x{stored_res_crc:08x} != 0x5eed9d14")
calc_res_crc = goodix_crc32(res[:24282])
if calc_res_crc != 0x5eed9d14:
    raise ValueError(f"Calculated resource CRC 0x{calc_res_crc:08x} != 0x5eed9d14")
print("  Resource CRC32 verified: 0x5eed9d14")

arm_payload = res[26:24282]
if len(arm_payload) != 24256:
    raise ValueError(f"ARM payload length {len(arm_payload)} != 24256")
arm_crc = goodix_crc32(arm_payload)
if arm_crc != 0x2448101a:
    raise ValueError(f"ARM payload CRC 0x{arm_crc:08x} != 0x2448101a")
print("  ARM payload length 24,256 and CRC32 0x2448101a verified")

hdr_tail = struct.pack("<II", 24256, 0x2448101a)
hdr_crc = goodix_crc32(hdr_tail)
if hdr_crc != 0xe752e818:
    raise ValueError(f"Header CRC 0x{hdr_crc:08x} != 0xe752e818")
hdr = struct.pack("<I", hdr_crc) + hdr_tail
fw = hdr + arm_payload
if len(fw) != 24268:
    raise ValueError(f"Final firmware length {len(fw)} != 24268")

sha256 = hashlib.sha256(fw).hexdigest()
expected_sha256 = "0f28f8f52860afea86bd56d869cd7f4fe41ba943edd1d56100113e94ecfd6c0d"
if sha256 != expected_sha256:
    raise ValueError(f"SHA-256 mismatch: got {sha256}, expected {expected_sha256}")
print(f"  Firmware SHA-256 verified: {sha256}")

with open(out_bin, "wb") as f:
    f.write(fw)

print(f"[+] Firmware successfully written to: {out_bin}")
EOF
    chmod 0644 "${TARGET_BIN}"
    if [[ "${TARGET_DIR}" != "${OUT_DIR}" ]]; then
        cp -f "${TARGET_BIN}" "${TARGET_DIR}/GF5298_GM168SEC_APP_13016.bin"
    fi
    echo "[+] Done. Firmware binary ready at ${TARGET_BIN}"
fi

