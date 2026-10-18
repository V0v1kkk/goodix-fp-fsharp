# Goodix F# fprintd D-Bus Bridge: Architecture, Security & Deployment Guide

This document describes the design, security model, deployment recipe, and maintenance procedures for connecting the pure F# Goodix fingerprint driver (`goodix-fp-fsharp`) to **DankGreeter** and **DMS (DankMaterialShell) Lock Screen** on Dell Vostro 7590 (`27c6:538d`).

---

## 1. Architecture Overview

### Component Flow
```
┌─────────────────────────────────────────────────────────────┐
│ Hardware: Goodix 53xc/53xd USB Sensor (27c6:538d)           │
└──────────────────────────────┬──────────────────────────────┘
                               │ USB bulk transfers (libusb-1.0)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ GoodixFp.Core (Pure F#)                                     │
│ - Protocol framing & CRC32                                  │
│ - TLS-PSK session key negotiation & AES decryption          │
│ - Raw 12-touch image capture & calibration                  │
└──────────────────────────────┬──────────────────────────────┘
                               │ Raw sensor image buffers
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ GoodixFp.NativeMatcher (Pure F# P/Invoke wrapper)           │
│ - Loads /usr/lib/goodix-fp/libgoodix_tod_53xc.so            │
│ - 1:1 biometric matching against TGLA templates             │
└──────────────────────────────┬──────────────────────────────┘
                               │ Match score & decision
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ GoodixFp.Daemon (/usr/lib/goodix-fp/goodix-fprintd)          │
│ - Native AOT executable (.NET 10)                            │
│ - Tmds.DBus.Protocol system bus service                     │
│ - Owns 'net.reactivated.Fprint'                             │
│ - Objects: /net/reactivated/Fprint/Manager                  │
│            /net/reactivated/Fprint/Device/0                 │
│ - Storage: /var/lib/goodix-fp/templates/<user>/<finger>.tgla│
└──────────────────────────────┬──────────────────────────────┘
                               │ Standard fprintd D-Bus API
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Stock Arch fprintd Package Components                       │
│ - /usr/lib/security/pam_fprintd.so                          │
│ - /usr/share/polkit-1/actions/net.reactivated.*             │
│ - /usr/share/dbus-1/system.d/net.reactivated.Fprint.conf    │
│ - Client utilities: fprintd-verify, fprintd-list            │
└──────────────────────────────┬──────────────────────────────┘
                               │ Standard PAM authentication
                               ▼
┌──────────────────────────────┴──────────────────────────────┐
│ Consumer Applications                                       │
│ - DankGreeter (/etc/pam.d/greetd)                           │
│ - DMS Lock Screen (DankMaterialShell screen lock)           │
└─────────────────────────────────────────────────────────────┘
```

### Design Rationale
- **Zero modification to libfprint**: We do not replace system libraries with unstable out-of-tree C forks.
- **Stock pam_fprintd**: Authentication consumers (DankGreeter, DMS, GDM, SDDM) use the standard distribution `pam_fprintd.so`.
- **Systemd drop-in redirection**: Rather than replacing system packages, `/etc/systemd/system/fprintd.service.d/10-goodix-fsharp.conf` overrides `ExecStart` of the stock `fprintd.service` to launch our Native AOT daemon.
- **Reuse stock D-Bus and Polkit policies**: Arch's stock `net.reactivated.Fprint.conf` and `net.reactivated.fprint.device.policy` provide all necessary bus permissions and Polkit action declarations.

---

## 2. Permission & Security Model

The bridge implements strict privilege separation and defense-in-depth:

### 1. D-Bus Caller Authentication (No Ambient Credentials)
- The daemon **never** trusts client-provided arguments (e.g., `username`) or environment variables for identity verification.
- When a client issues a request on the system bus, the daemon queries `org.freedesktop.DBus.GetConnectionUnixUser` to retrieve the authenticated POSIX UID of the caller process.
- Operations on another user's biometric state require root privileges (UID 0) or explicit Polkit authorization.

### 2. Polkit Authorization Integration
The daemon checks authorizations via `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` with `system-bus-name` subjects using the stock actions from the `fprintd` package:
- `net.reactivated.fprint.device.verify`: Default `allow_active=yes`. Allows the user in an active local console/desktop session to verify their own fingerprint.
- `net.reactivated.fprint.device.setusername`: Default `allow_active=auth_admin_keep`. Required if a non-root caller attempts to claim the device or verify for a different user.
- `net.reactivated.fprint.device.enroll`: Default `allow_active=auth_self_keep`. Required for enrollment operations.

### 3. Filesystem Sandboxing & Hardening
The daemon runs under strict systemd hardening configured in `10-goodix-fsharp.conf`:
- `ProtectSystem=strict`: The entire `/usr`, `/boot`, `/etc` filesystem hierarchy is mounted read-only.
- `ProtectHome=true`: User home directories (`/home`, `/root`, `/run/user`) are completely unmapped and inaccessible. The daemon cannot read any user files directly.
- `StateDirectory=goodix-fp`: Systemd provisions `/var/lib/goodix-fp` with permissions `0700` (`root:root`) and binds it read-write into the service mount namespace.
- `PrivateTmp=true`: Isolated private `/tmp` directory.
- `DeviceAllow=char-usb_device rw` & `ReadWritePaths=/sys/devices`: Limits hardware access exclusively to USB character devices and power configuration sysfs attributes.
- `MemoryDenyWriteExecute=true` (MDWE): Prevents creating memory mappings that are simultaneously writable and executable. Compatible with .NET Native AOT and `libgoodix_tod_53xc.so` (which has non-executable stacks and zero text relocations).

### 4. Biometric Data Confidentiality
- Biometric templates are stored exclusively in `/var/lib/goodix-fp/templates/<username>/<finger>.tgla`.
- Directory permissions are enforced at `0700` (`root:root`) and file permissions at `0600` (`root:root`).
- Raw camera frames, decrypted TLS communication, PSK secrets, and template bytes are never output to syslog or `journald`.

---

## 3. Arch Linux Installation Recipe

> [!IMPORTANT]
> Do not execute manual package installations or modify PAM configuration directly on the target machine without reviewing the planned commands below.

### Step 1: Install Base fprintd Package
Install the official distribution package to obtain `pam_fprintd.so`, client commands (`fprintd-verify`, `fprintd-list`), D-Bus policy, and Polkit actions:
```bash
sudo pacman -S --needed fprintd
```
*(Note: Do not start or enable fprintd.service yet.)*

### Step 2: Build Native AOT Daemon
From the repository root, build the self-contained Native AOT daemon binary:
```bash
dotnet publish src/GoodixFp.Daemon/GoodixFp.Daemon.fsproj \
    -c Release \
    -r linux-x64 \
    --self-contained \
    -o publish-daemon
```

### Step 3: Preview Installation (Dry Run)
Inspect the planned system changes, target paths, and unified diffs without modifying the system:
```bash
bash scripts/install-fprintd-bridge.sh --dry-run \
    --matcher ~/.local/share/goodix-fp/libgoodix_tod_53xc.so \
    --binary publish-daemon/GoodixFp.Daemon
```

### Step 4: Apply Bridge Installation
Execute the installer with root privileges:
```bash
sudo bash scripts/install-fprintd-bridge.sh --apply \
    --matcher ~/.local/share/goodix-fp/libgoodix_tod_53xc.so \
    --binary publish-daemon/GoodixFp.Daemon
```
The installer performs:
1. Installs `/usr/lib/goodix-fp/goodix-fprintd` (`0755 root:root`).
2. Copies matcher blob to `/usr/lib/goodix-fp/libgoodix_tod_53xc.so` (`0644 root:root`).
3. Creates template store `/var/lib/goodix-fp/templates` (`0700 root:root`).
4. Installs systemd drop-in `/etc/systemd/system/fprintd.service.d/10-goodix-fsharp.conf`.
5. Executes `systemctl daemon-reload` and restarts `fprintd.service`.

### Step 5: Import Existing Biometric Template
Import your pre-enrolled right index finger template into the secure system store:
```bash
sudo /usr/lib/goodix-fp/goodix-fprintd import \
    --user vladimir \
    --finger right-index-finger \
    --file ~/.local/share/goodix-fp/templates/right-index.tgla
```
*(Alternatively, pass `--import-template vladimir ~/.local/share/goodix-fp/templates/right-index.tgla` to `install-fprintd-bridge.sh --apply`)*

### Step 6: Verify Operation via Standard CLI
Verify that `fprintd` recognizes the device and enrolled finger:
```bash
fprintd-list vladimir
```
*Expected output:*
```
found 1 devices
Device at ...
Using device ...
Fingerprints for user vladimir:
 - right-index-finger
```

Perform an interactive verification on the sensor:
```bash
fprintd-verify vladimir
```
*Expected output:*
```
Using device ...
Listing enrolled fingers:
 - #0: right-index-finger
Verify result: verify-match (done)
```

### Step 7: Enable Fingerprint in DankGreeter & DMS (Described Only)
Once verification succeeds, enable the fingerprint factor independently in the consumer settings:
1. **DankGreeter**:
   - Open DankGreeter preferences or configuration.
   - Under Authentication, enable the **Fingerprint** factor (PAM service `greetd` invokes `system-local-login`, which includes `pam_fprintd.so` when configured).
   - Run the greeter theme and settings sync:
     `dms-greeter sync --yes`
     *(or via `dotnet fsi ~/scripts/system/setup.fsx -- dankgreeter --from greetd --sync-theme`)*
2. **DMS Lock Screen**:
   - Open DankMaterialShell settings.
   - Under Lock Screen Authentication, enable the **Fingerprint** factor in `OR/Auto` mode.
   - Password entry remains fully available as an immediate fallback without pressing Enter.

---

## 4. Rollback Procedure

To completely remove the bridge and return the system to stock state:
```bash
sudo bash scripts/install-fprintd-bridge.sh --remove
```

### What Rollback Does:
1. Stops `fprintd.service`.
2. Restores any pre-existing drop-in or deletes `/etc/systemd/system/fprintd.service.d/10-goodix-fsharp.conf`.
3. Runs `systemctl daemon-reload`.
4. If stock `fprintd` is installed and was enabled, restarts the stock service.
5. Removes `/usr/lib/goodix-fp/goodix-fprintd` and `/usr/lib/goodix-fp/libgoodix_tod_53xc.so`.
6. Preserves the template store in `/var/lib/goodix-fp/templates/` (pass `--purge` if you wish to erase biometric data).
7. Leaves `/etc/pam.d` and display manager configs completely intact.

---

## 5. Known Limitations & Operational Considerations

1. **GNOME Keyring Login Unlock**:
   When logging into a session using fingerprint authentication alone, `pam_gnome_keyring.so` does not receive the user's plaintext password. As a result, the default login keyring remains locked until an application (such as Google Chrome, VS Code, or Nextcloud) prompts for the keyring password.
   - *Recommendation*: Keep your login password as the keyring password. If you want automatic keyring unlocking at boot, enter your password; use fingerprint for unlocking the screen (DMS lock screen) where the keyring is already unlocked.
2. **Interactive Enrollment**:
   In Phase 1, `fprintd-enroll` D-Bus calls return an appropriate error code. Enrollment is performed using the interactive CLI tool:
   ```bash
   goodix-fp enroll right-index
   ```
   and then imported to `/var/lib/goodix-fp/templates/` via `goodix-fprintd import`.
3. **Sensor Concurrency**:
   Only one process can access the USB device at a time. If `goodix-fp probe` or `goodix-fp verify` is actively running, D-Bus `Claim` requests return `net.reactivated.Fprint.Error.AlreadyInUse`.

---

## 6. Integration & Real-Finger Testing

### 1. Automated Integration Test Suite (Private D-Bus, Real Hardware)
To run the automated 13-check integration harness against the real sensor on `vostro-laptop` without touching PAM or the system bus:
```bash
./tests/integration/run-bus-tests.sh --remote
```
Checks verified:
- D-Bus Introspection on `/net/reactivated/Fprint/Manager` and `/net/reactivated/Fprint/Device/0`
- `GetDevices` & `GetDefaultDevice` object paths
- Device properties (`name`, `scan-type`, `num-enroll-stages`, `finger-present`, `finger-needed`)
- `ListEnrolledFingers` -> `[right-index-finger]`
- `Claim` and `Release` lifecycle
- Concurrent `Claim` -> `AlreadyInUse`
- Non-claimer `VerifyStop` -> `ClaimDevice` error
- Privilege separation: `nobody` UID 65534 denied from listing/claiming target user prints
- `EnrollStart`, `EnrollStop`, `DeleteEnrolledFingers` return proper spec errors
- `VerifyStart` returns fast (<500ms; typical ~1ms)
- `VerifyStop` cancellation: sensor sleeps, subsequent `VerifyStart` restarts cleanly
- Mid-verify client crash (`kill -9`) -> automatic release via `NameOwnerChanged`, reclaimable
- Overall verification timeout path -> `VerifyStatus` (`done=true`) and clean stop

### 2. Interactive Real-Finger Touch Test (For User on vostro-laptop)
To verify fingerprint matching and rejection with real fingers:
```bash
ssh vostro-laptop
/tmp/goodix-fp/bus-test/manual-finger-test.sh
```
Covers:
- **Scenario 1**: Touch with enrolled finger (right index) -> `VerifyStatus: verify-match (done=True)`
- **Scenario 2**: Touch with unenrolled finger -> `VerifyStatus: verify-retry-scan` -> `verify-no-match (done=True)`
- **Scenario 3**: Start without touching -> `VerifyStop` cancellation -> clean restart -> `VerifyStop`
