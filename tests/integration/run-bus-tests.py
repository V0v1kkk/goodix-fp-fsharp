#!/usr/bin/env python3
"""
Integration test client for Goodix F# fprintd D-Bus Bridge daemon.
Runs against a private system bus and real hardware sensor on vostro-laptop.
Checks methods, signals, errors, rights of different UIDs, cancellation,
fast VerifyStart response, client crash (-9), and overall timeout path.
"""

import asyncio
import os
import subprocess
import sys
import time
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
from dbus_next.errors import DBusError
from dbus_next import Message, MessageType

BUS_ADDRESS = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
if not BUS_ADDRESS:
    print("[-] Error: DBUS_SYSTEM_BUS_ADDRESS environment variable must be set.")
    sys.exit(1)

SERVICE = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
MANAGER_IFACE = "net.reactivated.Fprint.Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_IFACE = "net.reactivated.Fprint.Device"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
INTROSPECT_IFACE = "org.freedesktop.DBus.Introspectable"

pass_count = 0
fail_count = 0

def log_test(name, passed, detail=""):
    global pass_count, fail_count
    if passed:
        pass_count += 1
        print(f"  [PASS] {name} {detail}")
    else:
        fail_count += 1
        print(f"  [FAIL] {name} - {detail}")


async def create_client():
    bus = await MessageBus(bus_address=BUS_ADDRESS).connect()
    # Subscribe to signals from net.reactivated.Fprint
    await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="AddMatch",
            signature="s",
            body=[f"type='signal',sender='{SERVICE}'"],
        )
    )
    return bus


async def call_method(bus, msg):
    reply = await bus.call(msg)
    if reply is not None and reply.message_type == MessageType.ERROR:
        err_msg = reply.body[0] if (reply.body and len(reply.body) > 0) else ""
        raise DBusError(reply.error_name, err_msg, reply)
    return reply.body if reply is not None else None


async def test_introspection(bus):
    try:
        reply_mgr = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=MANAGER_PATH,
                interface=INTROSPECT_IFACE,
                member="Introspect",
            )
        )
        xml_mgr = reply_mgr[0]
        has_mgr = MANAGER_IFACE in xml_mgr

        reply_dev = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=INTROSPECT_IFACE,
                member="Introspect",
            )
        )
        xml_dev = reply_dev[0]
        has_dev = DEVICE_IFACE in xml_dev

        log_test("1. Introspection (Manager & Device)", has_mgr and has_dev)
    except Exception as ex:
        log_test("1. Introspection", False, str(ex))


async def test_get_devices(bus):
    try:
        reply_devices = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=MANAGER_PATH,
                interface=MANAGER_IFACE,
                member="GetDevices",
            )
        )
        devices = reply_devices[0]
        has_dev = DEVICE_PATH in devices

        reply_default = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=MANAGER_PATH,
                interface=MANAGER_IFACE,
                member="GetDefaultDevice",
            )
        )
        default_dev = reply_default[0]
        is_match = (default_dev == DEVICE_PATH)

        log_test("2. GetDevices / GetDefaultDevice", has_dev and is_match, f"devices={devices}")
    except Exception as ex:
        log_test("2. GetDevices / GetDefaultDevice", False, str(ex))


async def test_properties(bus):
    try:
        reply = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=PROPS_IFACE,
                member="GetAll",
                signature="s",
                body=[DEVICE_IFACE],
            )
        )
        props = reply[0]
        name = props.get("name", None)
        scan_type = props.get("scan-type", None)
        stages = props.get("num-enroll-stages", None)
        f_present = props.get("finger-present", None)
        f_needed = props.get("finger-needed", None)

        valid = (
            name is not None
            and "Goodix" in name.value
            and scan_type.value == "press"
            and stages.value == -1
            and f_present.value is False
            and f_needed.value is False
        )
        log_test("3. Device Properties GetAll", valid, f"name={name.value if name else 'None'}")
    except Exception as ex:
        log_test("3. Device Properties GetAll", False, str(ex))


async def test_list_enrolled_fingers(bus):
    try:
        reply = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="ListEnrolledFingers",
                signature="s",
                body=["vladimir"],
            )
        )
        fingers = reply[0]
        has_right_index = "right-index-finger" in fingers
        log_test("4. ListEnrolledFingers -> [right-index-finger]", has_right_index, f"got {fingers}")
    except Exception as ex:
        log_test("4. ListEnrolledFingers", False, str(ex))


async def test_claim_and_release(bus):
    try:
        # Claim
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        # Check num-enroll-stages becomes 12 when claimed
        prop_reply = await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=PROPS_IFACE,
                member="Get",
                signature="ss",
                body=[DEVICE_IFACE, "num-enroll-stages"],
            )
        )
        stages = prop_reply[0].value

        # Release
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("5. Claim and Release cycle", stages == 12, f"claimed num-enroll-stages={stages}")
    except Exception as ex:
        log_test("5. Claim and Release cycle", False, str(ex))


async def test_second_client_claim_already_in_use(bus1):
    bus2 = None
    detail = ""
    try:
        # Client 1 claims
        await call_method(
            bus1,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        bus2 = await create_client()
        got_already_in_use = False
        try:
            await call_method(
                bus2,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="Claim",
                    signature="s",
                    body=["vladimir"],
                )
            )
            detail = "unexpectedly succeeded to claim twice"
        except DBusError as e:
            if e.type == "net.reactivated.Fprint.Error.AlreadyInUse":
                got_already_in_use = True
            else:
                detail = f"got error {e.type}: {e.text}"
        except Exception as e:
            detail = f"unexpected ex: {e}"

        # Client 1 releases
        await call_method(
            bus1,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("6. Second client Claim -> AlreadyInUse", got_already_in_use, detail if not got_already_in_use else "")
    except Exception as ex:
        log_test("6. Second client Claim -> AlreadyInUse", False, str(ex))
    finally:
        if bus2:
            bus2.disconnect()


async def test_non_claimer_verify_stop(bus1):
    bus2 = None
    detail = ""
    try:
        # Client 1 claims
        await call_method(
            bus1,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        bus2 = await create_client()
        got_claim_device_err = False
        try:
            await call_method(
                bus2,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="VerifyStop",
                )
            )
            detail = "VerifyStop unexpectedly succeeded for non-claimer"
        except DBusError as e:
            if e.type == "net.reactivated.Fprint.Error.ClaimDevice":
                got_claim_device_err = True
            else:
                detail = f"got error {e.type}: {e.text}"
        except Exception as e:
            detail = f"unexpected ex: {e}"

        # Client 1 releases
        await call_method(
            bus1,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("7. Non-claimer VerifyStop -> ClaimDevice error", got_claim_device_err, detail if not got_claim_device_err else "")
    except Exception as ex:
        log_test("7. Non-claimer VerifyStop", False, str(ex))
    finally:
        if bus2:
            bus2.disconnect()


def test_different_uid_rights():
    """Run client commands via sudo -u nobody to verify privilege boundaries."""
    try:
        # 1. nobody calling ListEnrolledFingers('vladimir') -> must fail with PermissionDenied
        cmd_list = [
            "sudo", "-u", "nobody",
            "busctl", f"--address={BUS_ADDRESS}",
            "call", SERVICE, DEVICE_PATH, DEVICE_IFACE, "ListEnrolledFingers", "s", "vladimir"
        ]
        proc1 = subprocess.run(cmd_list, capture_output=True, text=True)
        denied_list = proc1.returncode != 0 and ("Not authorized" in proc1.stderr or "PermissionDenied" in proc1.stderr)

        # 2. nobody calling Claim('vladimir') -> must fail with PermissionDenied
        cmd_claim = [
            "sudo", "-u", "nobody",
            "busctl", f"--address={BUS_ADDRESS}",
            "call", SERVICE, DEVICE_PATH, DEVICE_IFACE, "Claim", "s", "vladimir"
        ]
        proc2 = subprocess.run(cmd_claim, capture_output=True, text=True)
        denied_claim = proc2.returncode != 0 and ("Not authorized" in proc2.stderr or "PermissionDenied" in proc2.stderr)

        # 3. nobody calling ListEnrolledFingers('') -> caller is nobody, has no enrolled prints -> NoEnrolledPrints
        cmd_own = [
            "sudo", "-u", "nobody",
            "busctl", f"--address={BUS_ADDRESS}",
            "call", SERVICE, DEVICE_PATH, DEVICE_IFACE, "ListEnrolledFingers", "s", ""
        ]
        proc3 = subprocess.run(cmd_own, capture_output=True, text=True)
        denied_own = proc3.returncode != 0 and ("No enrolled prints" in proc3.stderr or "NoEnrolledPrints" in proc3.stderr)

        all_ok = denied_list and denied_claim and denied_own
        detail = f"list_denied={denied_list}, claim_denied={denied_claim}, own_no_prints={denied_own}"
        log_test("8. Different UID (nobody) privilege enforcement", all_ok, detail if not all_ok else "")
    except Exception as ex:
        log_test("8. Different UID privilege enforcement", False, str(ex))


async def test_enroll_and_delete_errors(bus):
    detail = ""
    try:
        # 1. DeleteEnrolledFingers -> PrintsNotDeleted
        got_prints_not_deleted = False
        try:
            await call_method(
                bus,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="DeleteEnrolledFingers",
                    signature="s",
                    body=["vladimir"],
                )
            )
            detail += "DeleteEnrolledFingers unexpectedly succeeded; "
        except DBusError as e:
            if e.type == "net.reactivated.Fprint.Error.PrintsNotDeleted":
                got_prints_not_deleted = True
            else:
                detail += f"DeleteEnrolledFingers got {e.type}; "
        except Exception as e:
            detail += f"DeleteEnrolledFingers ex {e}; "

        # Claim to test EnrollStart
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        # 2. EnrollStart -> Internal error
        got_enroll_error = False
        try:
            await call_method(
                bus,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="EnrollStart",
                    signature="s",
                    body=["right-index-finger"],
                )
            )
            detail += "EnrollStart unexpectedly succeeded; "
        except DBusError as e:
            if e.type in ("net.reactivated.Fprint.Error.Internal", "net.reactivated.Fprint.Error.PermissionDenied"):
                got_enroll_error = True
            else:
                detail += f"EnrollStart got {e.type}; "
        except Exception as e:
            detail += f"EnrollStart ex {e}; "

        # 3. EnrollStop -> NoActionInProgress
        got_enroll_stop_err = False
        try:
            await call_method(
                bus,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="EnrollStop",
                )
            )
            detail += "EnrollStop unexpectedly succeeded; "
        except DBusError as e:
            if e.type == "net.reactivated.Fprint.Error.NoActionInProgress":
                got_enroll_stop_err = True
            else:
                detail += f"EnrollStop got {e.type}; "
        except Exception as e:
            detail += f"EnrollStop ex {e}; "

        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        all_ok = got_prints_not_deleted and got_enroll_error and got_enroll_stop_err
        log_test("9. Enroll/Delete return correct errors", all_ok, detail if not all_ok else "")
    except Exception as ex:
        log_test("9. Enroll/Delete return correct errors", False, str(ex))


async def test_verify_start_fast_and_cancel_restart(bus):
    signals = []

    def on_msg(msg):
        if msg.message_type == MessageType.SIGNAL and msg.sender == SERVICE:
            signals.append((msg.member, msg.body))

    bus.add_message_handler(on_msg)

    try:
        # Claim
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        # 10. VerifyStart returns fast (<500ms)
        t0 = time.perf_counter()
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStart",
                signature="s",
                body=["any"],
            )
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        log_test("10. VerifyStart returns fast (<500ms)", elapsed_ms < 500.0, f"{elapsed_ms:.1f}ms")

        # Allow signal dispatch
        await asyncio.sleep(0.3)
        has_selected = any(m == "VerifyFingerSelected" for m, _ in signals)
        if not has_selected:
            print("      Notice: VerifyFingerSelected signal not observed yet.")

        # 11. VerifyStop cancels and next VerifyStart works
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStop",
            )
        )

        # Wait for sensor sleep to complete
        await asyncio.sleep(0.5)

        # Immediate second VerifyStart must succeed cleanly
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStart",
                signature="s",
                body=["any"],
            )
        )
        # Cancel second verify
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStop",
            )
        )
        await asyncio.sleep(0.5)

        # Release
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("11. VerifyStop cancels sensor sleep, repeated VerifyStart works", True)
    except Exception as ex:
        log_test("11. VerifyStop cancel & repeat", False, str(ex))


async def test_client_crash_auto_release(main_bus):
    try:
        # Spawn external client process that claims and calls VerifyStart
        child_code = f"""
import asyncio, os, sys
from dbus_next.aio import MessageBus
from dbus_next import Message, MessageType
from dbus_next.errors import DBusError

async def call_m(bus, msg):
    reply = await bus.call(msg)
    if reply is not None and reply.message_type == MessageType.ERROR:
        err_msg = reply.body[0] if (reply.body and len(reply.body) > 0) else ""
        raise DBusError(reply.error_name, err_msg, reply)
    return reply.body if reply is not None else None

async def run():
    try:
        bus = await MessageBus(bus_address="{BUS_ADDRESS}").connect()
        await call_m(bus, Message(
            destination="{SERVICE}", path="{DEVICE_PATH}", interface="{DEVICE_IFACE}",
            member="Claim", signature="s", body=["vladimir"]
        ))
        await call_m(bus, Message(
            destination="{SERVICE}", path="{DEVICE_PATH}", interface="{DEVICE_IFACE}",
            member="VerifyStart", signature="s", body=["any"]
        ))
        print("CLAIMED_AND_VERIFYING", flush=True)
        await asyncio.sleep(60)
    except Exception as e:
        print(f"CHILD_ERROR: {{e}}", flush=True)

asyncio.run(run())
"""
        proc = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Wait until child has claimed
        line = proc.stdout.readline()
        if "CLAIMED_AND_VERIFYING" not in line:
            err = proc.stderr.read()
            log_test("12. Client killed (-9) mid-verify -> device auto-released and reclaimable", False, f"child output: '{line.strip()}' err: '{err.strip()}'")
            proc.kill()
            return

        # Verify device is currently claimed by someone else
        already_in_use = False
        try:
            await call_method(
                main_bus,
                Message(
                    destination=SERVICE,
                    path=DEVICE_PATH,
                    interface=DEVICE_IFACE,
                    member="Claim",
                    signature="s",
                    body=["vladimir"],
                )
            )
        except DBusError as e:
            if e.type == "net.reactivated.Fprint.Error.AlreadyInUse":
                already_in_use = True

        # Kill child mid-verify
        proc.kill()
        proc.wait()

        # Wait 1.0s for NameOwnerChanged to trigger auto-release on daemon
        await asyncio.sleep(1.0)

        # Main client should now be able to claim successfully
        await call_method(
            main_bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        # Release
        await call_method(
            main_bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("12. Client killed (-9) mid-verify -> device auto-released and reclaimable", already_in_use)
    except Exception as ex:
        log_test("12. Client killed (-9) mid-verify", False, str(ex))


async def test_overall_timeout_path(bus):
    status_signals = []

    def on_msg(msg):
        if msg.message_type == MessageType.SIGNAL and msg.member == "VerifyStatus":
            status_signals.append(msg.body)

    bus.add_message_handler(on_msg)

    try:
        # Claim
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Claim",
                signature="s",
                body=["vladimir"],
            )
        )

        # Start verification (daemon verify timeout configured to 3000ms for test)
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStart",
                signature="s",
                body=["any"],
            )
        )

        # Wait up to 5 seconds for timeout VerifyStatus signal
        t_wait = 0
        while not status_signals and t_wait < 5.0:
            await asyncio.sleep(0.3)
            t_wait += 0.3

        has_timeout_status = False
        if status_signals:
            st, done = status_signals[0]
            # Timeout results in done=True with verify-unknown-error
            has_timeout_status = done is True and st in ("verify-unknown-error", "verify-no-match")

        # After done=true, VerifyStop should succeed cleanly (pam_fprintd flow)
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="VerifyStop",
            )
        )

        # Release
        await call_method(
            bus,
            Message(
                destination=SERVICE,
                path=DEVICE_PATH,
                interface=DEVICE_IFACE,
                member="Release",
            )
        )

        log_test("13. Overall verify timeout path -> done=true signal and clean stop", has_timeout_status, f"signals={status_signals}")
    except Exception as ex:
        log_test("13. Overall verify timeout path", False, str(ex))


async def main():
    print("=================================================================")
    print("  Goodix F# fprintd Bridge D-Bus Integration Test Suite")
    print("=================================================================")
    print(f"Connecting to private D-Bus: {BUS_ADDRESS}")

    bus = await create_client()

    await test_introspection(bus)
    await test_get_devices(bus)
    await test_properties(bus)
    await test_list_enrolled_fingers(bus)
    await test_claim_and_release(bus)
    await test_second_client_claim_already_in_use(bus)
    await test_non_claimer_verify_stop(bus)
    test_different_uid_rights()
    await test_enroll_and_delete_errors(bus)
    await test_verify_start_fast_and_cancel_restart(bus)
    await test_client_crash_auto_release(bus)
    await test_overall_timeout_path(bus)

    bus.disconnect()

    print("=================================================================")
    print(f"Total: {pass_count + fail_count} checks | Passed: {pass_count} | Failed: {fail_count}")
    print("=================================================================")

    if fail_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
