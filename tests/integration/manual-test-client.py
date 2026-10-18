#!/usr/bin/env python3
"""
Interactive manual finger test client for Goodix F# fprintd D-Bus Bridge.
Run by the USER on vostro-laptop.
Tests:
  Scenario 1: Correct finger -> verify-match
  Scenario 2: Wrong finger -> retry-scan -> verify-no-match
  Scenario 3: Start -> VerifyStop -> Start again
"""

import asyncio
import os
import sys
import time
from dbus_next.aio import MessageBus
from dbus_next.errors import DBusError
from dbus_next import Message, MessageType

BUS_ADDRESS = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
if not BUS_ADDRESS:
    print("[-] Error: DBUS_SYSTEM_BUS_ADDRESS must be set.")
    sys.exit(1)

SERVICE = "net.reactivated.Fprint"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_IFACE = "net.reactivated.Fprint.Device"

async def call_method(bus, msg):
    reply = await bus.call(msg)
    if reply is not None and reply.message_type == MessageType.ERROR:
        err_msg = reply.body[0] if (reply.body and len(reply.body) > 0) else ""
        raise DBusError(reply.error_name, err_msg, reply)
    return reply.body if reply is not None else None

async def run_scenario_1(bus):
    print("\n-------------------------------------------------------------")
    print("  SCENARIO 1: Correct Finger Authentication (verify-match)")
    print("-------------------------------------------------------------")
    print("Instructions: When prompted, place your ENROLLED finger (right index)")
    print("firmly on the fingerprint sensor until matched.\n")

    input("Press [Enter] to start Scenario 1...")

    status_events = []
    def on_msg(msg):
        if msg.message_type == MessageType.SIGNAL and msg.sender == SERVICE:
            if msg.member == "VerifyFingerSelected":
                print(f"  --> [SIGNAL] VerifyFingerSelected: {msg.body[0]}")
            elif msg.member == "VerifyFingerMatched":
                print(f"  --> [SIGNAL] VerifyFingerMatched: {msg.body[0]}")
            elif msg.member == "VerifyStatus":
                st, done = msg.body
                print(f"  --> [SIGNAL] VerifyStatus: result='{st}', done={done}")
                status_events.append((st, done))

    bus.add_message_handler(on_msg)

    print("[*] Claiming device for current user...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Claim", signature="s", body=[""]
    ))

    print("[*] Starting verification ('any')... PLACE ENROLLED FINGER ON SENSOR NOW!")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStart", signature="s", body=["any"]
    ))

    # Wait for completion (done=True) or up to 30s
    t_start = time.time()
    while time.time() - t_start < 30.0:
        if any(done for _, done in status_events):
            break
        await asyncio.sleep(0.2)

    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStop"
    ))
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Release"
    ))

    matched = any(st == "verify-match" and done for st, done in status_events)
    if matched:
        print("\n[+] SCENARIO 1 PASSED: Finger verified successfully (verify-match)!")
        return True
    else:
        print("\n[-] SCENARIO 1 FAILED: Expected verify-match, got:", status_events)
        return False


async def run_scenario_2(bus):
    print("\n-------------------------------------------------------------")
    print("  SCENARIO 2: Wrong Finger Rejection (retry-scan -> verify-no-match)")
    print("-------------------------------------------------------------")
    print("Instructions: When prompted, place an UNENROLLED finger (e.g. left thumb)")
    print("on the sensor. Touch, lift, and re-touch when prompted up to 3 times.\n")

    input("Press [Enter] to start Scenario 2...")

    status_events = []
    def on_msg(msg):
        if msg.message_type == MessageType.SIGNAL and msg.sender == SERVICE:
            if msg.member == "VerifyStatus":
                st, done = msg.body
                print(f"  --> [SIGNAL] VerifyStatus: result='{st}', done={done}")
                status_events.append((st, done))

    bus.add_message_handler(on_msg)

    print("[*] Claiming device for current user...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Claim", signature="s", body=[""]
    ))

    print("[*] Starting verification ('any')... PLACE WRONG FINGER ON SENSOR NOW!")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStart", signature="s", body=["any"]
    ))

    t_start = time.time()
    while time.time() - t_start < 40.0:
        if any(done for _, done in status_events):
            break
        await asyncio.sleep(0.2)

    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStop"
    ))
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Release"
    ))

    no_match = any(st == "verify-no-match" and done for st, done in status_events)
    retry_seen = any(st == "verify-retry-scan" for st, _ in status_events)

    if no_match:
        print(f"\n[+] SCENARIO 2 PASSED: Wrong finger rejected with verify-no-match! (retry observed: {retry_seen})")
        return True
    else:
        print("\n[-] SCENARIO 2 FAILED: Expected verify-no-match, got:", status_events)
        return False


async def run_scenario_3(bus, auto_mode=False):
    print("\n-------------------------------------------------------------")
    print("  SCENARIO 3: Start -> VerifyStop (Cancel) -> Restart Verification")
    print("-------------------------------------------------------------")
    print("Instructions: Do NOT touch the sensor. The script will start verification,")
    print("cancel it midway with VerifyStop, then start verification again.\n")

    if not auto_mode:
        input("Press [Enter] to start Scenario 3...")

    print("[*] Claiming device...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Claim", signature="s", body=[""]
    ))

    print("[*] Step 1: Starting verification ('any')...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStart", signature="s", body=["any"]
    ))
    print("    Verification started. Sensor is listening...")

    print("[*] Waiting 1.0s before cancellation...")
    await asyncio.sleep(1.0)

    print("[*] Step 2: Sending VerifyStop()...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStop"
    ))
    print("    VerifyStop succeeded. Sensor put to sleep.")

    print("[*] Waiting 0.5s before restarting...")
    await asyncio.sleep(0.5)

    print("[*] Step 3: Starting verification AGAIN ('any')...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStart", signature="s", body=["any"]
    ))
    print("    Second VerifyStart succeeded cleanly!")

    print("[*] Waiting 1.0s before second cancellation...")
    await asyncio.sleep(1.0)

    print("[*] Step 4: Cancelling second verification...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="VerifyStop"
    ))
    print("    Second VerifyStop succeeded.")

    print("[*] Releasing device...")
    await call_method(bus,Message(
        destination=SERVICE, path=DEVICE_PATH, interface=DEVICE_IFACE,
        member="Release"
    ))

    print("\n[+] SCENARIO 3 PASSED: Cancellation and repeated verify cycle succeeded cleanly!")
    return True


async def main():
    check_only = "--check-only" in sys.argv

    print("=================================================================")
    print("  Goodix F# fprintd Bridge: Real-Sensor Interactive Test")
    print("=================================================================")

    bus = await MessageBus(bus_address=BUS_ADDRESS).connect()
    await bus.call(Message(
        destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
        interface="org.freedesktop.DBus", member="AddMatch",
        signature="s", body=[f"type='signal',sender='{SERVICE}'"]
    ))

    if check_only:
        print("[*] Running automated check-only mode (Scenario 3 non-touch)...")
        ok = await run_scenario_3(bus, auto_mode=True)
        bus.disconnect()
        sys.exit(0 if ok else 1)

    # Interactive mode for the USER
    res1 = await run_scenario_1(bus)
    res2 = await run_scenario_2(bus)
    res3 = await run_scenario_3(bus, auto_mode=False)

    bus.disconnect()

    print("\n=================================================================")
    print("  MANUAL TEST SUMMARY:")
    print(f"    Scenario 1 (Enrolled Match):    {'PASS' if res1 else 'FAIL'}")
    print(f"    Scenario 2 (Wrong Finger):      {'PASS' if res2 else 'FAIL'}")
    print(f"    Scenario 3 (Cancel & Restart):  {'PASS' if res3 else 'FAIL'}")
    print("=================================================================")

    if res1 and res2 and res3:
        print("[+] All real-finger scenarios PASSED successfully!")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
