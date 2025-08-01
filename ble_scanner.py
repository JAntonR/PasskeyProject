# ble_scanner.py
import asyncio
from bleak import BleakScanner
import math
import json
from pathlib import Path

TARGET_UUID = "b9407f30-f5f8-466e-aff9-25556b57fe6d".lower()
TRIGGER_FILE = Path("trigger.json")

def estimate_distance(rssi, tx_power=-59):
    if rssi == 0:
        return float("inf")
    ratio = rssi / tx_power
    if ratio < 1.0:
        return ratio ** 10
    else:
        return 0.89976 * (ratio ** 7.7095) + 0.111

def set_trigger(value):
    with open(TRIGGER_FILE, "w") as f:
        json.dump({"trigger": value}, f)

async def scan_loop():
    while True:
        devices = await BleakScanner.discover(timeout=2.0)
        found, in_range = False, False

        for d in devices:
            for data in d.metadata.get("manufacturer_data", {}).values():
                if len(data) >= 23 and data[0:2] == b'\x02\x15':
                    uuid_bytes = data[2:18]
                    uuid = "-".join([
                        uuid_bytes[0:4].hex(),
                        uuid_bytes[4:6].hex(),
                        uuid_bytes[6:8].hex(),
                        uuid_bytes[8:10].hex(),
                        uuid_bytes[10:16].hex()
                    ])
                    if uuid.lower() == TARGET_UUID:
                        found = True
                        distance = estimate_distance(d.rssi)
                        if distance <= 3:
                            print("📲 Phone within locker (%.2f m)" % distance)
                            in_range = True
                        else:
                            print("📶 Too far (%.2f m)" % distance)

        if not found:
            print("❌ Device not found")

        set_trigger(in_range)
        await asyncio.sleep(1)

if __name__ == "__main__":
    print("🔍 Starting BLE scanner...")
    asyncio.run(scan_loop())
