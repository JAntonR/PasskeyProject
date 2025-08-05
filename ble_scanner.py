import asyncio
from bleak import BleakScanner
import requests

TARGET_UUID = "b9407f30-f5f8-466e-aff9-25556b57fe6d"

async def scan_loop():
    while True:
        devices = await BleakScanner.discover()
        for d in devices:
            if TARGET_UUID.lower() in str(d.metadata.get("uuids", "")).lower():
                rssi = d.rssi
                print(f"Device seen with RSSI: {rssi}")
                if rssi > -70:
                    requests.post("http://localhost:5000/set-trigger", json={"trigger": True})
                break
        await asyncio.sleep(3)

asyncio.run(scan_loop())
