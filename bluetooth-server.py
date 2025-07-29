import asyncio
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

async def scan_ble_devices():
    # We'll scan multiple times and aggregate results to get RSSI values better
    all_devices = {}
    for _ in range(3):  # Scan 3 times
        devices = await BleakScanner.discover(timeout=2.0)
        for device in devices:
            rssi = getattr(device, "rssi", None)
            if rssi is None and hasattr(device, "metadata"):
                rssi = device.metadata.get("rssi", None)

            # Update or add device info with latest RSSI
            all_devices[device.address] = {
                "name": device.name or "Unknown",
                "address": device.address,
                "rssi": rssi
            }
    # Return list of devices detected
    return list(all_devices.values())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    devices_list = asyncio.run(scan_ble_devices())
    return jsonify(devices_list)

if __name__ == '__main__':
    app.run(debug=True)
