import asyncio
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

async def scan_ble_devices():
    devices = await BleakScanner.discover(timeout=5.0)
    result = []
    for device in devices:
        # Extract RSSI
        rssi = getattr(device, "rssi", None)
        if rssi is None and hasattr(device, "metadata"):
            rssi = device.metadata.get("rssi", None)

        result.append({
            "name": device.name or "Unknown",
            "address": device.address,
            "rssi": rssi
        })
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    devices = asyncio.run(scan_ble_devices())
    return jsonify(devices)

if __name__ == '__main__':
    app.run(debug=True)
