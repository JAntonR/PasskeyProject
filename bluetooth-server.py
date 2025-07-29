from flask import Flask, jsonify, render_template
from flask_cors import CORS
import asyncio
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

def clean_metadata(metadata):
    clean = {}
    for key, value in metadata.items():
        if isinstance(value, bytes):
            clean[key] = value.hex()
        elif isinstance(value, dict):
            clean[key] = clean_metadata(value)
        else:
            clean[key] = value
    return clean

async def scan_ble_devices():
    devices = []
    async with BleakScanner() as scanner:
        await asyncio.sleep(5.0)  # scan for 5 seconds
        for d in scanner.discovered_devices:
            devices.append({
                "name": d.name,
                "address": d.address,
                "rssi": d.rssi,
                "metadata": clean_metadata(d.metadata)
            })
    return devices

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan')
def scan():
    try:
        devices = asyncio.run(scan_ble_devices())
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
