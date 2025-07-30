from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import asyncio
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

TARGET_DEVICE_NAME = "BBNo$"

# This function cleans the metadata dictionary by converting bytes to hex strings
# and recursively cleaning nested dictionaries.
# It ensures that the metadata is JSON serializable.
# This is necessary because Flask's jsonify function cannot handle bytes directly.
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

# This function scans for Bluetooth Low Energy (BLE) devices
# and returns a list of devices with their name, address, RSSI, and cleaned metadata
# It uses the BleakScanner from the bleak library to perform the scan.
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

# Flask routes for the web application
@app.route('/')
def index():
    return render_template("index.html")

# This route handles the BLE scan request.
# It runs the scan_ble_devices function asynchronously and returns the list of devices as JSON.
@app.route('/scan')
def scan():
    try:
        devices = asyncio.run(scan_ble_devices())
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# This route serves the login challenge for WebAuthn.
# It returns a JSON object with the challenge, relying party ID, timeout, allowed credentials,
# and user verification preference.
# The challenge is a base64-encoded string that should be replaced with a real challenge in
@app.route("/login-challenge")
def login_challenge():
    return jsonify({
        "publicKey": {
            "challenge": "c0ffee" * 8,
            "rpId": "localhost",
            "timeout": 60000,
            "allowCredentials": [{
                "type": "public-key",
                "id": "QUJDREVGR0g="  # base64 for fake id: "ABCDEFGH"
            }],
            "userVerification": "preferred"
        }
    })

# This route handles the verification of the WebAuthn assertion.
# It expects a JSON payload with the credential ID and other necessary data.
# In a real application, this should validate the assertion using a library like fido2.
@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    print("Received credential ID:", data.get("id"))
    # NOTE: Replace this with actual validation using fido2 or similar
    return jsonify({"status": "ok"})

# Main entry point for the Flask application
# It runs the Flask app in debug mode.
if __name__ == '__main__':
    app.run(debug=True)
