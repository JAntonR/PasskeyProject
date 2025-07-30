from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import asyncio
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

TARGET_DEVICE_NAME = "BBNo$"


# Cleans the metadata from the BLE from the binary data or bytes 
# Doing this recursively to handle nested dictionaries
# Makes it JSON serializable
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


# Runs the BLE scan asynchronously for about 5 seconds (longer means more devices and more accuracy)
# Returns a list of discovered devices with their name, address, RSSI, and cleaned metadata
# Calls the clean_metadata function to ensure the metadata is JSON serializable
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

# Initializes the html template rendering and CORS for the Flask app
@app.route('/')
def index():
    return render_template("index.html")

# Calls the asyncio function scan_ble_devices to get the list of BLE devices
# Returns the list as a JSON response
# Error here is reveled by the try-except block and followed with a 500 status code
@app.route('/scan')
def scan():
    try:
        devices = asyncio.run(scan_ble_devices())
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# I have little experience with FIDO2 and WebAuthn, so this is a mock implementation
# It simulates a login challenge and verification process
# Essentially this is the real prototype for the WebAuthn login flow
# In a real application, you would use a library like fido2 to handle the challenge
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

# This endpoint simulates the verification of a WebAuthn assertion
# In a real application, you would validate the assertion using a library like fido2
@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    print("Received credential ID:", data.get("id"))
    # NOTE: Replace this with actual validation using fido2 or similar
    return jsonify({"status": "ok"})


# This is the main entry point for the Flask application
# It runs the Flask app in debug mode for development purposes
if __name__ == '__main__':
    app.run(debug=True)
