from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import asyncio
from bleak import BleakScanner
import base64

app = Flask(__name__)
CORS(app)

TARGET_DEVICE_NAME = "BBNo$"
auth_triggered = False  # global flag for iPhone to poll

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
        await asyncio.sleep(5.0)
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
    global auth_triggered
    try:
        devices = asyncio.run(scan_ble_devices())
        target = next((d for d in devices if d["name"] == TARGET_DEVICE_NAME), None)
        if target and target["rssi"] and target["rssi"] > -65:
            auth_triggered = True
        else:
            auth_triggered = False
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/trigger-auth')
def trigger_auth():
    return jsonify({"trigger": auth_triggered})

@app.route("/login-challenge")
def login_challenge():
    # base64url (no padding) for "ABCDEF1234567890"
    challenge_b64url = "QUJDREVGMTIzNDU2Nzg5MA"
    credential_id_b64url = "Y3JlZF9pZF9leGFtcGxl"  # "cred_id_example"

    return jsonify({
        "publicKey": {
            "challenge": challenge_b64url,
            "rpId": "29755a3ecaee.ngrok-free.app",
            "timeout": 60000,
            "allowCredentials": [{
                "type": "public-key",
                "id": credential_id_b64url,
                "transports": ["internal"]
            }],
            "userVerification": "preferred"
        }
    })

@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    print("Received credential ID:", data.get("id"))
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True)
