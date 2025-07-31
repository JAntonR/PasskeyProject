from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import asyncio
from bleak import BleakScanner

app = Flask(__name__)
CORS(app)

IBEACON_UUID = "b9407f30-f5f8-466e-aff9-25556b57fe6d"  # UUID of iPhone beacon
auth_triggered = False  # Global flag to indicate proximity


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
            md = d.metadata.get("manufacturer_data", {})
            for _, raw in md.items():
                if len(raw) >= 23 and raw[0] == 0x02 and raw[1] == 0x15:
                    uuid_bytes = raw[2:18]
                    uuid_str = (
                        f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
                        f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
                        f"{uuid_bytes[10:16].hex()}"
                    )
                    if uuid_str.lower() == IBEACON_UUID.lower():
                        devices.append({
                            "type": "iBeacon",
                            "uuid": uuid_str,
                            "rssi": d.rssi,
                            "address": d.address
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
        target = next((d for d in devices if d["uuid"].lower() == IBEACON_UUID.lower()), None)
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
    return jsonify({
        "publicKey": {
            "challenge": "QUJDREVGR0g=",  # base64 of "ABCDEFGH"
            "rpId": "29755a3ecaee.ngrok-free.app",  # Update with your domain
            "timeout": 60000,
            "allowCredentials": [{
                "type": "public-key",
                "id": "QUJDREVGR0g="  # Match your credential ID
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
