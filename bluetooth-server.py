from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import asyncio
from bleak import BleakScanner
import os
import base64
import hashlib
import secrets

app = Flask(__name__)
CORS(app)

# === Configuration ===
TARGET_DEVICE_NAME = "BBNo$"
trigger_auth = False  # Global flag for triggering Face ID

# === Database Setup ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://lockeruser:securepassword@localhost:5432/smartlocker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class BLEScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(80))
    address = db.Column(db.String(120))
    rssi = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class UserCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    credential_id = db.Column(db.String(512), nullable=False)
    public_key = db.Column(db.String(2048), nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# === Helper Function ===
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

# === BLE Scan Function ===
async def scan_ble_devices():
    global trigger_auth
    devices = []

    async with BleakScanner() as scanner:
        await asyncio.sleep(5.0)
        for d, advertisement_data in scanner.discovered_devices:
            info = {
                "name": d.name,
                "address": d.address,
                "rssi": advertisement_data.rssi,
                "metadata": clean_metadata(d.metadata)
            }
            devices.append(info)

            # Save to database
            scan_entry = BLEScan(
                device_name=d.name,
                address=d.address,
                rssi=advertisement_data.rssi
            )
            db.session.add(scan_entry)

            # Check trigger condition
            if d.name == TARGET_DEVICE_NAME and advertisement_data.rssi > -75:
                trigger_auth = True

        db.session.commit()

    return devices

# === Routes ===

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

@app.route("/login-challenge")
def login_challenge():
    return jsonify({
        "publicKey": {
            "challenge": "c0ffee" * 8,
            "rpId": "9bae77f0c811.ngrok-free.app",
            "timeout": 60000,
            "allowCredentials": [{
                "type": "public-key",
                "id": "QUJDREVGR0g="  # base64 for fake id: "ABCDEFGH"
            }],
            "userVerification": "preferred"
        }
    })

@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    print("Received credential ID:", data.get("id"))
    # Add real validation with fido2 here if needed
    return jsonify({"status": "ok"})

@app.route("/trigger-auth")
def trigger_auth_status():
    global trigger_auth
    if trigger_auth:
        trigger_auth = False  # reset after triggering
        return jsonify({"trigger": True})
    return jsonify({"trigger": True})

@app.route("/register-challenge")
def register_challenge():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Username required"}), 400

    user_id = base64.b64encode(os.urandom(16)).decode("utf-8")
    challenge = base64.b64encode(os.urandom(32)).decode("utf-8")

    return jsonify({
        "challenge": challenge,
        "rp": { "name": "Smart Locker", "id": "localhost" },
        "user": {
            "id": user_id,
            "name": username,
            "displayName": username
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "timeout": 60000,
        "attestation": "none",
        "authenticatorSelection": {
            "userVerification": "required",
            "authenticatorAttachment": "platform"
        }
    })

@app.route("/register-credential", methods=["POST"])
def register_credential():
    data = request.get_json()
    username = data.get("username")
    credential_id = data.get("id")
    public_key = data.get("response", {}).get("attestationObject")  # Simplified placeholder

    if not username or not credential_id or not public_key:
        return jsonify({"error": "Missing required fields"}), 400

    # Store in DB
    user_cred = UserCredential(
        username=username,
        credential_id=credential_id,
        public_key=public_key
    )
    db.session.add(user_cred)
    db.session.commit()

    return jsonify({"status": "registered"})

# === Run App ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
