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
# === BLE Scan Model ===
# This model stores information about BLE devices scanned.
# It includes fields for device name, address, RSSI, and timestamp.
# It is used to log BLE scans and trigger authentication based on device proximity.
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(80))
    address = db.Column(db.String(120))
    rssi = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# === User Credential Model ===
# This model stores user credentials for FIDO2/WebAuthn
# It includes fields for username, credential ID, public key, and sign count.
# It is used to manage user registrations and authentications.
class UserCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    credential_id = db.Column(db.String(512), nullable=False)
    public_key = db.Column(db.String(2048), nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# === Helper Function ===
# This function cleans metadata by converting bytes to hex strings
# and recursively cleaning nested dictionaries.
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
# This function scans for BLE devices and checks if the target device is nearby.
# If the target device is found with sufficient signal strength, it triggers authentication.
async def scan_ble_devices():
    global trigger_auth
    devices = []

    async with BleakScanner() as scanner:
        await asyncio.sleep(5.0)
        for d, advertisement_data in scanner.discovered_devices:
            if d.name != TARGET_DEVICE_NAME:
                continue  # Skip devices that are not the target

            info = {
                "name": d.name,
                "address": d.address,
                "rssi": advertisement_data.rssi,
                "metadata": clean_metadata(d.metadata)
    }   
    devices.append(info)

    # Save to database only if name matches
    scan_entry = BLEScan(
        device_name=d.name,
        address=d.address,
        rssi=advertisement_data.rssi
    )
    db.session.add(scan_entry)

    # Check trigger condition
    if advertisement_data.rssi > -75:
        trigger_auth = True

# === Routes ===
# This route serves the main index page.
@app.route('/')
def index():
    return render_template("index.html")

# This route scans for BLE devices and checks if the target device is present.
# It returns a JSON response indicating whether the target device is found.
@app.route('/scan')
def scan():
    try:
        devices = asyncio.run(scan_ble_devices())
        return jsonify(devices = 'BBNo$' in [d['name'] for d in devices])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === Authentication Endpoints ===
# These endpoints handle FIDO2/WebAuthn authentication challenges and verifications.
# These are simplified for demonstration purposes and should be replaced with real FIDO2 logic.
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

# This endpoint verifies the assertion from the client.
# It should contain real validation logic using FIDO2 libraries.
@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    print("Received credential ID:", data.get("id"))
    # Add real validation with fido2 here if needed
    return jsonify({"status": "ok"})

# This endpoint triggers the Face ID authentication status.
# It checks a global flag and resets it after triggering.
@app.route("/trigger-auth")
def trigger_auth_status():
    global trigger_auth
    if trigger_auth:
        trigger_auth = False  # reset after triggering
        return jsonify({"trigger": True})
    return jsonify({"trigger": True}) # Forced to True for testing

# === Registration Endpoints ===
# These endpoints handle user registration for FIDO2/WebAuthn.
# They should be replaced with real FIDO2 registration logic.
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

# This endpoint registers the credential sent from the client.
# It should contain real validation and storage logic using FIDO2 libraries.
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
# This function initializes the database and runs the Flask app.
# It should be called when the script is executed directly.
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
