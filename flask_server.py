from flask import Flask, jsonify, request
import os
import json
import asyncio
from base64 import b64encode, b64decode
from bleak import BleakScanner

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)

app = Flask(__name__)

# WebAuthn Config
rp_id = "cf9a091c54f7.ngrok-free.app"  # ← Update to your ngrok domain
origin = f"https://{rp_id}"
rp = PublicKeyCredentialRpEntity(id=rp_id, name="Phone Locker")

# BLE beacon settings
IBEACON_UUID = "b9407f30-f5f8-466e-aff9-25556b57fe6d"
RSSI_THRESHOLD = -70

# Runtime data
users = {}
challenges = {}
auth_challenges = {}
trigger = {"value": False}

USERS_FILE = "users.json"

# ---------- User Storage ----------
def save_users():
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, default=lambda x: b64encode(x).decode())

def load_users():
    global users
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            raw = json.load(f)
            for username, u in raw.items():
                users[username] = {
                    "id": b64decode(u["id"]),
                    "credentials": []
                }
                for cred in u.get("credentials", []):
                    users[username]["credentials"].append({
                        "credential_id": b64decode(cred["credential_id"]),
                        "public_key": b64decode(cred["public_key"]),
                        "sign_count": cred["sign_count"]
                    })

# ---------- Registration ----------
@app.route("/generate-options", methods=["POST"])
def generate_options():
    data = request.get_json()
    username = data["username"]
    display_name = data["displayName"]

    user_id = os.urandom(16)
    users[username] = {
        "id": user_id,
        "credentials": []
    }

    user = PublicKeyCredentialUserEntity(id=user_id, name=username, display_name=display_name)
    options = generate_registration_options(
        rp=rp,
        user=user,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    challenges[username] = options.challenge
    return jsonify(json.loads(options_to_json(options)))

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    data = request.get_json()
    username = data["username"]
    credential = data["credential"]

    if username not in users or username not in challenges:
        return jsonify({"success": False, "error": "User not found or no challenge"}), 400

    try:
        cred = RegistrationCredential.parse_obj(credential)
        verification = verify_registration_response(
            credential=cred,
            expected_challenge=challenges[username],
            expected_origin=origin,
            expected_rp_id=rp_id,
        )
        users[username]["credentials"].append({
            "credential_id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count
        })
        save_users()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# ---------- Authentication (Face ID) ----------
@app.route("/login-challenge", methods=["POST"])
def login_challenge():
    data = request.get_json()
    username = data["username"]

    if username not in users or not users[username]["credentials"]:
        return jsonify({"error": "User not registered"}), 400

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[{
            "id": cred["credential_id"],
            "transports": ["internal"],
            "type": "public-key"
        } for cred in users[username]["credentials"]],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    auth_challenges[username] = options.challenge
    return jsonify(json.loads(options_to_json(options)))

@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.get_json()
    username = data["username"]
    credential = data["credential"]

    if username not in users or username not in auth_challenges:
        return jsonify({"success": False, "error": "No login challenge"}), 400

    try:
        auth = AuthenticationCredential.parse_obj(credential)
        matching_cred = None
        for cred in users[username]["credentials"]:
            if cred["credential_id"] == auth.raw_id:
                matching_cred = cred
                break

        if not matching_cred:
            return jsonify({"success": False, "error": "Credential not found"}), 400

        verification = verify_authentication_response(
            credential=auth,
            expected_challenge=auth_challenges[username],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=matching_cred["public_key"],
            credential_current_sign_count=matching_cred["sign_count"],
        )

        # Update sign count
        matching_cred["sign_count"] = verification.new_sign_count
        save_users()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# ---------- BLE Scan ----------
@app.route("/trigger-auth")
def check_trigger():
    return jsonify({"trigger": trigger["value"]})

async def scan_ble():
    while True:
        devices = await BleakScanner.discover()
        closest_rssi = -999
        for d in devices:
            if d.metadata.get("uuids") and any(IBEACON_UUID.lower() in uuid.lower() for uuid in d.metadata["uuids"]):
                closest_rssi = max(closest_rssi, d.rssi)

        trigger["value"] = closest_rssi > RSSI_THRESHOLD
        await asyncio.sleep(1)

# ---------- Server Startup ----------
if __name__ == "__main__":
    load_users()
    loop = asyncio.get_event_loop()
    loop.create_task(scan_ble())
    app.run(port=5000)
