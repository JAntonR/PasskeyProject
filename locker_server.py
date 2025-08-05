from flask import Flask, jsonify, request
from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity, UserVerificationRequirement, AuthenticatorSelectionCriteria
)
from bleak import BleakScanner
import asyncio
import threading
import os

app = Flask(__name__)
users = {}  # {username: {id, credentials: []}}
auth_triggered = False

# ✅ Use your ngrok or GitHub Pages domain here
RP_ID = "d7aa38fba230.ngrok-free.app"
ORIGIN = "https://d7aa38fba230.ngrok-free.app"

# ✅ BLE UUID of the iPhone beacon
TARGET_UUID = "b9407f30-f5f8-466e-aff9-25556b57fe6d"
RSSI_THRESHOLD = -65  # You can tune this value for 3 meters

rp = PublicKeyCredentialRpEntity(id=RP_ID, name="Locker Pickup")


@app.route("/")
def index():
    return "Locker BLE server is running!"


@app.route("/trigger-auth", methods=["GET"])
def trigger_auth():
    return jsonify({"trigger": auth_triggered})


@app.route("/set-trigger", methods=["POST"])
def set_trigger():
    global auth_triggered
    auth_triggered = request.json.get("trigger", True)
    return jsonify({"ok": True})


@app.route("/register-options", methods=["POST"])
def register_options():
    username = request.json["username"]
    user_id = os.urandom(16)
    options = generate_registration_options(
        rp=rp,
        user={"id": user_id, "name": username, "display_name": username},
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )
    users[username] = {"id": user_id, "credentials": [], "reg_challenge": options.challenge}
    return jsonify(options.model_dump())


@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    data = request.json
    username = data["username"]
    cred = verify_registration_response(
        credential=data["credential"],
        expected_challenge=users[username]["reg_challenge"],
        expected_origin=ORIGIN,
        expected_rp_id=rp.id
    )
    users[username]["credentials"].append({
        "id": cred.credential_id,
        "public_key": cred.credential_public_key
    })
    return jsonify({"status": "registered"})


@app.route("/login-challenge", methods=["POST"])
def login_challenge():
    username = request.json["username"]
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    options = generate_authentication_options(
        rp_id=rp.id,
        allow_credentials=[cred["id"] for cred in user["credentials"]],
        user_verification=UserVerificationRequirement.REQUIRED
    )
    user["auth_challenge"] = options.challenge
    return jsonify(options.model_dump())


@app.route("/verify-assertion", methods=["POST"])
def verify_assertion():
    data = request.json
    username = data["username"]
    user = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    cred = verify_authentication_response(
        credential=data["credential"],
        expected_challenge=user["auth_challenge"],
        expected_rp_id=rp.id,
        expected_origin=ORIGIN,
        credential_public_key=user["credentials"][0]["public_key"],
        credential_current_sign_count=0,
        require_user_verification=True
    )
    global auth_triggered
    auth_triggered = False
    return jsonify({"status": "OK", "unlock": True})


async def scan_ble():
    global auth_triggered
    while True:
        devices = await BleakScanner.discover()
        found = False
        for d in devices:
            if d.metadata.get("uuids") and TARGET_UUID.lower() in [u.lower() for u in d.metadata["uuids"]]:
                print(f"🔍 Found target UUID with RSSI {d.rssi} from {d.address}")
                if d.rssi > RSSI_THRESHOLD:
                    print("✅ Phone is nearby. Triggering auth.")
                    auth_triggered = True
                else:
                    print("📶 Signal too weak.")
                found = True
                break
        if not found:
            print("❌ Phone not found.")
        await asyncio.sleep(3)


def start_ble_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(scan_ble())


if __name__ == "__main__":
    print("🚀 Starting Locker BLE server at http://127.0.0.1:5000")
    threading.Thread(target=start_ble_loop, daemon=True).start()
    app.run(debug=True)
