# flask_server.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from base64 import b64encode, b64decode
import uuid
import json
from pathlib import Path

from webauthn import (
    generate_registration_options,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# ------------------ Config ------------------
RP_ID = "localhost"  # Can update to ngrok domain if needed
RP_NAME = "Phone Locker"
ORIGIN = "https://decfb4248dbd.ngrok-free.app"  # <- Replace after ngrok is started
TRIGGER_FILE = Path("trigger.json")

users = {}
challenges = {}

# ------------------ Routes ------------------

@app.route("/")
def home():
    return send_from_directory("templates", "register.html")

@app.route("/register-challenge", methods=["POST"])
def register_challenge():
    data = request.get_json()
    username = data["username"]

    if username not in users:
        user_id = uuid.uuid4().bytes
        users[username] = {
            "id": user_id,
            "credentials": [],
        }

    registration_options = generate_registration_options(
        rp=PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME),
        user=PublicKeyCredentialUserEntity(
            id=users[username]["id"],
            name=username,
            display_name=username,
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        attestation="none"
    )

    challenges[username] = registration_options.challenge
    return jsonify(json.loads(options_to_json(registration_options)))

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    data = request.get_json()
    username = data["username"]
    credential = data["credential"]

    try:
        result = verify_registration_response(
            credential=RegistrationCredential.parse_obj(credential),
            expected_challenge=challenges[username],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )

        users[username]["credentials"].append({
            "credential_id": result.credential_id,
            "public_key": result.credential_public_key,
            "sign_count": result.sign_count,
        })

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/trigger-auth")
def trigger_auth():
    if TRIGGER_FILE.exists():
        with open(TRIGGER_FILE) as f:
            data = json.load(f)
            return jsonify({"trigger": data.get("trigger", False)})
    return jsonify({"trigger": False})

if __name__ == "__main__":
    app.run(port=5000)
