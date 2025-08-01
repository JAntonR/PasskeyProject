from flask import Flask, request, jsonify
from flask_cors import CORS
from base64 import b64encode, b64decode
import os
import json
import uuid

from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)
from webauthn import (
    generate_registration_options,
    verify_registration_response,
)

app = Flask(__name__)
CORS(app)

rp_id = "localhost:5000"  # You can use your ngrok domain here if needed
rp_name = "Pizza Locker"
origin = "https://cf9a091c54f7.ngrok-free.app"  # <- Replace with your actual ngrok URL

# In-memory "database"
users = {}  # username -> { id, credentials }
challenges = {}  # username -> challenge

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
    else:
        user_id = users[username]["id"]

    registration_options = generate_registration_options(
        rp=PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
        user=PublicKeyCredentialUserEntity(
            id=user_id,
            name=username,
            display_name=username,
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        attestation="none"
    )

    challenges[username] = registration_options.challenge

    # Return JSON-serializable dict
    return jsonify(json.loads(options_to_json(registration_options)))

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    data = request.get_json()
    username = data["username"]
    credential = data["credential"]

    if username not in users or username not in challenges:
        return jsonify({"success": False, "error": "Unknown user or challenge expired"}), 400

    try:
        verified_registration = verify_registration_response(
            credential=RegistrationCredential.parse_obj(credential),
            expected_challenge=challenges[username],
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )

        # Store the credential for later login (not implemented yet)
        users[username]["credentials"].append({
            "credential_id": verified_registration.credential_id,
            "public_key": verified_registration.credential_public_key,
            "sign_count": verified_registration.sign_count,
        })

        return jsonify({"success": True})
    except Exception as e:
        print("Registration failed:", str(e))
        return jsonify({"success": False, "error": str(e)}), 400

if __name__ == "__main__":
    app.run(port=5000)
