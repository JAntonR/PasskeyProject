from flask import Flask, jsonify, request
from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity, UserVerificationRequirement, AuthenticatorSelectionCriteria
)
import base64, os

app = Flask(__name__)
users = {}  # {username: {id, credentials: []}}
auth_triggered = False

rp = PublicKeyCredentialRpEntity(id="your-domain.com", name="Locker Pickup")

@app.route("/trigger-auth", methods=["GET"])
def trigger_auth():
    return jsonify({"trigger": auth_triggered})

@app.route("/login-challenge", methods=["POST"])
def login_challenge():
    username = request.json["username"]
    user = users[username]
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
    user = users[username]
    cred = verify_authentication_response(
        credential=data["credential"],
        expected_challenge=user["auth_challenge"],
        expected_rp_id=rp.id,
        expected_origin="https://your.github.pages.site",
        credential_public_key=user["credentials"][0]["public_key"],
        credential_current_sign_count=0,
        require_user_verification=True
    )
    global auth_triggered
    auth_triggered = False
    return jsonify({"status": "OK", "unlock": True})

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
        expected_origin="https://your.github.pages.site",
        expected_rp_id=rp.id
    )
    users[username]["credentials"].append({
        "id": cred.credential_id,
        "public_key": cred.credential_public_key
    })
    return jsonify({"status": "registered"})

@app.route("/set-trigger", methods=["POST"])
def set_trigger():
    global auth_triggered
    auth_triggered = request.json.get("trigger", False)
    return jsonify({"ok": True})
