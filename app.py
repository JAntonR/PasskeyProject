from flask import Flask, render_template, request, jsonify, session
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialRpEntity,
    AuthenticatorTransport,
    UserVerificationRequirement,
    AttestationConveyancePreference,
)

import os
import base64
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(32)

# In-memory user store
users = {}
credentials = {}

rp = PublicKeyCredentialRpEntity(id="localhost", name="Demo WebAuthn RP")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/generate-registration-options", methods=["POST"])
def registration_options():
    username = request.json.get("username")
    user_id = secrets.token_bytes(16)

    options = generate_registration_options(
        rp=rp,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
    )

    session["current_challenge"] = options.challenge
    session["user_id"] = user_id
    users[username] = user_id

    return jsonify(options.model_dump())

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    credential = RegistrationCredential.parse_obj(request.json)
    expected_challenge = session.get("current_challenge")
    user_id = session.get("user_id")

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="https://localhost:5000",
        require_user_verification=True,
    )

    credentials[user_id] = {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    }

    return jsonify({"status": "ok"})

@app.route("/generate-authentication-options", methods=["POST"])
def authn_options():
    username = request.json.get("username")
    user_id = users.get(username)
    cred = credentials.get(user_id)

    options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[{
            "id": cred["credential_id"],
            "transports": [AuthenticatorTransport.INTERNAL],
        }],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session["authn_challenge"] = options.challenge
    session["user_id"] = user_id
    return jsonify(options.model_dump())

@app.route("/verify-authentication", methods=["POST"])
def verify_authn():
    credential = AuthenticationCredential.parse_obj(request.json)
    expected_challenge = session.get("authn_challenge")
    user_id = session.get("user_id")
    cred = credentials.get(user_id)

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="https://localhost:5000",
        credential_public_key=cred["public_key"],
        credential_current_sign_count=cred["sign_count"],
        require_user_verification=True,
    )

    cred["sign_count"] = verification.new_sign_count
    return jsonify({"status": "ok"})
