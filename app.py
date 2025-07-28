from flask import Flask, render_template, request, jsonify, session
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialParameters,
    RegistrationCredential,
    AuthenticationCredential
)
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

rp = PublicKeyCredentialRpEntity(id="localhost", name="Passkey Demo")

# Store credentials (in-memory for demo purposes)
CREDENTIALS = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/generate-registration-options", methods=["POST"])
def generate_registration():
    username = request.json["username"]
    user = PublicKeyCredentialUserEntity(
        id=username.encode(),
        name=username,
        display_name=username
    )
    options = generate_registration_options(
        rp=rp,
        user=user,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification="required"),
        pub_key_cred_params=[PublicKeyCredentialParameters(alg=-7, type="public-key")],
    )
    session["current_challenge"] = options.challenge
    session["username"] = username
    return jsonify(options.model_dump())

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    credential = RegistrationCredential.parse_obj(request.json)
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=session["current_challenge"],
        expected_rp_id="localhost",
        expected_origin="http://localhost:5000",
        require_user_verification=True
    )
    CREDENTIALS[session["username"]] = {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count
    }
    return jsonify({"status": "ok"})

@app.route("/generate-authentication-options", methods=["POST"])
def generate_authentication():
    username = request.json["username"]
    user_cred = CREDENTIALS.get(username)
    if not user_cred:
        return jsonify({"error": "No credentials"}), 404
    options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[{"id": user_cred["credential_id"], "type": "public-key"}],
        user_verification="required"
    )
    session["current_challenge"] = options.challenge
    session["username"] = username
    return jsonify(options.model_dump())

@app.route("/verify-authentication", methods=["POST"])
def verify_authentication():
    credential = AuthenticationCredential.parse_obj(request.json)
    user_cred = CREDENTIALS[session["username"]]
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=session["current_challenge"],
        expected_rp_id="localhost",
        expected_origin="http://localhost:5000",
        credential_public_key=user_cred["public_key"],
        credential_current_sign_count=user_cred["sign_count"],
        require_user_verification=True,
    )
    user_cred["sign_count"] = verification.new_sign_count
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)