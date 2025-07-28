from flask import Flask, render_template, request, jsonify, session
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
from fido2 import cbor
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

USERS = {}
CREDENTIALS = {}

rp_id = "localhost"
rp_name = "My Passkey App"
server = Fido2Server({"id": rp_id, "name": rp_name})

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate-registration-options", methods=["POST"])
def generate_registration_options():
    username = request.json["username"]
    user_id = os.urandom(16)
    user = {
        "id": user_id,
        "name": username,
        "displayName": username,
    }

    USERS[username] = user
    registration_data, state = server.register_begin(
        user,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session["state"] = state
    return cbor.encode(registration_data)

@app.route("/verify-registration", methods=["POST"])
def verify_registration():
    data = cbor.decode(request.get_data())
    state = session.pop("state")
    auth_data = server.register_complete(state, data["clientDataJSON"], data["attestationObject"])

    username = next((name for name, u in USERS.items() if u["id"] == auth_data.credential_id), None)
    CREDENTIALS[username] = auth_data.credential_data

    return cbor.encode({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)
