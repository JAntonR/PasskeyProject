from flask import Flask, request, jsonify, send_from_directory
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
from fido2.utils import websafe_encode, websafe_decode
from fido2 import cbor
import os

app = Flask(__name__, static_url_path="/static")

# Relying party (this server)
rp = PublicKeyCredentialRpEntity("localhost", "Passkey Demo")
server = Fido2Server(rp)

# In-memory database
user_db = {}             # username -> {id, credentials}
challenge_state = {}     # username -> registration state

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/static/<path:path>")
def send_static(path):
    return send_from_directory("static", path)

@app.route("/register/begin", methods=["POST"])
def register_begin():
    try:
        data = request.get_json()
        username = data["username"]
        display_name = data["displayName"]

        user_id = os.urandom(16)
        user = {
            "id": user_id,
            "name": username,
            "displayName": display_name,
        }

        registration_data, state = server.register_begin(
            user,
            user_verification=UserVerificationRequirement.PREFERRED
        )

        # Store challenge state
        challenge_state[username] = state
        user_db[username] = {"id": user_id, "credentials": []}

        # Encode all bytes to base64url so it's JSON-safe
        def b64(obj):
            if isinstance(obj, bytes):
                return websafe_encode(obj).decode()
            elif isinstance(obj, list):
                return [b64(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: b64(v) for k, v in obj.items()}
            else:
                return obj

        return jsonify({"publicKey": b64(registration_data)})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route("/register/complete", methods=["POST"])
def register_complete():
    data = request.get_json()
    username = data.get("username")
    if not username or username not in challenge_state:
        return jsonify({"status": "error", "error": "Invalid user or session"}), 400

    state = challenge_state.pop(username)

    attestation_response = {
        "clientDataJSON": websafe_decode(data["response"]["clientDataJSON"]),
        "attestationObject": websafe_decode(data["response"]["attestationObject"]),
    }

    auth_data = server.register_complete(state, attestation_response)
    user_db[username]["credentials"].append(auth_data.credential_data)

    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(ssl_context="adhoc", debug=True)
