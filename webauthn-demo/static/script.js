// Helper: Convert base64url string to Uint8Array
function base64urlToUint8Array(base64urlString) {
  const padding = '='.repeat((4 - (base64urlString.length % 4)) % 4);
  const base64 = (base64urlString + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
}

// Helper: Convert ArrayBuffer to base64url string
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.getElementById("registerBtn").onclick = async () => {
  try {
    const username = document.getElementById("username").value;
    const displayName = document.getElementById("displayName").value;

    if (!username || !displayName) {
      alert("Please enter username and display name");
      return;
    }

    // Step 1: Start registration - get challenge from server
    const resp = await fetch("/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, displayName }),
    });

    const response = await resp.json();
    console.log("Step 1 response:", response);

    if (!response.publicKey) {
      throw new Error("Server error: " + (response.message || "No publicKey in response"));
    }

    const publicKey = response.publicKey;

    // Decode challenge and user.id from base64url to Uint8Array
    publicKey.challenge = base64urlToUint8Array(publicKey.challenge);
    publicKey.user.id = base64urlToUint8Array(publicKey.user.id);

    // Also decode any other fields that must be Uint8Array (e.g. excludeCredentials id)
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((cred) => {
        cred.id = base64urlToUint8Array(cred.id);
        return cred;
      });
    }

    // Step 2: Call WebAuthn API to create credential
    const credential = await navigator.credentials.create({ publicKey });

    // Prepare data to send to server to complete registration
    const credentialResponse = {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
      },
    };

    // Step 3: Send credential to server for verification
    const completeResp = await fetch("/register/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: credentialResponse, username }),
    });

    const completeJson = await completeResp.json();
    console.log("Step 3 response:", completeJson);

    if (completeJson.status === "ok") {
      alert("Registration successful!");
    } else {
      alert("Registration failed: " + (completeJson.message || "Unknown error"));
    }
  } catch (err) {
    console.error("Registration error:", err);
    alert("Registration error: " + err.message);
  }
};
