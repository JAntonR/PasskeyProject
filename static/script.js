async function register() {
  const username = document.getElementById("username").value;
  const res = await fetch("/generate-registration-options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  const options = await res.json();

  options.challenge = base64ToBuffer(options.challenge);
  options.user.id = base64ToBuffer(options.user.id);

  const cred = await navigator.credentials.create({ publicKey: options });

  const credential = {
    id: cred.id,
    rawId: bufferToBase64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64(cred.response.clientDataJSON),
      attestationObject: bufferToBase64(cred.response.attestationObject)
    }
  };

  await fetch("/verify-registration", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential)
  });

  alert("Passkey registered!");
}

async function login() {
  const username = document.getElementById("username").value;
  const res = await fetch("/generate-authentication-options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  const options = await res.json();
  options.challenge = base64ToBuffer(options.challenge);
  options.allowCredentials = options.allowCredentials.map(c => ({
    ...c,
    id: base64ToBuffer(c.id)
  }));

  const assertion = await navigator.credentials.get({ publicKey: options });

  const credential = {
    id: assertion.id,
    rawId: bufferToBase64(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
      signature: bufferToBase64(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null
    }
  };

  await fetch("/verify-authentication", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential)
  });

  alert("Logged in successfully!");
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
