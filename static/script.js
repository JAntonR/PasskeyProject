async function startRegistration() {
  const username = document.getElementById("username").value;

  const res = await fetch("/generate-registration-options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });
  const options = await res.json();
  options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
  options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

  const credential = await navigator.credentials.create({ publicKey: options });

  const credentialJSON = {
    id: credential.id,
    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
    type: credential.type,
    response: {
      attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
      clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
    }
  };

  await fetch("/verify-registration", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentialJSON)
  });

  alert("Registered successfully!");
}

async function startLogin() {
  const username = document.getElementById("username").value;

  const res = await fetch("/generate-authentication-options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });
  const options = await res.json();
  options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
  options.allowCredentials = options.allowCredentials.map(cred => ({
    id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
    type: cred.type
  }));

  const assertion = await navigator.credentials.get({ publicKey: options });

  const assertionJSON = {
    id: assertion.id,
    rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
    type: assertion.type,
    response: {
      authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
      clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
      signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
      userHandle: assertion.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))) : null
    }
  };

  await fetch("/verify-authentication", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(assertionJSON)
  });

  alert("Logged in successfully!");
}
