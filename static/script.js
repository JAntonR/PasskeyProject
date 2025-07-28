async function register() {
  const username = document.getElementById("username").value;

  const res = await fetch("/generate-registration-options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });

  const options = await res.arrayBuffer();
  const credentialCreationOptions = CBOR.decode(options);

  const credential = await navigator.credentials.create({
    publicKey: credentialCreationOptions,
  });

  const attestationResponse = {
    id: credential.id,
    rawId: new Uint8Array(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
      attestationObject: new Uint8Array(credential.response.attestationObject),
    },
  };

  await fetch("/verify-registration", {
    method: "POST",
    body: CBOR.encode(attestationResponse),
  });

  alert("Registration complete!");
}
