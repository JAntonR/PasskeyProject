const BACKEND_URL = 'https://https://decfb4248dbd.ngrok-free.app'; // Replace this

async function register() {
  const username = document.getElementById('username').value;
  document.getElementById('status').textContent = '⏳ Requesting challenge...';

  const challengeResp = await fetch(`${BACKEND_URL}/register-challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username })
  });

  const options = await challengeResp.json();
  options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
  options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: options });
  } catch (err) {
    document.getElementById('status').textContent = '❌ User canceled or error.';
    return;
  }

  const response = {
    id: cred.id,
    rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
    type: cred.type,
    response: {
      attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))),
      clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)))
    }
  };

  const verifyResp = await fetch(`${BACKEND_URL}/verify-registration`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, credential: response })
  });

  const result = await verifyResp.json();
  document.getElementById('status').textContent = result.success ? '✅ Passkey registered!' : '❌ Registration failed.';
}
