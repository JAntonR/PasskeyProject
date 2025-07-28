const signUpButton = document.querySelector("[data-sign-up]")
const loginButton = document.querySelector("[data-login]")
const emailInput = document.querySelector("[data-email]")
const modal = document.querySelector("[data-modal]")
const closeButton = document.querySelector("[data-close]")

signUpButton.addEventListener("click", signup)
loginButton.addEventListener("click", login) 
closeButton.addEventListener("click", () => modal.close()) 

const SERVER_URL = "http://localhost:3000";

async function signup() {
    const email = emailInput.value;

    const data = await navigator.credentials.create({ publicKey: { 
        challenge: new Uint8Array([0,1,2,3,4,5,6]),
        rp: { name: "Passkey Project", id: "localhost"},
        user: { id: new Uint8Array(16),
                name: email, 
                displayName: email },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -8 },
            { type: "public-key", alg: -257 },
        ],
    
    },
})
    console.log(data);
    showModalText("Successfully signed up! Please log in.");
}

async function login() {
    const email = emailInput.value
    showModalText("Successfully logged in! You can now use the app.");
}

function showModalText(text) {
    modal.querySelector("[data-content]").innerText = text;
    modal.showModal()
}