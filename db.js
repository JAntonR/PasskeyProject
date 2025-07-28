const { use } = require("react");

const USERS = []

function getUserByEmail(email) {
    return USERS.find(user => user.email === email);
}
function getUserById(id) {
    return USERS.find(user => user.id === id);
}

function createUser(id, email, passkey) {
    USERS.push({ id, email, passkey });
}

function updateUserByCounter(id, counter) {
    const user = USERS.find(user => user.id === id);
    user.passkey.counter = counter;
}

module.exports = {
    getUserByEmail,
    getUserById,
    createUser,
    updateUserByCounter,
};