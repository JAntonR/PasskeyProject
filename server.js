const express =  require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const{  
    getUserByEmail, 
    getUserById, 
    createUser, 
    updateUserByCounter } = require('./db');


const app = express();
app.use(express.json())
app.use(cookieParser());

const CLIENT_URL = "http://localhost:5173";

app.use(cors({ origin: CLIENT_URL, credentials: true }));

app.listen(3000, () => {   
    console.log("Server is running on http://localhost:3000");
});