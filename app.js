require('dotenv').config();

const mongoose = require("mongoose");
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");

// my routes
const authRoutes = require('./routes/auth')

// DB CONNECTION
mongoose.connect(process.env.DATABASE, {
    autoIndex : true,
}).then(() => {
    console.log('DB CONNECTED');
})

// MIDDLEWARE
app.use(bodyParser.json());
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// MY ROUTES
app.use('/api', authRoutes)

// SETTING THE PORT
const port = process.env.PORT || 5000;

// STARTING THE SERVER
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}) 