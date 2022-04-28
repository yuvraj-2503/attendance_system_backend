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

app.use(bodyParser.json());
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// MY ROUTES
app.use('/api', authRoutes)

const port = process.env.PORT || 5000;

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}) 