const express = require('express');
const app = express();
require('dotenv').config();
const registerRoute = require("./routes/auth");



app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/secureapi/register", registerRoute);



module.exports = app;