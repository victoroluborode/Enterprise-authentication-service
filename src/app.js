const express = require('express');
const app = express();
require('dotenv').config();
const registerRoute = require("./routes/auth");
const cors = require('cors');



app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "http://localhost:3001", // React dev server URL
    credentials: true,
  })
);

app.use("/api/auth/register", registerRoute);



module.exports = app;