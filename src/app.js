const express = require('express');
const app = express();
require('dotenv').config();
const Routes = require("./routes/auth");
const cors = require('cors');
const { globalRateLimiter } = require("../src/middleware/ratelimiter")





app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "http://localhost:3001", // React dev server URL
    credentials: true,
  })
);

app.use(globalRateLimiter);
app.use("/api/auth/", Routes);



module.exports = app;