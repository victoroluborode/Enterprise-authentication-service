const express = require('express');
const app = express();
require('dotenv').config();
const Routes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");
const cors = require('cors');
const helmet = require('helmet');
const { globalRateLimiter } = require("../src/middleware/ratelimiter");
const redisClient = require("../src/config/redisClient")





app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  cors({
    origin: "http://localhost:3001", // React dev server URL
    credentials: true,
  })
);

app.use(globalRateLimiter);
app.use("/api/auth/", Routes);
app.use("/api/auth", TestEmailRoute);
app.use("api/auth", AdminRoutes);



module.exports = app;