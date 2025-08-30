// app.js
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

// Routes
const AuthRoutes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");

const app = express();

// Core middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(cors());
app.use(cookieParser());

// Health check
app.get("/", (req, res) => {
  res.send("API is running");
});

app.get("/api/auth/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: process.uptime(),
    message: "Server is up and running",
  });
});

// Attach routes
app.use("/api/auth", AuthRoutes);
app.use("/api/email", TestEmailRoute);
app.use("/api/admin", AdminRoutes);

module.exports = app;
