
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
require("dotenv").config();
const cors = require("cors");
const helmet = require("helmet");

// Import individual route files directly
const AuthRoutes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");

const redisClient = require("../src/config/redisClient");
const { globalErrorHandler } = require("./middleware/error-handler");
const requestLogger = require("../src/middleware/request-logger");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");

const swaggerDocument = YAML.load(path.resolve(__dirname, "../openapi.yaml"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  cors({
    origin: "http://localhost:3001",
    credentials: true,
  })
);

app.use(cookieParser());
app.use(requestLogger);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.get("/api/auth/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: process.uptime(),
    message: "Server is up and running",
  });
});

// Mount each route file directly - NO consolidated router needed
app.use("/api/auth/", AuthRoutes); // Auth routes: /api/auth/login, /api/auth/register, etc.
app.use("/api/email/", TestEmailRoute); // Email routes: /api/email/*
app.use("/api/admin/", AdminRoutes); // Admin routes: /api/admin/*

app.use(globalErrorHandler);
module.exports = app;
