const express = require('express');
const cookieParser = require("cookie-parser");
const app = express();
require('dotenv').config();
const Routes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");
const cors = require('cors');
const helmet = require('helmet');
const { globalRateLimiter } = require("../src/middleware/ratelimiter");
const redisClient = require("../src/config/redisClient");
const { globalErrorHandler } = require('./middleware/error-handler');
const requestLogger = require("../src/middleware/request-logger");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");


const swaggerDocument = YAML.load(path.resolve(__dirname, '../openapi.yaml'));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  cors({
    origin: "http://localhost:3001", // React dev server URL
    credentials: true,
  })
);

app.use(cookieParser());
app.use(requestLogger);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.get("/api/auth/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: process.uptime(),
    message: "Server is up and running"
  })
})

app.use((req, res, next) => {
  if (req.path.startsWith("/api/auth")) return next();
  globalRateLimiter(req, res, next);
});

app.use("/api/auth/", Routes);
app.use("/api/auth/", TestEmailRoute);
app.use("/api/auth/", AdminRoutes);

app.use(globalErrorHandler);

module.exports = app;