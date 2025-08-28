const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
require("dotenv").config({
  path: process.env.NODE_ENV === "production" ? ".env.production" : ".env",
});
const cors = require("cors");
const helmet = require("helmet");
const path = require("path");

// Import all required components
const requestLogger = require("../src/middleware/request-logger");
const { globalErrorHandler } = require("./middleware/error-handler");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");

// Import all routes
const AuthRoutes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");

const swaggerDocument = YAML.load(path.resolve(__dirname, "../openapi.yaml"));

// Main asynchronous startup function
const startServer = async () => {
  // CORRECTED: Await the async function from the rate limiter module
  // This ensures we get the object containing the limiters, not the function itself.
  const limiters = await require("./middleware/ratelimiter")();
  const { globalRateLimiter, loginRateLimiter, registerRateLimiter } = limiters;

  // Middleware setup
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

  // Rate limiters should be applied before routes
  app.use(globalRateLimiter);   //line 46
  app.use("/api/auth/login", loginRateLimiter);
  app.use("/api/auth/register", registerRateLimiter);

  // Health checks
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

  // Route setup
  app.use("/api/auth/", AuthRoutes);
  app.use("/api/email/", TestEmailRoute);
  app.use("/api/admin/", AdminRoutes);

  app.use(globalErrorHandler);

  // Start the server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

// Call the async function to start the server
startServer().catch((err) => {
  console.error("Failed to start the server:", err);
  process.exit(1);
});

module.exports = app;
