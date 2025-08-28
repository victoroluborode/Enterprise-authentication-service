const express = require("express");
const cookieParser = require("cookie-parser");
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

// Export async setup function instead of app directly
const setupApp = async () => {
  const app = express();

  // Await the async function from the rate limiter module
  const limiters = await require("./middleware/ratelimiter")();
  const { globalRateLimiter, loginRateLimiter, registerRateLimiter } = limiters;

  // Middleware setup
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(helmet());

  // Fixed CORS configuration
  app.use(
    cors({
      origin: [
        "http://localhost:3000", // Local development
        "http://localhost:3001", // Local frontend (if any)
        "https://secureauth-qkhg.onrender.com", // Your deployed domain for Swagger UI
      ],
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Device-Id"],
    })
  );

  app.use(cookieParser());
  app.use(requestLogger);

  // Swagger UI configuration
  app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument, {
      swaggerOptions: {
        docExpansion: "none", // Don't expand all endpoints by default
        defaultModelsExpandDepth: -1, // Don't load models automatically
        tryItOutEnabled: true, // Keep this enabled for testing
        persistAuthorization: true, // Keep auth between page reloads
        filter: true, // Enable search filter
      },
    })
  );

  // Apply specific rate limiters to auth routes BEFORE global rate limiter
  app.use("/api/auth/login", loginRateLimiter);
  app.use("/api/auth/register", registerRateLimiter);

  // Health checks (these should be BEFORE global rate limiter)
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

  // Create a modified global rate limiter that skips API docs and health checks
  const apiRateLimiter = (req, res, next) => {
    // Skip rate limiting for API documentation and health checks
    if (req.path.startsWith("/api-docs") || req.path.includes("/health")) {
      return next();
    }
    return globalRateLimiter(req, res, next);
  };

  // Apply global rate limiter AFTER health checks and docs, but BEFORE API routes
  app.use("/api", apiRateLimiter);

  // Route setup
  app.use("/api/auth/", AuthRoutes);
  app.use("/api/email/", TestEmailRoute);
  app.use("/api/admin/", AdminRoutes);

  app.use(globalErrorHandler);

  return app;
};

module.exports = setupApp;
