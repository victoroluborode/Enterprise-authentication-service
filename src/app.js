const express = require("express");
const cookieParser = require("cookie-parser");
require("dotenv").config({
  path: process.env.NODE_ENV === "production" ? ".env.production" : ".env",
});
const cors = require("cors");
const helmet = require("helmet");
const path = require("path");

// Middleware
const requestLogger = require("../src/middleware/request-logger");
const { globalErrorHandler } = require("./middleware/error-handler");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");

// Routes
const AuthRoutes = require("./routes/auth");
const TestEmailRoute = require("./routes/test-email");
const AdminRoutes = require("./routes/admin");

const swaggerDocument = YAML.load(path.resolve(__dirname, "../openapi.yaml"));

const setupApp = async () => {
  const app = express();

  // Import rate limiters
  const limiters = await require("./middleware/ratelimiter")();
  const { globalRateLimiter, loginRateLimiter, registerRateLimiter } = limiters;

  // Core middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(helmet());
  app.use(
    cors({
      origin: [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://secureauth-qkhg.onrender.com", // deployed domain
      ],
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Device-Id"],
    })
  );
  app.use(cookieParser());
  app.use(requestLogger);

  /**
   * Public routes (NOT rate limited)
   */
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

  // Swagger UI (no rate limit)
  app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument, {
      swaggerOptions: {
        docExpansion: "none",
        defaultModelsExpandDepth: -1,
        tryItOutEnabled: true,
        persistAuthorization: true,
        filter: true,
      },
    })
  );

  /**
   * Route-specific limiters
   */
  app.use("/api/auth/login", loginRateLimiter);
  app.use("/api/auth/register", registerRateLimiter);

  /**
   * Global rate limiter — applies to everything under `/api`,
   * except health checks and docs.
   */
  app.use("/api", (req, res, next) => {
    if (
      req.path.startsWith("/auth/health") || // whitelist health
      req.originalUrl.startsWith("/api-docs") // whitelist docs
    ) {
      return next();
    }
    return globalRateLimiter(req, res, next);
  });

  /**
   * Protected routes (rate limited by default)
   */
  app.use("/api/auth", AuthRoutes);
  app.use("/api/email", TestEmailRoute);
  app.use("/api/admin", AdminRoutes);

  // Global error handler
  app.use(globalErrorHandler);

  return app;
};

module.exports = setupApp;
