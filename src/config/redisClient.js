// config/redisClient.js
const { Redis } = require("ioredis");
const pino = require("pino");

const logger = pino();

// Create the main Redis client instance from the environment URL
const redisClient = process.env.REDIS_URL
  ? new Redis(process.env.REDIS_URL, {
      // Add robust connection options to prevent timeouts
      maxRetriesPerRequest: 3,
      connectTimeout: 10000,
      commandTimeout: 5000,
      tls: {}, // Use TLS for Upstash connections
    })
  : null;

// Use a promise to track the readiness state of the client.
// We'll export this promise so other files can wait for Redis to be ready.
const redisReadyPromise = new Promise((resolve, reject) => {
  if (!redisClient) {
    logger.warn("No REDIS_URL found. Redis client will not be used.");
    return resolve(null); // Resolve with null if Redis is not configured
  }

  // If the client is already ready (rare), resolve immediately
  if (redisClient.status === "ready") {
    return resolve(redisClient);
  }

  // Handle the 'ready' and 'error' events to know when to proceed
  redisClient.once("ready", () => {
    logger.info("Redis client connected successfully and is ready!");
    resolve(redisClient);
  });

  redisClient.once("error", (err) => {
    logger.error(
      "Redis client encountered an error during connection:",
      err.message
    );
    // Even on error, we resolve to allow the application to start
    // in a degraded mode (without Redis caching/rate limiting).
    resolve(null);
  });

  // Add a timeout to prevent the application from hanging indefinitely
  setTimeout(() => {
    if (redisClient.status !== "ready") {
      logger.warn(
        "Redis client connection timed out. Proceeding without caching/rate limiting."
      );
      resolve(null);
    }
  }, 10000);
});

module.exports = { redisClient, redisReadyPromise };
