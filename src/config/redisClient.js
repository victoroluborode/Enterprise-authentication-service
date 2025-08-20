const Redis = require("ioredis");
require("dotenv").config();

const redisOptions = {
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB || "0", 10),
  maxRetriesPerRequest: null,
  enableOfflineQueue: true,
  // ADDED: Additional options for better rate limiting compatibility
  lazyConnect: true,
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  // Ensure commands are properly queued and executed
  enableAutoPipelining: false,
};

const redisClient = new Redis(redisOptions);

redisClient.on("connect", () =>
  console.log("Redis client: Attempting to connect...")
);
redisClient.on("ready", () =>
  console.log("Redis client: Successfully connected and ready!")
);
redisClient.on("error", (err) => {
  console.error("Redis client: Error -", err);
  // Don't throw here, let the rate limiter handle Redis failures gracefully
});
redisClient.on("end", () => console.log("Redis client: Connection closed."));
redisClient.on("reconnecting", () =>
  console.log("Redis client: Reconnecting...")
);

// ADDED: Graceful shutdown handling
process.on("SIGINT", async () => {
  console.log("Shutting down Redis client...");
  await redisClient.quit();
  process.exit(0);
});

module.exports = redisClient;
