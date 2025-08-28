const Redis = require("ioredis");
require("dotenv").config();

if (!process.env.REDIS_URL) {
  console.warn("No REDIS_URL found. Redis client will not connect.");
}

const redisClient = process.env.REDIS_URL
  ? new Redis(
      "rediss://default:AcpJAAIncDE5MDJhMzhlYjAyZGQ0ZmIyOWRjOWRjODZiNTU4ZWJhOXAxNTE3ODU@proud-silkworm-51785.upstash.io:6379"
    )
  : null;

if (redisClient) { 
redisClient.on("connect", () =>
  console.log("Redis client: Attempting to connect...")
);
redisClient.on("ready", () =>
  console.log("Redis client: Successfully connected and ready!")
);
redisClient.on("error", (err) => {
  console.error("Redis client: Error -", err);
});
redisClient.on("end", () => console.log("Redis client: Connection closed."));
redisClient.on("reconnecting", () =>
  console.log("Redis client: Reconnecting...")
);
}



process.on("SIGINT", async () => {
  console.log("Shutting down Redis client...");
  await redisClient.quit();
  process.exit(0);
});

module.exports = redisClient;
