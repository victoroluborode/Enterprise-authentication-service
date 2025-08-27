const Redis = require("ioredis");
require("dotenv").config();

const redisClient = new Redis(process.env.REDIS_URL);

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


process.on("SIGINT", async () => {
  console.log("Shutting down Redis client...");
  await redisClient.quit();
  process.exit(0);
});

module.exports = redisClient;
