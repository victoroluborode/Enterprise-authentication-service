const Redis = require('ioredis');
require('dotenv').config();

const redisOptions = {
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB || "0", 10),
  maxRetriesPerRequest: null,
  enableOfflineQueue: true,
};

const redisClient = new Redis(redisOptions);

redisClient.on("connect", () =>
  console.log("Redis client: Attempting to connect...")
);
redisClient.on("ready", () =>
  console.log("Redis client: Successfully connected and ready!")
);
redisClient.on("error", (err) => console.error("Redis client: Error -", err));
redisClient.on("end", () => console.log("Redis client: Connection closed."));
redisClient.on("reconnecting", () =>
  console.log("Redis client: Reconnecting...")
);

module.exports = redisClient;