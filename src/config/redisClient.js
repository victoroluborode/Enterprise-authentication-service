const { Redis } = require("ioredis");
const pino = require("pino");

const logger = pino();


const redisClient = process.env.REDIS_URL
  ? new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      connectTimeout: 10000,
      commandTimeout: 5000,
      tls: {}, 
    })
  : null;


const redisReadyPromise = new Promise((resolve, reject) => {
  if (!redisClient) {
    logger.warn("No REDIS_URL found. Redis client will not be used.");
    return resolve(null); 
  }

  
  if (redisClient.status === "ready") {
    return resolve(redisClient);
  }

  
  redisClient.once("ready", () => {
    logger.info("Redis client connected successfully and is ready!");
    resolve(redisClient);
  });

  redisClient.once("error", (err) => {
    logger.error(
      "Redis client encountered an error during connection:",
      err.message
    );
    
    resolve(null);
  });

  
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
