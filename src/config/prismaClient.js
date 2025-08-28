// prisma.js
const { PrismaClient } = require("@prisma/client");
const { PrismaExtensionRedis, CacheCase } = require("prisma-extension-redis");
const { redisReadyPromise } = require("../config/redisClient");
const pino = require("pino");

const logger = pino();

// Global Prisma client instance
const prismaClient = new PrismaClient();
let prisma = prismaClient;

// Asynchronous function to initialize Prisma
const initializePrisma = async () => {
  const readyClient = await redisReadyPromise;

  if (readyClient) {
    try {
      logger.info("Initializing Prisma with Redis extension.");

      const cacheConfig = {
        ttl: 60,
        stale: 30,
        models: {
          user: { ttl: 60 },
          post: { ttl: 60 },
        },
        type: "STRING",
        cacheKey: {
          case: CacheCase.SNAKE_CASE,
          delimiter: ":",
          prefix: "auth_service",
        },
      };

      prisma = prisma.$extends(
        PrismaExtensionRedis({
          config: cacheConfig,
          redis: readyClient, // Pass the already-ready client instance
        })
      );

      logger.info("Prisma Redis extension loaded successfully.");
    } catch (error) {
      logger.warn("Prisma Redis extension failed to load:", error.message);
      logger.warn("Continuing without Redis caching for Prisma.");
    }
  } else {
    logger.warn("Redis not available, using Prisma without caching.");
  }
};

// Initialize Prisma and then connect to the database
(async () => {
  await initializePrisma();

  try {
    await prisma.$connect();
    logger.info("Prisma client connected successfully to the database.");
  } catch (err) {
    logger.fatal("Prisma client connection failed:", err);
  }
})();

module.exports = prisma;
