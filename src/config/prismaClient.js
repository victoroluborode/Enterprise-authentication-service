// prisma.js
const { PrismaClient } = require("@prisma/client");
const { PrismaExtensionRedis, CacheCase } = require("prisma-extension-redis");
const { redisReadyPromise } = require("../config/redisClient");
const pino = require("pino");

const logger = pino();

async function createPrisma() {
  const prismaClient = new PrismaClient();

  try {
    const readyClient = await redisReadyPromise;

    if (readyClient) {
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

      return prismaClient.$extends(
        PrismaExtensionRedis({
          config: cacheConfig,
          client: readyClient,
        })
      );
    }

    logger.warn("Redis not available, using plain Prisma client.");
    return prismaClient;
  } catch (error) {
    logger.error("Error initializing Prisma with Redis:", error);
    return prismaClient;
  }
}

// Export a promise of the ready Prisma client
const prisma = createPrisma();

module.exports = prisma;
