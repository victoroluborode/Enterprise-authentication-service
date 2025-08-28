const { PrismaClient } = require("@prisma/client");
const redisClient = require("../config/redisClient");
const path = require("path");

const prismaClient = new PrismaClient();

let prisma = prismaClient;

const initializePrismaWithRedis = async () => {
  if (process.env.REDIS_URL && redisClient) {
    try {
      console.log("=== PRISMA REDIS EXTENSION DEBUG ===");
      console.log("redisClient status:", redisClient.status);
      console.log("redisClient options:", {
        host: redisClient.options.host,
        port: redisClient.options.port,
      });

      // Wait for Redis to be ready if it's not already
      if (redisClient.status !== "ready") {
        console.log("Waiting for Redis client to be ready...");
        await redisClient.ping();
        console.log("Redis client is now ready");
      }

      const {
        PrismaExtensionRedis,
        CacheCase,
      } = require("prisma-extension-redis");

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

      // Try using Redis URL instead of client object
      prisma = prisma.$extends(
        PrismaExtensionRedis({
          config: cacheConfig,
          redis: {
            host: redisClient.options.host,
            port: redisClient.options.port,
            password: process.env.REDIS_URL.split('//')[1].split('@')[0].split(':')[1],
            username: "default",
            connectTimeout: 10000,
            commandTimeout: 5000,
            retryDelayOnFailedAttempt: (attempt) => Math.min(attempt * 50, 500),
            maxRetriesPerRequest: 3,
          },
        })
      );

      console.log(
        "Prisma Redis extension loaded successfully with URL configuration"
      );
    } catch (error) {
      console.warn("Prisma Redis extension failed to load:", error.message);
      console.warn("Continuing without Redis caching for Prisma");
    }
  } else {
    console.log("Redis not available, using Prisma without caching");
  }
};

// Initialize Redis extension asynchronously
initializePrismaWithRedis().catch(console.error);

// Connect Prisma
prisma
  .$connect()
  .then(() =>
    console.log(
      `Prisma client connected successfully to ${process.env.DATABASE_URL}`
    )
  )
  .catch((err) => console.error("Prisma client connection failed:", err));

// Graceful shutdown
const gracefulShutdown = async () => {
  try {
    await prisma.$disconnect();
    console.log("Prisma client disconnected");
  } catch (error) {
    console.error("Error disconnecting Prisma client:", error);
  }
};

process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);

module.exports = prisma;
