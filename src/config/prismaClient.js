const { PrismaClient } = require("@prisma/client");
const path = require("path");
const dotenv = require('dotenv')


dotenv.config({
  path: process.env.NODE_ENV === "production" ? ".env.production" : ".env",
});


const prismaClient = new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"]
});

let prisma = prismaClient;


if (process.env.REDIS_URL) {
  try {
    const redisClient = require("../config/redisClient");
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

    prisma = prisma.$extends(
      PrismaExtensionRedis({
        config: cacheConfig,
        client: redisClient,
      })
    );

    console.log("Prisma Redis extension loaded");
  } catch (error) {
    console.warn("Prisma Redis extension failed to load:", error.message);
  }
}

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
