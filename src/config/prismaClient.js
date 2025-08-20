const { PrismaClient } = require("@prisma/client");
const { withAccelerate } = require("@prisma/extension-accelerate");
const { withOptimize } = require("@prisma/extension-optimize");
const redisClient = require("../config/redisClient");
const { PrismaExtensionRedis, CacheCase } = require("prisma-extension-redis");
require

const PrismaClient = new PrismaClient();

const AutoCacheConfig = {
    ttl: 60,
    stale: 30,
};

const CacheConfig = {
    ttl: 60,
    stale: 30,
    auto: AutoCacheConfig,
    type: 'JSON',
    cacheKey: {
        case: CacheCase.SNAKE_CASE,
        delimiter: ':',
        prefix: 'auth_service'
    }
};

const prisma = prismaClient
  .$extends(withAccelerate())
  .$extends(withOptimize({ apiKey: process.env.OPTIMIZE_API_KEY }))
  .$extends(
    PrismaExtensionRedis({
      config: cacheConfig,
      client: redisClient,
    })
  );

export default prisma;