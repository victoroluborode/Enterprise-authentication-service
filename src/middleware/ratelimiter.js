// src/middleware/ratelimiter.js
const {
  RateLimiterRedis,
  RateLimiterMemory,
} = require("rate-limiter-flexible");
const redis = require("redis");
const AppError = require("../utils/app-error");
const logger = require("../utils/logger");

const setupLimiters = async () => {
  let redisClient;
  let store;

  // Attempt to connect to Redis
  try {
    redisClient = redis.createClient({ url: process.env.REDIS_URL });

    // This is the key change: we await the connection before proceeding.
    await redisClient.connect();
    logger.info("Redis client connected successfully and is ready!");
    store = "redis";
  } catch (err) {
    logger.warn(
      "Redis client connection timed out. Proceeding without caching/rate limiting."
    );
    store = "memory";
  }

  const getStore = () => {
    if (store === "redis") {
      return { storeClient: redisClient };
    }
    return {};
  };

  const commonOptions = {
    duration: 60, // 1 minute
  };

  const globalRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 200, // 200 requests per minute
    keyPrefix: "global",
    ...getStore(),
  });

  const loginRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 login attempts
    keyPrefix: "login_fail_consecutive",
    ...getStore(),
  });

  const registerRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 10, // 10 registration attempts
    keyPrefix: "register",
    ...getStore(),
  });

  const tokenRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 15, // 15 token refresh attempts
    keyPrefix: "token_refresh",
    ...getStore(),
  });

  const postsRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 200, // 200 requests per minute
    keyPrefix: "posts",
    ...getStore(),
  });

  const createPostRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 10, // 10 posts per minute
    keyPrefix: "create_post",
    ...getStore(),
  });

  const sessionsRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 session list requests per minute
    keyPrefix: "sessions",
    ...getStore(),
  });

  const logoutAllRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 logout all attempts per minute
    keyPrefix: "logout_all",
    ...getStore(),
  });

  const logoutSpecificRateLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 logout specific attempts per minute
    keyPrefix: "logout_specific",
    ...getStore(),
  });

  const resendVerificationLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 3, // 3 resend verification attempts per minute
    keyPrefix: "resend_verification",
    ...getStore(),
  });

  const changePasswordLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 change password attempts per minute
    keyPrefix: "change_password",
    ...getStore(),
  });

  const forgotPasswordLimiter = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 forgot password attempts per minute
    keyPrefix: "forgot_password",
    ...getStore(),
  });

  return {
    globaRateLimiter,
    loginRateLimiter,
    registerRateLimiter,
    tokenRateLimiter,
    postsRateLimiter,
    createPostRateLimiter,
    sessionsRateLimiter,
    logoutAllRateLimiter,
    logoutSpecificRateLimiter,
    resendVerificationLimiter,
    changePasswordLimiter,
    forgotPasswordLimiter,
    redisClient: store === "redis" ? redisClient : undefined,
  };
};

module.exports = setupLimiters;
