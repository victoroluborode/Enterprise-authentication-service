// src/middleware/ratelimiter.js
const {
  RateLimiterRedis,
  RateLimiterMemory,
} = require("rate-limiter-flexible");
const redis = require("redis");
const AppError = require("../utils/app-error");
const logger = require("../utils/logger");

// Helper function to create the Express middleware wrapper
const rateLimiterMiddleware = (rateLimiter) => {
  return (req, res, next) => {
    // Use the X-Device-Id header as the unique key, with a fallback to IP
    const key = req.header("X-Device-Id") || req.ip;

    rateLimiter
      .consume(key)
      .then(() => {
        next();
      })
      .catch((rejRes) => {
        res.status(429).send("Too many requests.");
      });
  };
};

const setupLimiters = async () => {
  let redisClient;
  let store;

  // Attempt to connect to Redis
  try {
    redisClient = redis.createClient({ url: process.env.REDIS_URL });

    // Await the connection before proceeding.
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

  // Create the instances of the rate limiters
  const globalLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 200, // 200 requests per minute
    keyPrefix: "global",
    ...getStore(),
  });

  const loginLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 login attempts
    keyPrefix: "login_fail_consecutive",
    ...getStore(),
  });

  const registerLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 10, // 10 registration attempts
    keyPrefix: "register",
    ...getStore(),
  });

  const tokenLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 15, // 15 token refresh attempts
    keyPrefix: "token_refresh",
    ...getStore(),
  });

  const postsLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 200, // 200 requests per minute
    keyPrefix: "posts",
    ...getStore(),
  });

  const createPostLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 10, // 10 posts per minute
    keyPrefix: "create_post",
    ...getStore(),
  });

  const sessionsLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 session list requests per minute
    keyPrefix: "sessions",
    ...getStore(),
  });

  const logoutAllLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 logout all attempts per minute
    keyPrefix: "logout_all",
    ...getStore(),
  });

  const logoutSpecificLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 logout specific attempts per minute
    keyPrefix: "logout_specific",
    ...getStore(),
  });

  const resendVerificationLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 3, // 3 resend verification attempts per minute
    keyPrefix: "resend_verification",
    ...getStore(),
  });

  const changePasswordLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 change password attempts per minute
    keyPrefix: "change_password",
    ...getStore(),
  });

  const forgotPasswordLimiterInstance = new (
    store === "redis" ? RateLimiterRedis : RateLimiterMemory
  )({
    ...commonOptions,
    points: 5, // 5 forgot password attempts per minute
    keyPrefix: "forgot_password",
    ...getStore(),
  });

  return {
    globalRateLimiter: rateLimiterMiddleware(globalLimiterInstance),
    loginRateLimiter: rateLimiterMiddleware(loginLimiterInstance),
    registerRateLimiter: rateLimiterMiddleware(registerLimiterInstance),
    tokenRateLimiter: rateLimiterMiddleware(tokenLimiterInstance),
    postsRateLimiter: rateLimiterMiddleware(postsLimiterInstance),
    createPostRateLimiter: rateLimiterMiddleware(createPostLimiterInstance),
    sessionsRateLimiter: rateLimiterMiddleware(sessionsLimiterInstance),
    logoutAllRateLimiter: rateLimiterMiddleware(logoutAllLimiterInstance),
    logoutSpecificRateLimiter: rateLimiterMiddleware(
      logoutSpecificLimiterInstance
    ),
    resendVerificationLimiter: rateLimiterMiddleware(
      resendVerificationLimiterInstance
    ),
    changePasswordLimiter: rateLimiterMiddleware(changePasswordLimiterInstance),
    forgotPasswordLimiter: rateLimiterMiddleware(forgotPasswordLimiterInstance),
    redisClient: store === "redis" ? redisClient : undefined,
  };
};

module.exports = setupLimiters;
