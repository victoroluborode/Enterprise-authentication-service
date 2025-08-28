// middleware/ratelimiter.js
const { rateLimit } = require("express-rate-limit");
const RedisStore = require("rate-limit-redis").default;
const { redisClient, redisReadyPromise } = require("../config/redisClient");
const pino = require("pino");

const logger = pino();

const getClientIP = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  const realIP = req.headers["x-real-ip"];
  if (realIP) return realIP;
  if (req.ip)
    return typeof req.ip === "string" ? req.ip : JSON.stringify(req.ip);
  return (
    req.connection?.remoteAddress || req.socket?.remoteAddress || "127.0.0.1"
  );
};

// Use an async function to create the rate limiter
const createLimiter = async (options) => {
  const {
    windowMs,
    max,
    message,
    type,
    keyGen,
    prefix = "ratelimit",
  } = options;

  // IMPORTANT: Wait for Redis to be ready before configuring the store
  const readyClient = await redisReadyPromise;

  const config = {
    windowMs,
    max,
    message,
    statusCode: 429,
    headers: true,
    keyGenerator: (req) => {
      const key = keyGen ? keyGen(req) : getClientIP(req);
      const finalKey = String(key);
      logger.info(`[RateLimiter] Key for ${prefix}: ${finalKey}`);
      return finalKey;
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
      logger.warn(
        `RATE LIMIT HIT: ${type}, IP: ${getClientIP(req)}, Path: ${req.path}`
      );
      res.status(options.statusCode).send(options.message);
    },
  };

  if (readyClient) {
    try {
      config.store = new RedisStore({
        client: readyClient,
        prefix: `${prefix}:`,
        sendCommand: (...args) => readyClient.call(...args),
      });
      logger.info(`[RateLimiter] Using Redis store for ${prefix}`);
    } catch (error) {
      logger.warn(
        `[RateLimiter] Failed to create Redis store for ${prefix}, falling back to memory store:`,
        error.message
      );
    }
  } else {
    logger.warn(
      `[RateLimiter] Redis not available, using memory store for ${prefix}`
    );
  }

  return rateLimit(config);
};

// Export an async function that returns the limiters
// We need to do this because the createLimiter function is now async
module.exports = async () => {
  const globalRateLimiter = await createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message:
      "Too many requests from this IP, please try again after 15 minutes.",
    type: "IP-based",
    prefix: "global",
  });

  const loginRateLimiter = await createLimiter({
    windowMs: 5 * 60 * 1000,
    max: 20,
    message: "Too many login attempts, please try again after 5 minutes.",
    type: "IP-based",
    prefix: "login",
  });

  const registerRateLimiter = await createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message:
      "Too many registration attempts from this IP, please try again after 15 minutes.",
    type: "IP-based",
    prefix: "register",
  });

  const tokenRateLimiter = await createLimiter({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message:
      "Too many token refresh requests, please try again after 1 minute.",
    type: "User-based",
    prefix: "token",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const postsRateLimiter = await createLimiter({
    windowMs: 5 * 60 * 1000,
    max: 50,
    message: "Too many post requests, please try again after 5 minutes.",
    type: "User-based",
    prefix: "posts",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const createPostRateLimiter = await createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many posts created. Please try again later.",
    type: "User-based",
    prefix: "create_post",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const sessionsRateLimiter = await createLimiter({
    windowMs: 1 * 60 * 1000,
    max: 20,
    message: "Too many session requests, please try again after 1 minute.",
    type: "User-based",
    prefix: "sessions",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const logoutAllRateLimiter = await createLimiter({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: "Too many logout all requests, please try again after 5 minutes.",
    type: "User-based",
    prefix: "logout_all",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const logoutSpecificRateLimiter = await createLimiter({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message:
      "Too many specific session logout requests, please try again after 5 minutes.",
    type: "User-based",
    prefix: "logout_specific",
    keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
  });

  const resendVerificationLimiter = await createLimiter({
    windowMs: 10 * 60 * 1000,
    max: 2,
    message:
      "Too many resend verification requests. Please try again after 10 minutes.",
    type: "User-based",
    prefix: "resend_verification",
    keyGen: (req) =>
      req.body?.email ? `email_${req.body.email}` : getClientIP(req),
  });

  const changePasswordLimiter = await createLimiter({
    windowMs: 30 * 60 * 1000,
    max: 3,
    message:
      "Too many password change attempts. Please try again after 30 minutes.",
    type: "User-based",
    prefix: "change_password",
    keyGen: (req) => (req.user?.id ? `user_${req.user.id}` : getClientIP(req)),
  });

  const forgotPasswordLimiter = await createLimiter({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message:
      "Too many password reset requests. Please try again after 15 minutes.",
    type: "User-based",
    prefix: "forgot_password",
    keyGen: (req) =>
      req.body?.email ? `email_${req.body.email}` : getClientIP(req),
  });

  return {
    globalRateLimiter,
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
  };
};
