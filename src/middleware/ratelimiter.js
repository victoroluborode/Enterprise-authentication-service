// Fixed middleware/ratelimiter.js
const { rateLimit } = require("express-rate-limit");
const RedisStore = require("rate-limit-redis").default;
const redisClient = require("../config/redisClient");

const getClientIP = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  const realIP = req.headers["x-real-ip"];

  if (forwarded) return forwarded.split(",")[0].trim();
  if (realIP) return realIP;
  if (req.ip)
    return typeof req.ip === "string" ? req.ip : JSON.stringify(req.ip);
  return (
    req.connection?.remoteAddress || req.socket?.remoteAddress || "127.0.0.1"
  );
};

const createLimiter = (options) => {
  const {
    windowMs,
    max,
    message,
    type,
    keyGen,
    prefix = "ratelimit",
  } = options;

  // Create base configuration
  const config = {
    windowMs,
    max,
    message,
    statusCode: 429,
    headers: true,
    keyGenerator: (req) => {
      const key = keyGen ? keyGen(req) : getClientIP(req);
      const finalKey = String(key);
      console.log(`[RateLimiter] Key for ${prefix}: ${finalKey}`);
      return finalKey;
    },
    skipFailedRequests: true,
    skipSuccessfulRequests: false,
    validate: {
      trustProxy: false,
      xForwardedForLimit: 1,
      singleCount: false,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
      console.warn(
        `RATE LIMIT HIT: ${type}, IP: ${getClientIP(req)}, Path: ${req.path}`
      );
      res.status(options.statusCode).send(options.message);
    },
  };

  // Only add Redis store if redisClient is available and ready
  if (redisClient && process.env.REDIS_URL && redisClient.status === "ready") {
    try {
      config.store = new RedisStore({
        client: redisClient,
        prefix: `${prefix}:`,
        sendCommand: (...args) => redisClient.call(...args),
        // Prevent the package from creating its own Redis client
        resetExpiryOnChange: false,
        windowMs: windowMs,
      });
      console.log(
        `[RateLimiter] Using Redis store for ${prefix} (client status: ${redisClient.status})`
      );
    } catch (error) {
      console.warn(
        `[RateLimiter] Failed to create Redis store for ${prefix}, falling back to memory store:`,
        error.message
      );
    }
  } else {
    const reason = !redisClient
      ? "no client"
      : !process.env.REDIS_URL
      ? "no URL"
      : `client status: ${redisClient.status}`;
    console.warn(
      `[RateLimiter] Redis not ready (${reason}), using memory store for ${prefix}`
    );
  }

  return rateLimit(config);
};

// ----- Limiters -----
const globalRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes.",
  type: "IP-based",
  prefix: "global",
});

const loginRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: "Too many login attempts, please try again after 5 minutes.",
  type: "IP-based",
  prefix: "login",
});

const registerRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message:
    "Too many registration attempts from this IP, please try again after 15 minutes.",
  type: "IP-based",
  prefix: "register",
});

const tokenRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: "Too many token refresh requests, please try again after 1 minute.",
  type: "User-based",
  prefix: "token",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const postsRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 50,
  message: "Too many post requests, please try again after 5 minutes.",
  type: "User-based",
  prefix: "posts",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const createPostRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many posts created. Please try again later.",
  type: "User-based",
  prefix: "create_post",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const sessionsRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000,
  max: 20,
  message: "Too many session requests, please try again after 1 minute.",
  type: "User-based",
  prefix: "sessions",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const logoutAllRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: "Too many logout all requests, please try again after 5 minutes.",
  type: "User-based",
  prefix: "logout_all",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const logoutSpecificRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message:
    "Too many specific session logout requests, please try again after 5 minutes.",
  type: "User-based",
  prefix: "logout_specific",
  keyGen: (req) => (req.user ? `user_${req.user.id}` : getClientIP(req)),
});

const resendVerificationLimiter = createLimiter({
  windowMs: 10 * 60 * 1000,
  max: 2,
  message:
    "Too many resend verification requests. Please try again after 10 minutes.",
  type: "User-based",
  prefix: "resend_verification",
  keyGen: (req) =>
    req.body?.email ? `email_${req.body.email}` : getClientIP(req),
});

const changePasswordLimiter = createLimiter({
  windowMs: 30 * 60 * 1000,
  max: 3,
  message:
    "Too many password change attempts. Please try again after 30 minutes.",
  type: "User-based",
  prefix: "change_password",
  keyGen: (req) => (req.user?.id ? `user_${req.user.id}` : getClientIP(req)),
});

const forgotPasswordLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message:
    "Too many password reset requests. Please try again after 15 minutes.",
  type: "User-based",
  prefix: "forgot_password",
  keyGen: (req) =>
    req.body?.email ? `email_${req.body.email}` : getClientIP(req),
});

module.exports = {
  globalRateLimiter,
  loginRateLimiter,
  tokenRateLimiter,
  registerRateLimiter,
  postsRateLimiter,
  createPostRateLimiter,
  sessionsRateLimiter,
  logoutAllRateLimiter,
  logoutSpecificRateLimiter,
  resendVerificationLimiter,
  changePasswordLimiter,
  forgotPasswordLimiter,
};
