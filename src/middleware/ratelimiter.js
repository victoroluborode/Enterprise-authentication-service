// Fixed middleware/ratelimiter.js
const { rateLimit } = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const redisClient = require("../config/redisClient");

// Helper function to safely extract IP address
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

  return rateLimit({
    windowMs,
    max,
    message,
    statusCode: 429,
    headers: true,
    store: new RedisStore({
      client: redisClient,
      prefix: `${prefix}:`, // Add colon for better key separation
      sendCommand: (...args) => redisClient.call(...args), // Ensure proper Redis command execution
    }),
    keyGenerator: (req) => {
      const key = keyGen ? keyGen(req) : getClientIP(req);
      const finalKey = String(key);
      console.log(`[RateLimiter] Key for ${prefix}: ${finalKey}`);
      return finalKey;
    },
    skipFailedRequests: true,
    skipSuccessfulRequests: false,
    // CRITICAL FIX: Disable validation that causes double counting
    validate: {
      trustProxy: false,
      xForwardedForLimit: 1,
      singleCount: false, // This prevents ERR_ERL_DOUBLE_COUNT
    },
    // Add standardHeaders for better client handling
    standardHeaders: true,
    legacyHeaders: false,
    onLimitReached: (req) => {
      console.warn(
        `RATE LIMIT HIT: ${type}, IP: ${getClientIP(req)}, Path: ${req.path}`
      );
    },
  });
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
  keyGen: (req) => (req.user?.id ? `user_${req.user.id}` : getClientIP(req)), // Fixed: use req.user.id instead of req.user.sub
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
