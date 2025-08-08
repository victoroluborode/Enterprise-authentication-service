const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const redisClient = require('../config/redisClient');
const { Command } = require('ioredis');



const createLimiter = ({
  windowMs,
  max,
  message,
  type,
  keyGenerator,
  prefix = "ratelimit"
}) => {
  const storeInstance = new RedisStore({
    sendCommand: (command, ...args) => redisClient[command.toLowerCase()](...args),
    prefix: prefix 
  });

  return rateLimit({
    windowMs,
    max,
    message,
    statusCode: 429,
    headers: true,
    store: storeInstance,
    keyGenerator: keyGenerator || rateLimit.ipKeyGenerator,
    handler: (req, res, next, options) => {
      let logMessage = `RATE LIMIT HIT: Type: ${type}`;
      if (type === "User-based") {
        const userId = req.user ? req.user.id : "N/A";
        logMessage += `, UserID: ${userId}`;
      }
      logMessage += `, IP: ${req.ip}, Path: ${req.path}, Method: ${req.method}, Message: ${options.message}`;
      console.warn(logMessage);
      return res.status(options.statusCode).json({
        message: options.message,
      });
    },
  });
};


const globalRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes.",
  type: "IP-based",
  prefix: "global_rate_limit_",
});

const loginRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message:
    "Too many login attempts from this IP, please try again after 5 minutes.",
  type: "IP-based",
  prefix: "login_rate_limit_",
});

const tokenRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: "Too many token refresh requests, please try again after 1 minute.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user ? `token_refresh_${req.user.id}` : rateLimit.ipKeyGenerator(req),
  prefix: "token_rate_limit_",
});

const registerRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message:
    "Too many registration attempts from this IP, please try again after 15 minutes.",
  type: "IP-based",
  prefix: "register_rate_limit_",
});

const postsRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 50,
  message: "Too many post requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user ? `posts_retrieval_${req.user.id}` : rateLimit.ipKeyGenerator(req),
  prefix: "posts_rate_limit_",
});

const createPostRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many posts created. Please try again later.",
  type: "User-based",
  keyGenerator: (req) => 
    req.user ? `create_post_${req.user.id}` : rateLimit.ipKeyGenerator(req),
  prefix: "create_post_rate_limit_",
});


const sessionsRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000,
  max: 20,
  message: "Too many session requests, please try again after 1 minute.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user
      ? `sessions_retrieval_${req.user.id}`
      : rateLimit.ipKeyGenerator(req),
  prefix: "sessions_rate_limit_",
});

const logoutAllRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: "Too many logout all requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user ? `logout_all_${req.user.id}` : rateLimit.ipKeyGenerator(req),
  prefix: "logout_all_rate_limit_",
});

const logoutSpecificRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message:
    "Too many specific session logout requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user ? `logout_specific_${req.user.id}` : rateLimit.ipKeyGenerator(req),
  prefix: "logout_specific_rate_limit_",
});

const resendVerificationLimiter = createLimiter({
  windowMs: 10 * 60 * 1000, 
  max: 2, 
  message:
    "Too many resend verification requests. Please try again after 10 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.body.email
      ? `resend_verification_${req.body.email}`
      : rateLimit.ipKeyGenerator(req),
  prefix: "resend_verification_rate_limit_",
});

const changePasswordLimiter = createLimiter({
  windowMs: 30 * 60 * 1000, 
  max: 3, 
  message:
    "Too many password change attempts. Please try again after 30 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user?.sub
      ? `change_password_${req.user.sub}`
      : rateLimit.ipKeyGenerator(req), 
  prefix: "change_password_rate_limit_",
});

const forgotPasswordLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message:
    "Too many password reset requests. Please try again after 15 minutes.",
  type: "User-based",
  keyGenerator: (req) =>
    req.body.email
      ? `forgot_password_${req.body.email}`
      : rateLimit.ipKeyGenerator(req),
  prefix: "forgot_password_rate_limit_",
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