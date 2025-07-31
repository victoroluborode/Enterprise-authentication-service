const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const redisClient = require('../config/redisClient');

const store = new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args),
})



const createLimiter = ({
  windowMs,
  max,
  message,
  type = "IP-based",
  keyGenerator,
}) => {
  return rateLimit({
    windowMs,
    max,
    message,
    statusCode: 429,
    headers: true,
    store: store,
    keyGenerator: keyGenerator || ((req) => req.ip),
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
});

const loginRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000, 
  max: 5, 
  message:
    "Too many login attempts from this IP, please try again after 5 minutes.",
  type: "IP-based",
});

const tokenRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000, 
  max: 10, 
  message: "Too many token refresh requests, please try again after 1 minute.",
  type: "User-based",
  keyGenerator: (req) => (req.user ? `token_refresh_${req.user.id}` : req.ip),
});

const registerRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message:
    "Too many registration attempts from this IP, please try again after 15 minutes.",
  type: "IP-based",
});

const postsRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000, 
  max: 50, 
  message: "Too many post requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) => (req.user ? `posts_retrieval_${req.user.id}` : req.ip),
});

const sessionsRateLimiter = createLimiter({
  windowMs: 1 * 60 * 1000, 
  max: 20, 
  message: "Too many session requests, please try again after 1 minute.",
  type: "User-based",
  keyGenerator: (req) =>
    req.user ? `sessions_retrieval_${req.user.id}` : req.ip,
});

const logoutAllRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000, 
  max: 3, 
  message: "Too many logout all requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) => (req.user ? `logout_all_${req.user.id}` : req.ip),
});

const logoutSpecificRateLimiter = createLimiter({
  windowMs: 5 * 60 * 1000, 
  max: 5,
  message:
    "Too many specific session logout requests, please try again after 5 minutes.",
  type: "User-based",
  keyGenerator: (req) => (req.user ? `logout_specific_${req.user.id}` : req.ip),
});

module.exports = {
  globalRateLimiter,
  loginRateLimiter,
  tokenRateLimiter,
  registerRateLimiter,
  postsRateLimiter,
  sessionsRateLimiter,
  logoutAllRateLimiter,
  logoutSpecificRateLimiter,
};