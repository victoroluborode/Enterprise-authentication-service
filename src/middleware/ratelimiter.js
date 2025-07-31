const rateLimit = require('express-rate-limit');


const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  message: "Too many requests from this IP, please try again after 15 minutes.",
  statusCode: 429,
  headers: true,
  handler: (req, res, next, options) => {
    console.warn(`RATE LIMIT: Too many requests from this IP: ${req.ip}`);
    res.status(options.statusCode).json({
      message: options.message,
    });
  },
});

const loginRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message:
        "Too many login attempts from this IP, please try again after 5 minutes.",
    statusCode: 429,
    headers: true,
    handler: (req, res, next, options) => {
        console.warn(`RATE LIMIT: Login attempts exceeded for IP: ${req.ip}`);
        res.status(options.statusCode).json({
            message: options.message
        })
  }
});

const tokenRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: "Too many token refresh requests, please try again after 1 minute.",
  statusCode: 429,
  headers: true,
  handler: (req, res, next, options) => {
    console.warn(
      `RATE LIMIT: Token refresh attempts exceeded for IP: ${req.ip}`
    );
    res.status(options.statusCode).json({
      message: options.message,
    });
  },
});

module.exports =  {globalRateLimiter, loginRateLimiter, tokenRateLimiter}