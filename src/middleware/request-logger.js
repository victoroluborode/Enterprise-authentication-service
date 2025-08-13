const logger = require("../utils/logger");

const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
      const duration = Date.now() - start;
      const level = res.statusCode >= 400 ? 'error' : 'info';
    logger[level]({
      message: "Request completed",
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
    });
  });
  next();
};

module.exports = requestLogger;
