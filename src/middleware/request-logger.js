const logger = require("../utils/logger");

const requestLogger = (req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;

    let level = "info";
    if (res.statusCode >= 500) {
      level = "error";
    } else if (res.statusCode >= 400) {
      level = "warn";
    }

    logger.log(
      level,
      `${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`,
      {
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        duration: `${duration}ms`,
        ip: req.ip,
      }
    );
  });

  next();
};

module.exports = requestLogger;
