const winston = require('winston');
const path = require('path');
require('dotenv').config();

const myFormat = winston.format.printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`
});

const getModuleLabel = (callingModule) => {
    return callingModule ? path.relative(process.cwd(), callingModule.filename) : 'APP';
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || "debug",
    format: winston.format.combine(
        winston.format.label({ label: getModuleLabel(module) }),
        winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
        myFormat
    ),
    defaultMeta: {},
    transports: [
        new winston.transports.File({
            filename: path.join("logs", "error.log"),
            level: "error",
        }),

        new winston.transports.File({
            filename: path.join("logs", "combined.log"),
        }),

        new winston.transports.Console({
            level: "error"
        }),
    ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

module.exports = logger;