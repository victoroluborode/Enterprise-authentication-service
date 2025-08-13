const winston = require("winston");
const path = require("path");
const DailyRotateFile = require('winston-daily-rotate-file');
require("dotenv").config();

const myFormat = winston.format.printf(
  ({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
  }
);

const getModuleLabel = (callingModule) => {
  return callingModule
    ? path.relative(process.cwd(), callingModule.filename)
    : "APP";
};

const dailyRotateFileTransport = new DailyRotateFile({
    filename: path.join("logs", "application-%DATE%.log"),
    datePattern: "YYYY-MM-DD",
    zippedArchive: true,
    maxSize: "20m",
    maxFiles: "14d",
    format: winston.format.json()
}) 

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
      format: winston.format.json(),
    }),

    new winston.transports.File({
      filename: path.join("logs", "combined.log"),
      format: winston.format.json(),
    }),

    new winston.transports.Console({
      level: "error",
    }),

    dailyRotateFileTransport,
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
