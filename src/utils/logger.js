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
        
    ]
})