// prisma.js
const { PrismaClient } = require("@prisma/client");
const logger = require("../utils/logger");

const prismaClient = new PrismaClient();

(async () => {
  try {
    await prisma.$connect();
    logger.info("Prisma client connected successfully to the database.");
  } catch (err) {
    logger.error("Prisma client connection failed:", err);
  }
})();

module.exports = prisma;
