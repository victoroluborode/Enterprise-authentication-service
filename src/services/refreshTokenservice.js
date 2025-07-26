const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const { addDays } = require("date-fns");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();
const prisma = new PrismaClient();

const createRefreshToken = async (user) => {
  const ttlDays = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
  const expiresAt = addDays(new Date(), ttlDays);
  const jti = uuidv4();
  const payload = {
    sub: user.id,
    email: user.email,
    jti,
  };
  const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: `${ttlDays}m`,
  });


  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      jti,
      expiresAt,
    },
  });
  return refreshToken;
};


const verifyRefreshTokens = async (req, res, next) => {
  const refreshToken = req.body.token;
  try {
    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh token required",
      });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const userId = decoded.sub;
    const jti = decoded.jti;

    req.jtiOldToken = jti;

    const storedJtiRecord = await prisma.refreshToken.findFirst({
      where: {
        userId,
        jti,
        expiresAt: {
          gte: new Date(),
        },
      },
    });

    if (!storedJtiRecord) {
      return res.status(403).json({
        message: "Invalid or revoked refresh token",
      });
    }

      req.user = {
        id: decoded.sub,
        email: decoded.email,
        jti: decoded.jti
      };

    next();
  } catch (err) {
    return res
      .status(403)
      .json({
        message: "Invalid or revoked refresh token",
        error: err.message,
      });
  }
};


module.exports = { createRefreshToken, verifyRefreshTokens };
