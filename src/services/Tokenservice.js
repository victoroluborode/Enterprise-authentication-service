const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
const { addDays } = require("date-fns");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();
const prisma = new PrismaClient();

const createAccessToken = async (user) => {
  const roleNames = user.roles
    ? user.roles.map((userRole) => userRole.role.name)
    : [];
  const payload = {
    sub: user.id,
    roles: roleNames,
    tokenVersion: user.tokenVersion || 0,
  }

  const accesstoken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "10m" });
  return accesstoken;
}

const createRefreshToken = async (user, deviceId, ipAddress, userAgent) => {
  const ttlDays = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
  const expiresAt = addDays(new Date(), ttlDays);
  const jti = uuidv4();
  // const deviceId = uuidv4();
  const payload = {
    sub: user.id,
    jti,
    deviceId,
  };
  const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: `${ttlDays}m`,
  });


  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      jti,
      expiresAt,
      deviceId,
      ipAddress: ipAddress,
      userAgent: userAgent
    },
  });
  return {
    token: refreshToken,
    jti: jti
  };
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
    const existingDeviceId = decoded.deviceId;

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
        jti: decoded.jti,
        deviceId: existingDeviceId,
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


module.exports = { createAccessToken,createRefreshToken, verifyRefreshTokens };
