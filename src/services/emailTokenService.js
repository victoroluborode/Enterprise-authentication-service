const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const createEmailToken = async (userId) => {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const hashedToken = await bcrypt.hash(token, 10);

  await prisma.emailVerificationToken.create({
    data: {
      userId: userId,
      token: hashedToken,
      expiresAt: expiresAt,
    },
  });
  return token;
};

const verifyEmailToken = async (req, res, next) => {
  try {
    const token = req.query.token;
    if (!token) {
      return res.status(401).json({
        message: "Token required",
      });
    }

    await prisma.emailVerificationToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
    
    const emailTokens = await prisma.emailVerificationToken.findMany({
      where: {
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    let matchedToken;

    for (let dbToken of emailTokens) {
      const match = await bcrypt.compare(token, dbToken.token);
      if (match) {
        matchedToken = dbToken;
        break;
      }
    }

    if (!matchedToken) {
      return res.status(401).json({
        message: "Invalid token",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: matchedToken.userId },
    });

    if (user.emailVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    await prisma.user.update({
      where: {
        id: matchedToken.userId,
      },
      data: {
        emailVerified: true,
      },
    });

    await prisma.emailVerificationToken.delete({
      where: {
        id: matchedToken.id,
      },
    });

    res.status(200).json({
      message: "Email verified successful",
    });

    
  } catch (err) {
    res.status(500).json({
      error: "Server error",
    });
  }
};

module.exports = { createEmailToken, verifyEmailToken };
