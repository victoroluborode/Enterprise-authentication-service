const bcrypt = require("bcrypt");
const crypto = require("crypto");
const prisma = require("../config/prismaClient")
const {v4: uuidv4} = require('uuid')

const createEmailToken = async (userId) => {
  const tokenId = uuidv4();
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const hashedToken = await bcrypt.hash(token, 10);

  await prisma.emailVerificationToken.create({
    data: {
      userId: userId,
      tokenId: tokenId,
      token: hashedToken,
      expiresAt: expiresAt,
    },
  });
  return {token, tokenId};
};

const verifyEmailToken = async (req, res, next) => {
  try {
    const {tokenId, token} = req.query;
    
    await prisma.emailVerificationToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    const emailToken = await prisma.emailVerificationToken.findUnique({
      where: {
        tokenId: tokenId
      },
    });

    if (!emailToken || emailToken.expiresAt < new Date()) {
      console.log("LOG: Token not found or expired. Returning early.");
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

     console.log("LOG: Token found. Proceeding with verification.");
    const isTokenValid = await bcrypt.compare(token, emailToken.token);
    if (!isTokenValid) {
      return res.status(401).json({
        message: "Invalid token",
      });
    }

    

    const user = await prisma.user.findUnique({
      where: { id: emailToken.userId }
    });

    if (user.emailVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    await prisma.user.update({
      where: {
        id: emailToken.userId,
      },
      data: {
        emailVerified: true,
      },
    });

    console.log("LOG: Deleting token with ID:", emailToken.id);
    await prisma.emailVerificationToken.delete({
      where: {
        id: emailToken.id,
      },
    });
    console.log("LOG: Token delete successful.");
    
    res.status(200).json({
      message: "Email verified successful",
    });
  } catch (err) {
    if (err.code === "P2025") {
      console.error(
        "LOG: P2025 error caught. Something went wrong between finding the token and deleting it."
      );
    }
    console.error(err);
    res.status(500).json({
      error: "Server error",
    });
  }
};

const requireEmailVerification = async (req, res, next) => {
  const userId = req.user.id;

  
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.emailVerified) {
      res.status(400).json({
        message: "Email is not verified",
      });
    }

    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Server error",
    });
  }
};

module.exports = { createEmailToken, verifyEmailToken, requireEmailVerification };
