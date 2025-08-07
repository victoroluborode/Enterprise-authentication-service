require("dotenv").config();
const express = require("express");
const router = express.Router();
const registerUser = require("../services/userService");
const {
  registerValidation,
  loginValidation,
  tokenValidation,
  postValidation,
  changePasswordValidation,
} = require("../utils/validation");
const { sanitizeFields } = require("../utils/sanitization");
const { authenticateToken } = require("../middleware/auth");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {
  createAccessToken,
  createRefreshToken,
  verifyRefreshTokens,
} = require("../services/Tokenservice");
const { decodeJwt } = require("../utils/jwt");
const {
  loginRateLimiter,
  tokenRateLimiter,
  registerRateLimiter,
  postsRateLimiter,
  createPostRateLimiter,
  sessionsRateLimiter,
  logoutAllRateLimiter,
  logoutSpecificRateLimiter,
  resendVerificationLimiter,
  changePasswordLimiter,
} = require("../middleware/ratelimiter");
const {
  createEmailToken,
  verifyEmailToken,
  requireEmailVerification,
} = require("../services/emailTokenService");
const verificationEmailTemplate = require("../utils/template");

router.post(
  "/register",
  registerValidation,
  sanitizeFields(["email", "password", "fullname", "deviceId"]),
  registerRateLimiter,
  async (req, res) => {
    const { email, password, fullname, deviceId } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];

    try {
      const existingUser = await prisma.user.findUnique({
        where: { email: email },
      });

      console.log(existingUser);

      if (existingUser) {
        return res.status(400).json({
          message: "User already exists",
        });
      }

      const { userWithRoles, verificationlink } = await registerUser(
        email,
        password,
        fullname
      );
      console.log(verificationlink);
      const userRoles = userWithRoles.roles.map(
        (userRole) => userRole.role.name
      );

      const accessToken = await createAccessToken(userWithRoles);
      const refreshToken = await createRefreshToken(
        userWithRoles,
        deviceId,
        ipAddress,
        userAgent
      );

      const decodedPayload = decodeJwt(accessToken);
      console.log("Decoded JWT Payload:", decodedPayload);

      const decodedPayloadRefresh = decodeJwt(refreshToken.token);
      console.log("Decoded Refresh JWT Payload:", decodedPayloadRefresh);

      const userResponse = {
        id: userWithRoles.id,
        email: userWithRoles.email,
        fullname: userWithRoles.fullname,
      };

      res.status(201).json({
        success: true,
        message: `User registered successfully.`,
        verificationLink: verificationlink,
        accessToken,
        refreshToken: refreshToken.token,
        user: userResponse,
        roles: userRoles,
      });
    } catch (err) {
      console.log("Registration error:", err);
      res.status(500).json({
        error: "Server error",
      });
    }
  }
);

router.get("/verify-email", verifyEmailToken, async (req, res) => {
  try {
    return res.status(200).json({
      message: "Email successfully verified ✅",
    });
  } catch (err) {
    return res.status(500).json({
      error: "Server error",
    });
  }
});

router.post(
  "/resend-verification-email",
  resendVerificationLimiter,
  async (req, res) => {
    const email = req.body.email;
    try {
      const user = await prisma.user.findUnique({
        where: {
          email: email,
        },
      });

      if (!user) {
        return res.status(404).json({
          message: "User not found",
        });
      }

      if (user.emailVerified) {
        return res.status(400).json({
          message: "Email already verified",
        });
      }

      await prisma.emailVerificationToken.deleteMany({
        where: { userId: user.id },
      });

      const emailToken = await createEmailToken(user.id);
      const verificationlink = `http://localhost:3000/api/auth/verify-email?token=${emailToken}`;
      const html = verificationEmailTemplate(verificationlink);

      await sendEmail({
        to: email,
        subject: "Verify your email",
        html: html,
      });

      res.status(200).json({
        message: "Verification email resent successfully",
        verificationlink: verificationlink,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Server error",
      });
    }
  }
);

router.post(
  "/post",
  authenticateToken,
  requireEmailVerification,
  createPostRateLimiter,
  postValidation,
  sanitizeFields(["title", "content"]),
  async (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.sub;
    try {
      const newPost = await prisma.post.create({
        data: {
          title: title,
          content: content,
          userId: userId,
        },
      });

      res.status(201).json({
        message: "Post created successfully",
        post: newPost,
      });
    } catch (err) {
      res.status(500).json({
        error: "Failed to create post",
      });
    }
  }
);

router.post(
  "/change-password",
  authenticateToken,
  changePasswordLimiter,
  changePasswordValidation,
  async (req, res) => {
    try {
      const { currentpassword, newpassword } = req.body;
      const userId = req.user.sub;

      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      const password = user.password;
      const doesPasswordMatch = await bcrypt.compare(currentpassword, password);

      if (!doesPasswordMatch) {
        return res.status(401).json({
          message: "Password is incorrect",
        });
      }

      const hashedNewPassword = await bcrypt.hash(newpassword, 10);

      await prisma.user.update({
        where: {id: userId},
        data: {
          password: hashedNewPassword,
        },
      });

      res.status(200).json({
        message: "Password changed successfully",
      });

    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: "Server error",
      });
    }
  }
);

router.get("/posts", authenticateToken, postsRateLimiter, async (req, res) => {
  const userId = req.user.sub;
  try {
    const posts = await prisma.post.findMany({
      where: { userId: userId },
    });
    res.status(200).json({
      message: "Access Granted",
      posts: posts,
    });
  } catch (err) {
    console.error("error:", err);
    res.status(500).json({
      error: "server error",
      message: "An unexpected error occurred while getting posts",
    });
  }
});

router.get(
  "/sessions",
  authenticateToken,
  sessionsRateLimiter,
  async (req, res) => {
    try {
      const userId = req.user.sub;
      const sessions = await prisma.refreshToken.findMany({
        where: {
          userId: userId,
          expiresAt: {
            gte: new Date(),
          },
        },
        select: {
          jti: true,
          deviceId: true,
          ipAddress: true,
          userAgent: true,
          expiresAt: true,
          createdAt: true,
        },
      });

      res.status(200).json({
        message: "Sessions retrieved successfully",
        sessions: sessions,
      });
    } catch (err) {
      console.error("Error retrieving sessions:", err);
      res.status(500).json({
        error: "Server error",
        message: "An unexpected error occurred while retrieving sessions",
      });
    }
  }
);

router.post(
  "/login",
  loginValidation,
  sanitizeFields(["email", "password", "deviceId"]),
  loginRateLimiter,
  async (req, res) => {
    const { email, password, deviceId } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];
    try {
      const user = await prisma.user.findUnique({
        where: { email: email },
      });
      if (!user) {
        return res.status(401).json({
          message: "Invalid email or password",
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({
          message: "Invalid email or password",
        });
      }

      const accesstoken = await createAccessToken(user);
      const refreshtoken = await createRefreshToken(
        user,
        deviceId,
        ipAddress,
        userAgent
      );

      const decodedPayload = decodeJwt(accesstoken);
      console.log("Decoded JWT Payload:", decodedPayload);

      const userResponse = {
        id: user.id,
        email: user.email,
        fullname: user.fullname,
      };

      res.status(200).json({
        accesstoken: accesstoken,
        refreshtoken: refreshtoken,
        message: "Login successful",
        user: userResponse,
      });
    } catch (err) {
      console.log("Login error:", err);
      res.status(500).json({
        error: "Server error",
      });
    }
  }
);

router.post(
  "/token",
  tokenValidation,
  verifyRefreshTokens,
  tokenRateLimiter,
  async (req, res) => {
    const jtiOldToken = req.jtiOldToken;
    const userId = req.user.id;
    const deviceId = req.user.deviceId;

    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];
    try {
      const accesstoken = await createAccessToken(req.user);
      const refreshtoken = await createRefreshToken(
        req.user,
        deviceId,
        ipAddress,
        userAgent
      );

      const decodedPayload = decodeJwt(accesstoken);
      console.log("Decoded JWT Payload:", decodedPayload);

      await prisma.refreshToken.delete({
        where: {
          userId: userId,
          jti: jtiOldToken,
        },
      });

      res.status(200).json({
        accesstoken: accesstoken,
        refreshtoken: refreshtoken,
        message: "Tokens refreshed successfully",
      });
    } catch (err) {
      console.log("Token refresh error:", err);
      res.status(500).json({
        error: "server error",
        message: "An unexpected error occurred during token refresh.",
      });
    }
  }
);

router.delete(
  "/logout",
  authenticateToken,
  logoutSpecificRateLimiter,
  async (req, res) => {
    const userId = req.user.id;
    const jti = req.user.jti;

    if (!userId || !jti) {
      return res
        .status(400)
        .json({ message: "Invalid token payload for logout." });
    }

    try {
      await prisma.refreshToken.deleteMany({
        where: {
          userId: userId,
          jti: jti,
        },
      });

      res
        .status(200)
        .json({ message: "Logout successful for current session." });
    } catch (err) {
      console.error("Error during logout:", err);
      res.status(500).json({ error: "Server error during logout." });
    }
  }
);

router.delete(
  "/sessions",
  authenticateToken,
  logoutAllRateLimiter,
  async (req, res) => {
    const userId = req.user.sub;
    try {
      await prisma.refreshToken.deleteMany({
        where: {
          userId: userId,
        },
      });
      await prisma.user.update({
        where: { id: userId },
        data: { tokenVersion: { increment: 1 } },
      });
      res.status(200).json({
        message: "Logged out from all devices",
      });
    } catch (err) {
      res.status(500).json({
        error: "Server error",
        message: "An unexpected error occurred during logout all",
      });
    }
  }
);

router.delete(
  "/sessions/:jti",
  authenticateToken,
  logoutSpecificRateLimiter,
  async (req, res) => {
    const jti = req.params.jti;
    const userId = req.user.sub;

    if (!jti) {
      return res
        .status(400)
        .json({ message: "Session ID (jti) is required in the path." });
    }
    try {
      const deletedToken = await prisma.refreshToken.deleteMany({
        where: {
          jti: jti,
          userId: userId,
        },
      });

      if (deletedToken.count === 0) {
        return res.status(404).json({
          message: "Session not found or already deleted",
        });
      }
      res.status(200).json({
        message: "Session deleted successfully",
      });
    } catch (err) {
      console.error("Error deleting session:", err);
      res.status(500).json({
        error: "Server error",
        message: "An unexpected error occurred while deleting the session",
      });
    }
  }
);

module.exports = router;
