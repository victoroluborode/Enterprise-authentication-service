require("dotenv").config();
const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const registerUser = require("../services/userService");
const {
  registerValidation,
  loginValidation,
  tokenValidation,
  postValidation,
  changePasswordValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
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
  forgotPasswordLimiter,
} = require("../middleware/ratelimiter");
const {
  createEmailToken,
  verifyEmailToken,
  requireEmailVerification,
} = require("../services/emailTokenService");
const {
  verificationEmailTemplate,
  resetPasswordEmailTemplate,
} = require("../utils/template");
const { sendEmail } = require("../utils/emailservice");
const { hasPermissions, hasRole } = require("../middleware/rolePermissions");
const AppError = require("../utils/app-error");
const logger = require("../utils/logger");

router.post(
  "/register",
  registerValidation,
  sanitizeFields(["email", "password", "fullname"]),
  registerRateLimiter,
  async (req, res, next) => {
    const { email, password, fullname } = req.body;
    const deviceId = req.headers['x-device-id'];
    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];

    try {
      const existingUser = await prisma.user.findUnique({
        where: { email: email },
      });

      if (existingUser) {
        logger.warn("Registration attempt with existing email", {
          email: email,
        });
        return next(new AppError("User already exists", 400));
      }

      const { userWithRoles, verificationlink } = await registerUser(
        email,
        password,
        fullname
      );

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

      const decodedPayloadRefresh = decodeJwt(refreshToken.token);

      const userResponse = {
        id: userWithRoles.id,
        email: userWithRoles.email,
        fullname: userWithRoles.fullname,
      };

      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      })

      res.status(201).json({
        success: true,
        message: `User registered successfully.`,
        verificationLink: verificationlink,
        accessToken: accessToken,
        user: userResponse,
        roles: userRoles,
      });
      logger.info("User registered successfully", {
        userId: userWithRoles.id,
        email: userWithRoles.email,
      });
    } catch (err) {
      logger.error("User registration failed", err);
      next(err);
    }
  }
);

router.get("/verify-email", verifyEmailToken, async (req, res, next) => {
  try {
    res.status(200).json({
      message: "Email successfully verified ",
    });
    logger.info("Email verified successfully", { userId: req.user.id });
  } catch (err) {
    logger.error("Email verification failed", err);
    next(err);
  }
});

router.post(
  "/resend-verification-email",
  resendVerificationLimiter,
  async (req, res, next) => {
    const email = req.body.email;
    try {
      const user = await prisma.user.findUnique({
        where: {
          email: email,
        },
      });

      if (!user) {
        logger.warn("Resend verification email attempt for non-existent user", {
          email: email,
        });
        return next(new AppError("User not found", 404));
      }

      if (user.emailVerified) {
        logger.warn(
          "Resend verification email attempt for already verified user",
          { email: email }
        );
        return next(new AppError("Email already verified", 400));
      }

      await prisma.emailVerificationToken.deleteMany({
        where: { userId: user.id },
      });

      const { token, tokenId } = await createEmailToken(user.id);
      const verificationlink = `http://localhost:3000/api/auth/verify-email?token=${token}&tokenId=${tokenId}`;
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
      logger.info("Verification email resent", {
        userId: user.id,
        email: email,
      });
    } catch (err) {
      logger.error("Resending verification email failed", err);
      next(err);
    }
  }
);

router.post(
  "/post",
  authenticateToken,
  hasPermissions(["post:create"]),
  requireEmailVerification,
  createPostRateLimiter,
  postValidation,
  sanitizeFields(["title", "content"]),
  async (req, res, next) => {
    const { title, content } = req.body;
    const userId = req.user.id;
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
      logger.info("Post created successfully", {
        postId: newPost.id,
        userId: userId,
      });
    } catch (err) {
      logger.error("Post creation failed", err);
      next(err);
    }
  }
);

router.post(
  "/change-password",
  authenticateToken,
  changePasswordLimiter,
  changePasswordValidation,
  async (req, res, next) => {
    try {
      const { currentpassword, newpassword } = req.body;
      const userId = req.user.id;

      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      const password = user.password;
      const doesPasswordMatch = await bcrypt.compare(currentpassword, password);

      if (!doesPasswordMatch) {
        logger.warn("Change password attempt with incorrect current password", {
          userId: userId,
        });
        return next(new AppError("Password is incorrect", 401));
      }

      const hashedNewPassword = await bcrypt.hash(newpassword, 10);

      await prisma.user.update({
        where: { id: userId },
        data: {
          password: hashedNewPassword,
        },
      });

      res.status(200).json({
        message: "Password changed successfully",
      });
      logger.info("Password changed successfully", { userId: userId });
    } catch (err) {
      logger.error("Change password failed", err);
      next(err);
    }
  }
);

router.post(
  "/forgot-password",
  forgotPasswordLimiter,
  forgotPasswordValidation,
  async (req, res, next) => {
    const { email } = req.body;
    try {
      const user = await prisma.user.findUnique({
        where: { email: email },
      });

      if (!user) {
        logger.info("Forgot password request for non-existent email", {
          email: email,
        });
        return next(
          new AppError(
            "If that email is associated with an account, you’ll receive a reset link shortly.",
            200
          )
        );
      }

      const userId = user.id;

      await prisma.passwordResetToken.deleteMany({
        where: { userId },
      });

      const tokenId = uuidv4();
      const rawtoken = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
      const passwordResetToken = await bcrypt.hash(rawtoken, 10);

      await prisma.passwordResetToken.create({
        data: {
          userId: userId,
          tokenId: tokenId,
          token: passwordResetToken,
          expiresAt: expiresAt,
        },
      });

      const resetPasswordLink = `http://localhost:3000/api/auth/reset-password?tokenId=${tokenId}&token=${rawtoken}`;
      const html = resetPasswordEmailTemplate(resetPasswordLink);

      await sendEmail({
        to: email,
        subject: "Reset your password",
        html: html,
      });

      res.status(200).json({
        message:
          "If an account with that email exists, a password reset link has been sent.",
        resetPasswordLink: resetPasswordLink,
      });
      logger.info("Password reset link sent", { email: email, userId: userId });
    } catch (err) {
      logger.error("Forgot password process failed", err);
      next(err);
    }
  }
);

router.post(
  "/reset-password",
  resetPasswordValidation,
  async (req, res, next) => {
    try {
      const { tokenId, token } = req.query;
      const { newpassword } = req.body;

      await prisma.passwordResetToken.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });

      const passwordToken = await prisma.passwordResetToken.findUnique({
        where: {
          tokenId: tokenId,
        },
      });

      if (!passwordToken || passwordToken.expiresAt < new Date()) {
        logger.warn(
          "Attempt to use an invalid or expired password reset token",
          { tokenId: tokenId }
        );
        return next(new AppError("Invalid or expired token", 401));
      }

      const isTokenValid = await bcrypt.compare(token, passwordToken.token);
      if (!isTokenValid) {
        logger.warn("Attempt to use an invalid password reset token", {
          tokenId: tokenId,
        });
        return next(new AppError("Invalid token", 401));
      }

      const userId = passwordToken.userId;
      const hashedNewPassword = await bcrypt.hash(newpassword, 10);

      await prisma.user.update({
        where: { id: userId },
        data: {
          password: hashedNewPassword,
        },
      });

      await prisma.refreshToken.deleteMany({
        where: {
          userId: userId,
        },
      });

      await prisma.user.update({
        where: { id: userId },
        data: { tokenVersion: { increment: 1 } },
      });

      await prisma.passwordResetToken.delete({ where: { tokenId: tokenId } });

      res.status(200).json({
        message: "Password reset successful",
      });
      logger.info("Password reset successfully", { userId: userId });
    } catch (err) {
      logger.error("Password reset failed", err);
      next(err);
    }
  }
);

router.get(
  "/posts",
  authenticateToken,
  hasPermissions(["post:read"]),
  postsRateLimiter,
  async (req, res, next) => {
    try {
      const posts = await prisma.post.findMany({
        include: {
          user: {
            select: {
              fullname: true,
              email: true,
            },
          },
        },
      });
      res.status(200).json({
        message: "Access Granted",
        posts: posts,
      });
      logger.info("Posts retrieved successfully", {
        userId: req.user.id,
        count: posts.length,
      });
    } catch (err) {
      logger.error("Retrieving posts failed", err);
      next(err);
    }
  }
);

router.put(
  "/posts/:postId",
  authenticateToken,
  hasPermissions(["post:update_own", "post:update"]),
  async (req, res, next) => {
    const { postId } = req.params;
    const { title, content } = req.body;

    const existingPost = await prisma.post.findUnique({
      where: { id: parseInt(postId) },
    });

    if (!existingPost) {
      logger.warn("Attempt to update non-existent post", {
        postId: postId,
        userId: req.user.id,
      });
      return next(new AppError("Post not found.", 404));
    }

    try {
      const updatedPost = await prisma.post.update({
        where: { id: parseInt(postId) },
        data: {
          title: title || existingPost.title,
          content: content || existingPost.content,
        },
      });
      res.status(200).json(updatedPost);
      logger.info("Post updated successfully", {
        postId: updatedPost.id,
        userId: req.user.id,
      });
    } catch (err) {
      logger.error("Updating post failed", err);
      next(err);
    }
  }
);

router.delete(
  "/posts/:postId",
  authenticateToken,
  hasPermissions(["post:delete_own", "post:delete"]),
  async (req, res, next) => {
    const { postId } = req.params;

    const existingPost = await prisma.post.findUnique({
      where: { id: parseInt(postId) },
    });

    if (!existingPost) {
      logger.warn("Attempt to delete non-existent post", {
        postId: postId,
        userId: req.user.id,
      });
      return next(new AppError("Post not found.", 404));
    }

    try {
      await prisma.post.delete({
        where: { id: parseInt(postId) },
      });
      res.status(200).json({ message: "Post deleted successfully." });
      logger.info("Post deleted successfully", {
        postId: postId,
        userId: req.user.id,
      });
    } catch (err) {
      logger.error("Deleting post failed", err);
      next(err);
    }
  }
);

router.get(
  "/sessions",
  authenticateToken,
  sessionsRateLimiter,
  async (req, res, next) => {
    try {
      const userId = req.user.id;
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
      logger.info("User sessions retrieved", {
        userId: userId,
        count: sessions.length,
      });
    } catch (err) {
      logger.error("Retrieving sessions failed", err);
      next(err);
    }
  }
);

router.post(
  "/login",
  loginValidation,
  sanitizeFields(["email", "password", "deviceId"]),
  loginRateLimiter,
  async (req, res, next) => {
    const { email, password } = req.body;
    const deviceId = req.headers['x-device-id']
    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];
    try {
      const user = await prisma.user.findUnique({
        where: { email: email },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: {
                    include: {
                      permission: true,
                    },
                  },
                },
              },
            },
          },
        },
      });
      if (!user) {
        logger.warn("Login attempt with invalid email", {
          email: email,
          deviceId: deviceId,
        });
        return next(new AppError("Invalid email or password", 401));
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        logger.warn("Login attempt with invalid password", {
          email: email,
          deviceId: deviceId,
        });
        return next(new AppError("Invalid email or password", 401));
      }

      const accessToken = await createAccessToken(user);
      const refreshToken = await createRefreshToken(
        user,
        deviceId,
        ipAddress,
        userAgent
      );

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      })

      const userResponse = {
        id: user.id,
        email: user.email,
        fullname: user.fullname,
      };

      res.status(200).json({
        accesstoken: accessToken,
        message: "Login successful",
        user: userResponse,
      });
      logger.info("User logged in successfully", {
        userId: user.id,
        deviceId: deviceId,
      });
    } catch (err) {
      logger.error("User login failed", err);
      next(err);
    }
  }
);

router.post(
  "/token",
  tokenValidation,
  verifyRefreshTokens,
  tokenRateLimiter,
  async (req, res, next) => {
    const jtiOldToken = req.jtiOldToken;
    const userId = req.user.id;
    const deviceId = req.user.deviceId;

    const ipAddress = req.ip;
    const userAgent = req.headers["user-agent"];
    try {
      const userWithRoles = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: {
                    include: {
                      permission: true,
                    },
                  },
                },
              },
            },
          },
        },
      });

      const accesstoken = await createAccessToken(userWithRoles);
      const refreshtoken = await createRefreshToken(
        req.user,
        deviceId,
        ipAddress,
        userAgent
      );

      const decodedPayload = decodeJwt(accesstoken);

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
      logger.info("Tokens refreshed successfully", {
        userId: userId,
        deviceId: deviceId,
      });
    } catch (err) {
      logger.error("Token refresh failed", err);
      next(err);
    }
  }
);

router.delete(
  "/logout",
  authenticateToken,
  logoutSpecificRateLimiter,
  async (req, res, next) => {
    const userId = req.user.id;
    const jti = req.user.jti;

    if (!userId || !jti) {
      logger.warn("Logout attempt with invalid token payload", {
        userId: userId,
        jti: jti,
      });
      return next(new AppError("Invalid token payload for logout.", 400));
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
      logger.info("User logged out of current session", {
        userId: userId,
        jti: jti,
      });
    } catch (err) {
      logger.error("Logout of specific session failed", err);
      next(err);
    }
  }
);

router.delete(
  "/sessions",
  authenticateToken,
  logoutAllRateLimiter,
  async (req, res, next) => {
    const userId = req.user.id;
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
      logger.info("User logged out of all sessions", { userId: userId });
    } catch (err) {
      logger.error("Logout of all sessions failed", err);
      next(err);
    }
  }
);

router.delete(
  "/sessions/:jti",
  authenticateToken,
  logoutSpecificRateLimiter,
  async (req, res, next) => {
    const jti = req.params.jti;
    const userId = req.user.id;

    if (!jti) {
      logger.warn("Attempt to delete session without jti in path", {
        userId: userId,
      });
      return next(
        new AppError("Session ID (jti) is required in the path.", 400)
      );
    }
    try {
      const deletedToken = await prisma.refreshToken.deleteMany({
        where: {
          jti: jti,
          userId: userId,
        },
      });

      if (deletedToken.count === 0) {
        logger.warn("Attempt to delete non-existent session", {
          jti: jti,
          userId: userId,
        });
        return next(new AppError("Session not found or already deleted", 404));
      }
      res.status(200).json({
        message: "Session deleted successfully",
      });
      logger.info("Specific session deleted successfully", {
        userId: userId,
        jti: jti,
      });
    } catch (err) {
      logger.error("Deleting a specific session failed", err);
      next(err);
    }
  }
);

module.exports = router;
