// src/routes/auth.js
require("dotenv").config();
const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const registerUser = require("../services/userService");
const {
  registerValidation,
  loginValidation,
  postValidation,
  changePasswordValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
} = require("../utils/validation");
const { startTimer } = require("../utils/timer");
const { sanitizeFields } = require("../utils/sanitization");
const { authenticateToken } = require("../middleware/auth");
const prisma = require("../config/prismaClient");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {
  createAccessToken,
  createRefreshToken,
  verifyRefreshTokens,
} = require("../services/Tokenservice");
const { decodeJwt } = require("../utils/jwt");
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
const { userInfo } = require("os");

  router.post(
    "/register",
    registerValidation,
    sanitizeFields(["email", "password", "fullname"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL register");
      const { email, password, fullname } = req.body;
      const deviceId = req.headers["x-device-id"];
      const ipAddress = req.ip;
      const userAgent = req.headers["user-agent"];

      try {
        const existingUser = await prisma.user.findUnique({
          where: { email }
        });
        timer.log("findUnique");

        if (existingUser) {
          logger.warn("Registration attempt with existing email", { email });
          return next(new AppError("User already exists", 400));
        }

        const { userWithRoles } = await registerUser(email, password, fullname);
        timer.log("registerUser");

        const userRoles = userWithRoles.roles.map(
          (userRole) => userRole.role.name
        );
        timer.log("roles mapping");

        const accessToken = await createAccessToken(userWithRoles);
        timer.log("createAccessToken");

        const refreshToken = await createRefreshToken(
          userWithRoles,
          deviceId,
          ipAddress,
          userAgent
        );
        timer.log("createRefreshToken");

        res.cookie("refreshToken", refreshToken.token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        res.status(201).json({
          message: `User registered successfully. Please check your email for a verification link`,
          accessToken,
          user: {
            id: userWithRoles.id,
            email: userWithRoles.email,
            fullname: userWithRoles.fullname,
          },
          roles: userRoles,
        });
        timer.log("response send");
        timer.end();

        logger.info("User registered successfully", {
          userId: userWithRoles.id,
          email: userWithRoles.email,
        });
      } catch (err) {
        logger.error("User registration failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- EMAIL VERIFICATION -------------------------
  router.get("/verify-email", verifyEmailToken, async (req, res, next) => {
    const timer = startTimer("TOTAL verify-email");
    try {
      res.status(200).json({ message: "Email successfully verified" });
      logger.info("Email verified successfully", { userId: req.user.id });
      timer.log("response send");
      timer.end();
    } catch (err) {
      logger.error("Email verification failed", err);
      timer.end();
      next(err);
    }
  });

  router.post(
    "/resend-verification-email",
    async (req, res, next) => {
      const timer = startTimer("TOTAL resend-verification-email");
      const email = req.body.email;
      try {
        const user = await prisma.user.findUnique({
          where: { email }
        });
        timer.log("findUnique");

        if (!user) {
          logger.warn(
            "Resend verification email attempt for non-existent user",
            {
              email,
            }
          );
          return next(new AppError("User not found", 404));
        }

        if (user.emailVerified) {
          logger.warn(
            "Resend verification email attempt for already verified user",
            { email }
          );
          return next(new AppError("Email already verified", 400));
        }

        await prisma.emailVerificationToken.deleteMany({
          where: { userId: user.id },
        });
        timer.log("deleteMany");

        const { token, tokenId } = await createEmailToken(user.id);
        timer.log("createEmailToken");
        const verificationlink = `http://localhost:3000/api/auth/verify-email?token=${token}&tokenId=${tokenId}`;
        const html = verificationEmailTemplate(verificationlink);

        await sendEmail({ to: email, subject: "Verify your email", html });
        timer.log("sendEmail");

        res.status(200).json({
          message: "Verification email resent successfully",
          verificationlink,
        });
        timer.log("response send");
        timer.end();

        logger.info("Verification email resent", { userId: user.id, email });
      } catch (err) {
        logger.error("Resending verification email failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- LOGIN -------------------------
  router.post(
    "/login",
    loginValidation,
    sanitizeFields(["email", "password", "deviceId"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL login");
      const { email, password } = req.body;
      const deviceId = req.headers["x-device-id"];
      const ipAddress = req.ip;
      const userAgent = req.headers["user-agent"];

      try {
        const user = await prisma.user.findUnique({
          where: { email },
          select: {
            id: true,
            email: true,
            fullname: true,
            password: true,
            roles: {
              select: {
                role: {
                  select: {
                    name: true,
                    permissions: {
                      select: { permission: { select: { name: true } } },
                    },
                  },
                },
              },
            },
          },
        });
        timer.log("findUnique");

        if (!user) {
          logger.warn("Login attempt with invalid email", { email, deviceId });
          return next(new AppError("Invalid email or password", 401));
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        timer.log("bcrypt.compare");
        if (!isPasswordValid) {
          logger.warn("Login attempt with invalid password", {
            email,
            deviceId,
          });
          return next(new AppError("Invalid email or password", 401));
        }

        const accessToken = await createAccessToken(user);
        timer.log("createAccessToken");
        const refreshToken = await createRefreshToken(
          user,
          deviceId,
          ipAddress,
          userAgent
        );
        timer.log("createRefreshToken");

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

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
        timer.log("response send");
        timer.end();

        logger.info("User logged in successfully", {
          userId: user.id,
          deviceId,
        });
      } catch (err) {
        logger.error("User login failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- TOKEN REFRESH -------------------------
  router.post(
    "/token",
    verifyRefreshTokens,
    async (req, res, next) => {
      const timer = startTimer("TOTAL token-refresh");
      const { jtiOldToken } = req;
      const { id: userId, deviceId } = req.user;
      const ipAddress = req.ip;
      const userAgent = req.headers["user-agent"];

      try {
        const userWithRoles = await prisma.user.findUnique({
          where: { id: userId },
          include: {
            roles: {
              include: {
                role: {
                  include: { permissions: { include: { permission: true } } },
                },
              },
            },
          },
        });
        timer.log("findUnique");

        const accessToken = await createAccessToken(userWithRoles);
        timer.log("createAccessToken");
        const refreshToken = await createRefreshToken(
          req.user,
          deviceId,
          ipAddress,
          userAgent
        );
        timer.log("createRefreshToken");

        await prisma.refreshToken.delete({
          where: { userId, jti: jtiOldToken },
        });
        timer.log("delete");

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          expires: refreshToken.expiresAt,
        });

        res.status(200).json({
          accesstoken: accessToken,
          message: "Tokens refreshed successfully",
        });
        timer.log("response send");
        timer.end();
        logger.info("Tokens refreshed successfully", { userId, deviceId });
      } catch (err) {
        logger.error("Token refresh failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- LOGOUT -------------------------
  router.delete(
    "/logout",
    authenticateToken,
    async (req, res, next) => {
      const timer = startTimer("TOTAL logout");
      const { id: userId, jti } = req.user;
      if (!userId || !jti)
        return next(new AppError("Invalid token payload for logout.", 400));

      try {
        await prisma.refreshToken.deleteMany({ where: { userId, jti } });
        timer.log("deleteMany");
        res
          .status(200)
          .json({ message: "Logout successful for current session." });
        timer.log("response send");
        timer.end();
        logger.info("User logged out of current session", { userId, jti });
      } catch (err) {
        logger.error("Logout of specific session failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- LOGOUT ALL -------------------------
  router.delete(
    "/sessions",
    authenticateToken,
    async (req, res, next) => {
      const timer = startTimer("TOTAL logout-all");
      const userId = req.user.id;
      try {
        await prisma.refreshToken.deleteMany({ where: { userId } });
        timer.log("deleteMany");
        await prisma.user.update({
          where: { id: userId },
          data: { tokenVersion: { increment: 1 } },
        });
        timer.log("update");
        res.status(200).json({ message: "Logged out from all devices" });
        timer.log("response send");
        timer.end();
        logger.info("User logged out of all sessions", { userId });
      } catch (err) {
        logger.error("Logout of all sessions failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- LOGOUT SPECIFIC SESSION -------------------------
  router.delete(
    "/sessions/:jti",
    authenticateToken,
    async (req, res, next) => {
      const timer = startTimer("TOTAL logout-specific-session");
      const { jti } = req.params;
      const userId = req.user.id;
      if (!jti)
        return next(
          new AppError("Session ID (jti) is required in the path.", 400)
        );

      try {
        const deletedToken = await prisma.refreshToken.deleteMany({
          where: { jti, userId },
        });
        timer.log("deleteMany");
        if (deletedToken.count === 0)
          return next(
            new AppError("Session not found or already deleted", 404)
          );

        res.status(200).json({ message: "Session deleted successfully" });
        timer.log("response send");
        timer.end();
        logger.info("Specific session deleted successfully", { userId, jti });
      } catch (err) {
        logger.error("Deleting a specific session failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- CHANGE PASSWORD -------------------------
  router.post(
    "/change-password",
    authenticateToken,
    changePasswordValidation,
    async (req, res, next) => {
      const timer = startTimer("TOTAL change-password");
      try {
        const { currentpassword, newpassword } = req.body;
        const userId = req.user.id;

        const user = await prisma.user.findUnique({
          where: { id: userId },
        });
        timer.log("findUnique");
        const doesPasswordMatch = await bcrypt.compare(
          currentpassword,
          user.password
        );
        timer.log("bcrypt.compare");
        if (!doesPasswordMatch)
          return next(new AppError("Password is incorrect", 401));

        const hashedNewPassword = await bcrypt.hash(newpassword, 10);
        timer.log("bcrypt.hash");
        await prisma.user.update({
          where: { id: userId },
          data: { password: hashedNewPassword },
        });
        timer.log("update");

        res.status(200).json({ message: "Password changed successfully" });
        timer.log("response send");
        timer.end();
        logger.info("Password changed successfully", { userId });
      } catch (err) {
        logger.error("Change password failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- FORGOT PASSWORD -------------------------
  router.post(
    "/forgot-password",
    forgotPasswordValidation,
    async (req, res, next) => {
      const timer = startTimer("TOTAL forgot-password");
      const { email } = req.body;
      try {
        const user = await prisma.user.findUnique({
          where: { email },
        });
        timer.log("findUnique");
        if (!user)
          return next(
            new AppError(
              "If that email is associated with an account, you’ll receive a reset link shortly.",
              200
            )
          );

        const userId = user.id;
        await prisma.passwordResetToken.deleteMany({ where: { userId } });
        timer.log("deleteMany");

        const tokenId = uuidv4();
        const rawtoken = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        const passwordResetToken = await bcrypt.hash(rawtoken, 10);
        timer.log("bcrypt.hash");

        await prisma.passwordResetToken.create({
          data: { userId, tokenId, token: passwordResetToken, expiresAt },
        });
        timer.log("create");

        const resetPasswordLink = `${process.env.WEBSITE_URL}/reset-password.html?tokenId=${tokenId}&token=${rawtoken}`;
        const html = resetPasswordEmailTemplate(resetPasswordLink);

        await sendEmail({ to: email, subject: "Reset your password", html });
        timer.log("sendEmail");

        res.status(200).json({
          message:
            "If an account with that email exists, a password reset link has been sent.",
          resetPasswordLink,
        });
        timer.log("response send");
        timer.end();
        logger.info("Password reset link sent", { email, userId });
      } catch (err) {
        logger.error("Forgot password process failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- RESET PASSWORD -------------------------
  router.post(
    "/reset-password",
    resetPasswordValidation,
    async (req, res, next) => {
      const timer = startTimer("TOTAL reset-password");
      try {
        const { tokenId, token } = req.query;
        const { newPassword } = req.body;

        await prisma.passwordResetToken.deleteMany({
          where: { expiresAt: { lt: new Date() } },
        });
        timer.log("deleteMany expired");

        const passwordToken = await prisma.passwordResetToken.findUnique({
          where: { tokenId },
        });
        timer.log("findUnique");
        if (!passwordToken || passwordToken.expiresAt < new Date())
          return next(new AppError("Invalid or expired token", 401));

        const isTokenValid = await bcrypt.compare(token, passwordToken.token);
        timer.log("bcrypt.compare");
        if (!isTokenValid) return next(new AppError("Invalid token", 401));

        const userId = passwordToken.userId;
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        timer.log("bcrypt.hash");

        await prisma.user.update({
          where: { id: userId },
          data: { password: hashedNewPassword },
        });
        timer.log("update user");
        await prisma.refreshToken.deleteMany({ where: { userId } });
        timer.log("delete refresh tokens");
        await prisma.user.update({
          where: { id: userId },
          data: { tokenVersion: { increment: 1 } },
        });
        timer.log("increment token version");
        await prisma.passwordResetToken.delete({ where: { tokenId } });
        timer.log("delete password reset token");

        res.status(200).json({ message: "Password reset successful" });
        timer.log("response send");
        timer.end();
        logger.info("Password reset successfully", { userId });
      } catch (err) {
        logger.error("Password reset failed", err);
        timer.end();
        next(err);
      }
    }
  );

  // ------------------------- POSTS -------------------------
  router.get(
    "/posts",
    authenticateToken,
    hasPermissions(["post:read"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL get-posts");
      try {
        const posts = await prisma.post.findMany({
          include: { user: { select: { fullname: true, email: true } } },
          cache: true,
        });
        timer.log("findMany");
        res.status(200).json({ message: "Access Granted", posts });
        timer.log("response send");
        timer.end();
        logger.info("Posts retrieved successfully", {
          userId: req.user.id,
          count: posts.length,
        });
      } catch (err) {
        logger.error("Retrieving posts failed", err);
        timer.end();
        next(err);
      }
    }
  );

  router.post(
    "/post",
    authenticateToken,
    hasPermissions(["post:create"]),
    requireEmailVerification,
    postValidation,
    sanitizeFields(["title", "content"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL create-post");
      const { title, content } = req.body;
      const userId = req.user.id;
      try {
        const newPost = await prisma.post.create({
          data: { title, content, userId },
        });
        timer.log("create");
        res
          .status(201)
          .json({ message: "Post created successfully", post: newPost });
        timer.log("response send");
        timer.end();
        logger.info("Post created successfully", {
          postId: newPost.id,
          userId,
        });
      } catch (err) {
        logger.error("Post creation failed", err);
        timer.end();
        next(err);
      }
    }
  );

  router.put(
    "/posts/:postId",
    authenticateToken,
    hasPermissions(["post:update_own", "post:update"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL update-post");
      const { postId } = req.params;

      const existingPost = await prisma.post.findUnique({
        where: { id: parseInt(postId) },
      });
      timer.log("findUnique");
      if (!existingPost) return next(new AppError("Post not found.", 404));

      try {
        const updatedPost = await prisma.post.update({
          where: { id: parseInt(postId) },
          data: {
            title: title || existingPost.title,
            content: content || existingPost.content,
          },
        });
        timer.log("update");
        res.status(200).json(updatedPost);
        timer.log("response send");
        timer.end();
        logger.info("Post updated successfully", {
          postId: updatedPost.id,
          userId: req.user.id,
        });
      } catch (err) {
        logger.error("Updating post failed", err);
        timer.end();
        next(err);
      }
    }
  );

  router.delete(
    "/posts/:postId",
    authenticateToken,
    hasPermissions(["post:delete_own", "post:delete"]),
    async (req, res, next) => {
      const timer = startTimer("TOTAL delete-post");
      const { postId } = req.params;

      const existingPost = await prisma.post.findUnique({
        where: { id: parseInt(postId) },
      });
      timer.log("findUnique");
      if (!existingPost) return next(new AppError("Post not found.", 404));

      try {
        await prisma.post.delete({ where: { id: parseInt(postId) } });
        timer.log("delete");
        res.status(200).json({ message: "Post deleted successfully." });
        timer.log("response send");
        timer.end();
        logger.info("Post deleted successfully", {
          postId,
          userId: req.user.id,
        });
      } catch (err) {
        logger.error("Deleting post failed", err);
        timer.end();
        next(err);
      }
    }
  );



module.exports = router;
