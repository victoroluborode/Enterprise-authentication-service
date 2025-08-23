const express = require("express");
const router = express.Router();
const { hasPermissions } = require("../middleware/rolePermissions");
const prisma = require("../config/prismaClient")
const { authenticateToken } = require("../middleware/auth");
const AppError = require("../utils/app-error");

router.get(
  "/roles",
  authenticateToken,
  hasPermissions("roles:list"),
  async (req, res, next) => {
    try {
      const roles = await prisma.role.findMany({
        cache: true
      });
      res.status(200).json(roles);
    } catch (err) {
      console.error(err);
      next(err);
    }
  }
);

router.get(
  "/permissions",
  authenticateToken,
  hasPermissions("permissions:list"),
  async (req, res, next) => {
    try {
      const permissions = await prisma.permission.findMany({
        cache: true
      });
      res.status(200).json(permissions);
    } catch (err) {
      console.error(err);
      next(err);
    }
  }
);

router.post(
  "/user-roles",
  authenticateToken,
  hasPermissions("user:role:assign"),
  async (req, res, next) => {
    const { userId, roleId } = req.body;
    if (!userId || !roleId) {
      return next(new AppError("User ID and Role ID are required.", 400));
    }
    try {
      await prisma.userRole.create({
        data: { userId, roleId },
      });
      res.status(201).json({ message: "Role assigned successfully." });
    } catch (err) {
      next(err);
    }
  }
);

router.delete(
  "/user-roles",
  authenticateToken,
  hasPermissions("user:role:remove"),
  async (req, res, next) => {
    const { userId, roleId } = req.params;
    if (!userId || !roleId) {
      return next(new AppError("User ID and Role ID are required.", 400));
    }
    try {
      await prisma.userRole.delete({
        where: { userId_roleId: { userId, roleId } },
      });
      res.status(200).json({ message: "Role removed successfully." });
    } catch (err) {
      console.error(err);
      if (err.code === "P2025") {
        return next(
          new AppError("User does not have this role assigned.", 404)
        );
      } else {
        next(err)
      }
    }
  }
);

router.post(
  "/role-permissions",
  authenticateToken,
  hasPermissions("role:permission:assign"),
  async (req, res, next) => {
    const { roleId, permissionId } = req.body;
    if (!roleId || !permissionId) {
      return next(new AppError("Role ID and Permission ID are required.", 400));
    }
    try {
      await prisma.rolePermission.create({
        data: { roleId, permissionId },
      });
      res
        .status(201)
        .json({ message: "Permission assigned to role successfully." });
    } catch (err) {
      next(err);
    }
  }
);

router.delete(
  "/role-permissions",
  authenticateToken,
  hasPermissions("role:permission:remove"),
  async (req, res) => {
    const { roleId, permissionId } = req.body;
    if (!roleId || !permissionId) {
      return next(new AppError("Role ID and Permission ID are required.", 400));
    }
    try {
      await prisma.rolePermission.delete({
        where: { roleId_permissionId: { roleId, permissionId } },
      });
      res
        .status(200)
        .json({ message: "Permission removed from role successfully." });
    } catch (err) {
      console.error(err);
      if (err.code === "P2025") {
        return next(
          new AppError("Role does not have this permission assigned.", 404)
        );
      } else {
        next(err);
      }
    }
  }
);

module.exports = router;
