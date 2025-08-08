const express = require("express");
const router = express.Router();
const { hasPermissions } = require("../middleware/rolePermissions");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const { authenticateToken } = require("../middleware/auth");

router.get(
  "/roles",
  authenticateToken,
  hasPermissions("roles:list"),
  async (req, res) => {
    try {
      const roles = await prisma.role.findMany();
      res.status(200).json(roles);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to retrieve roles." });
    }
  }
);

router.get(
  "/permissions",
  authenticateToken,
  hasPermissions("permissions:list"),
  async (req, res) => {
    try {
      const permissions = await prisma.permission.findMany();
      res.status(200).json(permissions);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to retrieve permissions." });
    }
  }
);

router.post(
  "/user-roles",
  authenticateToken,
  hasPermissions("user:role:assign"),
  async (req, res) => {
    const { userId, roleId } = req.body;
    try {
      await prisma.userRole.create({
        data: { userId, roleId },
      });
      res.status(201).json({ message: "Role assigned successfully." });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to assign role." });
    }
  }
);

router.delete(
  "/user-roles",
  authenticateToken,
  hasPermissions("user:role:remove"),
  async (req, res) => {
    const { userId, roleId } = req.body;
    try {
      await prisma.userRole.delete({
        where: { userId_roleId: { userId, roleId } },
      });
      res.status(200).json({ message: "Role removed successfully." });
    } catch (err) {
      console.error(err);
      if (err.code === "P2025") {
        res
          .status(404)
          .json({ error: "User does not have this role assigned." });
      } else {
        res.status(500).json({ error: "Failed to remove role." });
      }
    }
  }
);

router.post(
  "/role-permissions",
  authenticateToken,
  hasPermissions("role:permission:assign"),
  async (req, res) => {
    const { roleId, permissionId } = req.body;
    try {
      await prisma.rolePermission.create({
        data: { roleId, permissionId },
      });
      res
        .status(201)
        .json({ message: "Permission assigned to role successfully." });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to assign permission to role." });
    }
  }
);

router.delete(
  "/role-permissions",
  authenticateToken,
  hasPermissions("role:permission:remove"),
  async (req, res) => {
    const { roleId, permissionId } = req.body;
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
        res
          .status(404)
          .json({ error: "Role does not have this permission assigned." });
      } else {
        res
          .status(500)
          .json({ error: "Failed to remove permission from role." });
      }
    }
  }
);

module.exports = router;
