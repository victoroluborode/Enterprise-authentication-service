const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const hasRole = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      const userId = req.user.sub;
      const userWithRoles = await prisma.user.findUnique({
        where: {
          id: userId,
        },
        include: { roles: { select: { role: { select: { name: true } } } } },
      });

      const userRoles = userWithRoles.roles.map((ur) => ur.role.name);
      const hasRequiredRole = userRoles.some((role) =>
        allowedRoles.includes(role)
      );

      if (hasRequiredRole) {
        next();
      } else {
        res.status(403).json({
          message: "Forbidden",
        });
      }
    } catch (err) {
      res.status(500).json({
        message: "Server error",
      });
    }
  };
};

const hasPermissions = (requiredPermission) => {
  return async (req, res, next) => {
    try {
      const userPermissions = req.user.permissions;
      if (userPermissions && userPermissions.includes(requiredPermission)) {
        next();
      } else {
        res.status(403).json({
          message: "Forbidden: You do not have the necessary permissions.",
        });
      }
    } catch (err) {
      res.status(500).json({
        message: "Server error",
      });
    }
  };
};

module.exports = { hasRole, hasPermissions };