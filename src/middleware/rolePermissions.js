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

const hasPermissions = (requiredPermissions) => {
  return async (req, res, next) => {
    try {
      const user = req.user;

      if (!user) {
        return res.status(401).json({
          error: "Authentication required",
        });
      }

      const userPermissions = user.roles.flatMap((userRole) =>
        userRole.role.permissions.map((p) => p.permission.name)
      );

      for (const requiredPermission of requiredPermissions) {
        if (userPermissions.includes(requiredPermission)) {
          return next();
        }

        const [resource, action] = requiredPermission.split(":");
        if (action && action.endsWith("_own")) {
          const postId = req.params.postId || req.body.postId;
          if (!postId) {
            continue;
          }

          const post = await prisma.post.findUnique({
            where: { id: postId },
            select: { userId: true },
          });

          if (post && post.userId === user.id) {
            return next();
          }
        }
      }

      return res.status(403).json({
        error: "Forbidden: You do not have the required permissions.",
      });
    } catch (err) {
      console.log("Permission check error:", err);
      return res.status(500).json({
        message: "Server error",
      });
    }
  };
};

module.exports = { hasRole, hasPermissions };
