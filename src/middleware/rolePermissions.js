const prisma = require("../config/prismaClient");

const hasRole = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      const userId = req.user.id;
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

      const userPermissions = [];
      if (user.roles) {
        for (const userRole of user.roles) {
          if (userRole.role && userRole.role.permissions) {
            for (const permission of userRole.role.permissions) {
              if (permission.permission && permission.permission.name) {
                userPermissions.push(permission.permission.name);
              }
            }
          }
        }
      }

      console.log("Required permissions for this route:", requiredPermissions);
      console.log("Permissions available to the user:", userPermissions);
      for (const requiredPermission of requiredPermissions) {
        if (
          userPermissions.includes(requiredPermission) &&
          !requiredPermission.endsWith("_own")
        ) {
          console.log(
            `Permission found: ${requiredPermission}. Access granted.`
          );
          return next();
        }

        const [resource, action] = requiredPermission.split(":");
        if (
          action &&
          action.endsWith("_own") &&
          userPermissions.includes(requiredPermission)
        ) {
          const resourceId = parseInt(req.params[`${resource}Id`]);
          const postId = req.params.postId || req.body.postId;

          if (resourceId) {
            try {
              const resourceObject = await prisma[resource].findUnique({
                where: { id: resourceId },
                select: { userId: true },
              });

              if (resourceObject && resourceObject.userId === user.id) {
                console.log(
                  `Ownership check passed for ${resource} with id ${resourceId}. Access granted.`
                );
                return next();
              }
            } catch (err) {
              console.error(
                `Error checking ownership for ${resource} with id ${resourceId}:`,
                err
              );
            }
          }
        }
      }
      console.log("No required permissions found. Access denied.");
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
