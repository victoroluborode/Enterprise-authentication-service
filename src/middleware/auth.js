const jwt = require('jsonwebtoken');
const prisma = require("../config/prismaClient")

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.status(401).json({
          message: "No token provided",
        });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({
              message: "Invalid or expired token",
            });
        }
      
        const tokenVer = decoded.tokenVersion;
      const user = await prisma.user.findUnique({
        where: { id: decoded.sub },
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
      if (!user || user.tokenVersion !== tokenVer) {
        console.warn(
          `Token version mismatch for user ${
            decoded.sub
          }. JWT Version: ${tokenVer}, DB Version: ${
            user ? user.tokenVersion : "N/A"
          }`
        );
        return res.status(403).json({
          message: "Token invalidated. Please log in again.",
        });
      }
      
        req.user = user;
        next();
    });
};

module.exports = { authenticateToken };