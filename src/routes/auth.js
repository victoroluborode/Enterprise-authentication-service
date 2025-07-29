require("dotenv").config();
const express = require("express");
const router = express.Router();
const registerUser = require("../services/userService");
const { registerValidation, loginValidation } = require("../utils/validation");
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

const posts = [
  {
    email: "packma110@gmail.com",
    title: "How I Learned Node.js",
    body: "I started learning Node.js by building a personal blog API. The concepts were tough at first, but breaking them into small tasks helped a lot.",
    createdAt: "2025-07-14T10:00:00Z",
    author: {
      name: "Pack Ma",
      bio: "Backend developer in training, passionate about scalable systems and clean code.",
      avatar: "https://example.com/avatar1.png",
    },
  },
  {
    email: "Pinkedin110@gmail.com",
    title: "My DevOps Journey",
    body: "Discovering Docker, GitHub Actions, and infrastructure as code completely changed how I think about deployment.",
    createdAt: "2025-07-13T16:45:00Z",
    author: {
      name: "Pinked In",
      bio: "Cloud enthusiast. DevOps engineer who enjoys making things reliable and reproducible.",
      avatar: "https://example.com/avatar2.png",
    },
  },
  {
    email: "sainthuncho110@gmail.com",
    title: "Debugging JavaScript",
    body: "One bug took me 4 hours to solve — missing an `await` in an async function. Debugging can be frustrating but so rewarding when you finally get it.",
    createdAt: "2025-07-12T08:30:00Z",
    author: {
      name: "Victor Oluborode",
      bio: "Backend developer in training, passionate about scalable systems and clean code.",
      avatar: "https://example.com/avatar1.png",
    },
  },
  {
    email: "kiaricephus110@gmail.com",
    title: "What I Wish I Knew Before Learning AWS",
    body: "IAM permissions are no joke. I locked myself out twice. But once I understood the roles and policies, everything clicked.",
    createdAt: "2025-07-10T14:20:00Z",
    author: {
      name: "Kiari Cephus",
      bio: "Cloud enthusiast. DevOps engineer who enjoys making things reliable and reproducible.",
      avatar: "https://example.com/avatar2.png",
    },
  },
];

router.post("/register", registerValidation, async (req, res) => {
  const { email, password, fullname, deviceId } = req.body;
  const ipAddress = req.ip;
  const userAgent = req.headers['user-agent']; 

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

    const userWithRoles = await registerUser(email, password, fullname);
    const userRoles = userWithRoles.roles.map((userRole) => userRole.role.name);

    const accessToken = await createAccessToken(userWithRoles);
    const refreshToken = await createRefreshToken(userWithRoles, deviceId, ipAddress, userAgent);

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
});

router.get("/posts", authenticateToken, async (req, res) => {
  const email = req.query.email;
  console.log(email);
  try {
    res.status(200).json({
      message: "Access Granted",
      posts: posts.filter((post) => post.email === email),
    });
  } catch (err) {
    console.error("error:", err);
    res.status(500).json({
      error: "server error",
      message: "An unexpected error occurred while getting posts",
    });
  }
});

router.get("/sessions", authenticateToken, async (req, res) => {
  try { 
    const userId = req.user.sub;
    const sessions = await prisma.refreshToken.findMany({
      where: {
        userId: userId,
        expiresAt: {
        gte: new Date(),
      } },
      select: {
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
})

router.post("/login", loginValidation, async (req, res) => {
  const { email, password, deviceId } = req.body;
  const ipAddress = req.ip;
  const userAgent = req.headers['user-agent'];
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
    const refreshtoken = await createRefreshToken(user, deviceId, ipAddress, userAgent);

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
});

router.post("/token", verifyRefreshTokens, async (req, res) => {
  const jtiOldToken = req.jtiOldToken;
  const userId = req.user.id;
  const deviceId = req.user.deviceId;

  const ipAddress = req.ip;
  const userAgent = req.headers['user-agent'];
  try {
    const accesstoken = await createAccessToken(req.user);
    const refreshtoken = await createRefreshToken(req.user, deviceId, ipAddress, userAgent);

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
});

router.delete("/logout", (req, res) => {
  const refreshToken = req.body.token;
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        return res.sendStatus(401);
      }
      const userId = decoded.sub;
      const jti = decoded.jti;
      try {
        await prisma.refreshToken.delete({
          where: {
            userId,
            jti,
          },
        });

        res.status(200).json({ message: "Logout successful" });
      } catch (err) {
        res.status(500).json({ error: "Token deletion failed" });
      }
    }
  );
});

router.delete("/logoutall", authenticateToken, async (req, res) => {
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
});

module.exports = router;
