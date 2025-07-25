require("dotenv").config();
const express = require("express");
const router = express.Router();
const registerUser = require("../services/userService");
const { registerValidation, loginValidation, tokenValidation } = require("../utils/validation");
const { authenticateToken } = require("../middleware/auth");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {
  createRefreshToken,
  verifyRefreshTokens,
} = require("../services/refreshTokenservice");

const posts = [
  {
    email: "jackma110@gmail.com",
    title: "How I Learned Node.js",
    body: "I started learning Node.js by building a personal blog API. The concepts were tough at first, but breaking them into small tasks helped a lot.",
    createdAt: "2025-07-14T10:00:00Z",
    author: {
      name: "Jack Ma",
      bio: "Backend developer in training, passionate about scalable systems and clean code.",
      avatar: "https://example.com/avatar1.png",
    },
  },
  {
    email: "linkedIn110@gmail.com",
    title: "My DevOps Journey",
    body: "Discovering Docker, GitHub Actions, and infrastructure as code completely changed how I think about deployment.",
    createdAt: "2025-07-13T16:45:00Z",
    author: {
      name: "Linked In",
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
  const { email, password, fullname } = req.body;
  try {
    const existingUser = await prisma.user.findUnique({
      where: { email: email },
    });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }
    const user = await registerUser(email, password, fullname);
    const userResponse = {
      id: user.id,
      email: user.email,
      fullname: user.full_name, 
    };
    res.status(201).json({
      success: true,
      message: `User registered successfully.`,
      user: userResponse,
    });
  } catch (err) {
    console.log("Registration error:", err);
    res.status(500).json({
      error: "Server error",
    });
  }
});

router.get("/posts", authenticateToken, async (req, res) => {
  res.json(posts.filter((post) => post.email === req.user.email));
});

const generateAccessTokens = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1.5m" });
};

router.post("/login", loginValidation, async (req, res) => {
  const { email, password } = req.body;
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

    const accesstoken = generateAccessTokens(user);
    const refreshtoken = await createRefreshToken(user);

    const userResponse = {
      id: user.id,
      email: user.email,
      fullname: user.full_name
    }

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



router.post("/token", tokenValidation, verifyRefreshTokens, async (req, res) => {
  const accesstoken = generateAccessTokens(req.user);
  res.status(200).json({
    accesstoken: accesstoken,
    message: "access token refreshed"
  });
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
        await prisma.RefreshToken.delete({
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
  const userId = req.user.id;
  try {
    await prisma.RefreshToken.deleteMany({
      where: {
        userId,
      },
    });
    res.status(200).json({
      message: "Logged out from all devices",
    });
  } catch (err) {
    res.status(500).json({ err: "Failed to logout from all devices" });
  }
});

module.exports = router;
