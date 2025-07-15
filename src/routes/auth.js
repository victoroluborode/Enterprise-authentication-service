const express = require('express');
const router = express.Router();
const registerUser = require('../services/userService')
const { registerValidation, loginValidation } = require('../utils/validation');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");

router.post("/register", registerValidation, async (req, res) => {
    const { email, password, fullname } = req.body;
    try {
        const existingUser = await prisma.user.findUnique({
            where: { email: email }
        });

        if (existingUser) {
            return res.status(400).json({
                error: "Email already in use"
            })
        }
        await registerUser(email, password, fullname);
        res.status(200).json({
            success: true,
            message: "user registered"
        })
    } catch (err) {
        console.log("Registration error:", err)
        res.status(500).json({
            error: "Server error"
        })
    }
    
});


router.post("/login", loginValidation, async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await prisma.user.findUnique({
          where: { email: email },
        });
        if (!user) {
            return res.status(400).json({
                message: "Invalid email or password"
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }


        res.status(200).json({
            message: "Login successful",
            user
        })

    } catch (err) {
        console.log("Login error:", err);
        res.status(500).json({
          error: "Server error",
        });
    }
})



module.exports = router;

