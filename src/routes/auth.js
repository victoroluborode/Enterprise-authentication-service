const express = require('express');
const router = express.Router();
const registerUser = require('../services/userService')
const registerValidation = require('../utils/validation');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

router.post("/", registerValidation, async (req, res) => {
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




module.exports = router;

