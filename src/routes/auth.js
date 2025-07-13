const express = require('express');
const router = express.Router();
const registerUser = require('../services/userService')
const registerValidation = require('../utils/validation')

router.post("/", registerValidation, async (req, res) => {
    try {
        const { email, password, fullname } = req.body;
        await registerUser(email, password, fullname);
        res.status(200).json({
            success: true,
            message: "user registered"
        })
    } catch (err) {
        res.status(500).json({
            error: "Server error"
        })
    }
    
});




module.exports = router;

