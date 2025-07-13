const { body, validationResult } = require('express-validator');

const registerValidation = [
    body("email").notEmpty().isEmail().withMessage("Enter a valid email address"),
    body("password")
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
        .withMessage(
            "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
        ),
    body('fullname').trim().notEmpty().withMessage('Full name is required'),

        (req, res, next) => {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array()
                });
            }
            next();
    }
];

module.exports = registerValidation;