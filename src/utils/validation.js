const { body, validationResult } = require('express-validator');

const registerValidation = [
    body("email").notEmpty().isEmail().withMessage("Enter a valid email address"),
    body("password")
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
        .withMessage(
            "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
        ),
  body('fullname').trim().notEmpty().withMessage('Full name is required'),
  body('deviceId').notEmpty().withMessage("Device ID must not be empty").isUUID().withMessage('Device ID must be a valid UUID'),

        (req, res, next) => {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    message: errors.array()
                });
            }
            next();
    }
];

const loginValidation = [
  body("email").notEmpty().isEmail().withMessage("Enter a valid email address"),
  body("password")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
    .withMessage(
      "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
  ),
  body('deviceId').optional().isUUID().withMessage('Device ID must be a valid UUID'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: errors.array(),
      });
    }
    next();
  },
];

const postValidation = [
  body('title').notEmpty().withMessage("Title is required"),
  body('content').notEmpty().withMessage('Content is required').isLength({ min: 10 }).withMessage('Content must be atleast 10 characters'),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: errors.array(),
      })
    }
    next();
  }
]


const tokenValidation = [
  body('token').notEmpty().withMessage("Refresh token required"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(401).json({
        message: errors.array(),
      })
    }
    next();
  }
]


const changePasswordValidation = [
  body("currentpassword")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
    .withMessage(
      "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    ),
  body("newpassword")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
    .withMessage(
      "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    ),
];
module.exports = { tokenValidation, registerValidation, loginValidation, postValidation, changePasswordValidation};