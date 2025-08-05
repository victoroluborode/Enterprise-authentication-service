const express = require('express');
const router = express.Router();
const { sendEmail } = require("../utils/emailservice");
const { verificationEmailTemplate } = require("../utils/template");


router.get('/test-email', async (req, res) => {
    try {
        const verificationLink = 'http://localhost:3000/verify?token=abc123';

        const emailResult = await sendEmail({
            to: 'someone@example.com',
            subject: 'Verify your account',
            html: verificationEmailTemplate(verificationLink)
        });

        if (emailResult.success) {
            return res.status(200).json({
                message: "Email sent successfully",
                previewUrl: emailResult.previewUrl,
                messageId: emailResult.messageId
            });
        } else {
            return res.status(500).json({
                message: 'Failed to send email',
                error: emailResult.error,
            });
        }
    } catch (err) {
        console.error('Unexpected error:', err.message);
        return res.status(500).json({
            message: 'Something went wrong while sending the email',
            error: err.message
        })
    }
});

module.exports = router;