const nodemailer = require("nodemailer");


let transporter;

async function createTestAccount() {
  const testAccount = await nodemailer.createTestAccount();
  transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass,
    },
  });

  console.log("Ethereal test account created:");
  console.log(`User: ${testAccount.user}`);
  console.log(`Pass: ${testAccount.pass}`);
}

async function sendEmail({ to, subject, html }) {
  try {
    if (!transporter) {
      await createTestAccount();
    }
    const info = await transporter.sendMail({
      from: "SecureAuth <no-reply@example.com>",
      to,
      subject,
      html,
    });
      
      console.log("Message sent:", info.messageId);
      console.log("Preview URL:", nodemailer.getTestMessageUrl(info));
      return {
        success: true,
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info),
      };
  } catch (err) {
      console.error("Email sending failed:", err.message);
      return {
        success: false,
        error: err.message,
      };
  }
}

module.exports = { sendEmail };