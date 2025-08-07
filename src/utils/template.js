// utils/templates.js
function verificationEmailTemplate(link) {
  return `
    <div style="font-family: sans-serif; line-height: 1.6;">
      <h2>Welcome to SecureAuth</h2>
      <p>Click the button below to verify your email:</p>
      <a href="${link}" style="background: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Verify Email</a>
      <p>If you didn’t request this, you can ignore this email.</p>
    </div>
  `;
};

function resetPasswordEmailTemplate(link) {
  return `
    <div style="font-family: sans-serif; line-height: 1.6; color: #333;">
      <h2>Reset Your Password</h2>
      <p>We received a request to reset your password. Click the button below to set a new one:</p>
      <a href="${link}" style="background: #007BFF; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
      <p>This link will expire in 15 minutes for your security.</p>
      <p>If you didn’t request a password reset, you can safely ignore this email.</p>
      <br />
      <p style="font-size: 0.9em; color: #666;">— SecureAuth Team</p>
    </div>
  `;
}

module.exports = {
  verificationEmailTemplate,
  resetPasswordEmailTemplate
};
