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
}

module.exports = {
  verificationEmailTemplate,
};
