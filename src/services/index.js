const verifyEmailToken = async (req, res, next) => {
  try {
    const { tokenId, token } = req.query;

    // These checks stay outside the transaction
    // as they validate the request before touching the database.
    if (!tokenId || !token) {
      return res.status(401).json({ message: "Invalid request" });
    }

    // This lookup can be outside or inside the transaction.
    // Putting it outside is a common practice to validate first.
    const emailToken = await prisma.emailVerificationToken.findUnique({
      where: { identifier: tokenId },
    });

    // All these validation checks are outside the transaction.
    if (!emailToken || emailToken.expiresAt < new Date()) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    const isTokenValid = await bcrypt.compare(token, emailToken.hashedToken);
    if (!isTokenValid) {
      return res.status(401).json({
        message: "Invalid token",
      });
    }

    // Only the database-modifying operations go inside the transaction.
    await prisma.$transaction(async (tx) => {
      // 1. Update the user
      await tx.user.update({
        where: { id: emailToken.userId },
        data: { emailVerified: true },
      });

      // 2. Delete the token
      await tx.emailVerificationToken.delete({
        where: { id: emailToken.id },
      });
    });

    res.status(200).json({ message: "Email verified successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};
