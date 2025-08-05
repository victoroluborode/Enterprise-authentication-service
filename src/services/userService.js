const bcrypt = require("bcrypt");
const { createEmailToken } = require("../services/emailTokenService");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const { sendEmail } = require("../utils/emailservice");
const verificationEmailTemplate =
  require("../utils/template").verificationEmailTemplate;

async function registerUser(email, password, fullname) {
  try {
    const saltRounds = 10;
    const userPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await prisma.user.create({
      data: {
        email: email,
        password: userPassword,
        fullname: fullname,
      },
    });

    const defaultRole = await prisma.role.findUnique({
      where: { name: "USER" },
    });

    if (!defaultRole) {
      console.error(
        "Error: Default 'USER' role not found in database. Please seed your roles."
      );
      throw new Error("Default role not found. System misconfiguration.");
    }

    await prisma.userRole.create({
      data: {
        userId: newUser.id,
        roleId: defaultRole.id,
      },
    });

    const userWithRoles = await prisma.user.findUnique({
      where: { id: newUser.id },
      include: {
        roles: {
          include: {
            role: true,
          },
        },
      },
    });

    const emailToken = await createEmailToken(newUser.id);
    const verificationlink = `http://localhost:3000/api/auth/verify-email?token=${emailToken}`;
    const html = verificationEmailTemplate(verificationlink);

    await sendEmail({
      to: email,
      subject: "Verify your email",
      html: html,
    });

    console.log("User created", userWithRoles);
      return { userWithRoles, verificationlink };
  } catch (err) {
    console.log("Registration failed:", err);
  }
}

module.exports = registerUser;
