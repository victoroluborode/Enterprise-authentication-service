const bcrypt = require("bcrypt");
const { createEmailToken } = require("../services/emailTokenService");
const prisma = require("../config/prismaClient");
const { sendEmail } = require("../utils/emailservice");
const verificationEmailTemplate =
  require("../utils/template").verificationEmailTemplate;

async function registerUser(email, password, fullname) {
  try {
    console.time("Total registerUser");

    
    console.time("prisma.role.findFirst");

    console.log("All roles:", await prisma.role.findMany());
    const defaultRole = await prisma.role.findFirst({
      where: {
        name: {
          equals: "USER",
          mode: "insensitive",
        },
      }
    });
    console.log("Default role lookup result:", defaultRole);
    console.timeEnd("prisma.role.findFirst");

    if (!defaultRole) {
      throw new Error("Default role not found. System misconfiguration.");
    }

    console.time("bcrypt.hash");
    const saltRounds = 10;
    const userPassword = await bcrypt.hash(password, saltRounds);
    console.timeEnd("bcrypt.hash");

    console.time("prisma.user.create");
    const newUser = await prisma.user.create({
      data: {
        email,
        password: userPassword,
        fullname,
      },
    });
    console.timeEnd("prisma.user.create");

    console.time("prisma.userRole.create");
    const userRole = await prisma.userRole.create({
      data: {
        userId: newUser.id,
        roleId: defaultRole.id,
      },
    });
    console.timeEnd("prisma.userRole.create");

    
    const userWithRoles = {
      ...newUser,
      roles: [
        {
          id: userRole.id,
          userId: newUser.id,
          roleId: defaultRole.id,
          role: {
            ...defaultRole,
            permissions: [], 
          },
        },
      ],
    };

    console.time("createEmailToken");
    const { token, tokenId } = await createEmailToken(newUser.id);
    console.timeEnd("createEmailToken");

    console.time("sendEmail (async fire-and-forget)");
    sendEmail({
      to: email,
      subject: "Verify your email",
      html: verificationEmailTemplate(
        `http://localhost:3000/api/auth/verify-email?token=${token}&tokenId=${tokenId}`
      ),
    });
    console.timeEnd("sendEmail (async fire-and-forget)");

    console.timeEnd("Total registerUser");

    return { userWithRoles };
  } catch (err) {
    console.error("Registration failed:", err);
    throw err;
  }
}

module.exports = registerUser;
