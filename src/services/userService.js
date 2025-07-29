const bcrypt = require('bcrypt');

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function registerUser(email, password, fullname) {
    const saltRounds = 10;
    const userPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await prisma.user.create({
        data: {
            email: email,
            password: userPassword,
            fullname: fullname
        }
    });

    const defaultRole = await prisma.role.findUnique({
        where: { name: 'USER' },
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
    })

    const userWithRoles = await prisma.user.findUnique({
        where: { id: newUser.id },
        include: {
            roles: {
                include: {
                    role: true
                }
            }
        }
    })

    console.log("User created", userWithRoles);
    return userWithRoles;
};

module.exports = registerUser;