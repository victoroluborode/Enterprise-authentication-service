const bcrypt = require('bcrypt');

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function registerUser(email, password, full_name) {
    const saltRounds = 10;
    const userPassword = await bcrypt.hash(password, saltRounds);

    const user = await prisma.user.create({
        data: {
            email: email,
            password: userPassword,
            full_name: full_name
        }
    });

    console.log("User created", user);
};

module.exports = registerUser;