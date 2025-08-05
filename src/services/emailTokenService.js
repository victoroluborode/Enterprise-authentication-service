const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient;

const createEmailToken = async (userId) => {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const hashedToken = await bcrypt.hash(token, 10);

    await prisma.emailverificationtoken.create({
        data: {
            userId: userId,
            token: hashedToken,
            expiresAt: expiresAt
        },
    });
    return token;
};

module.exports = { createEmailToken };


