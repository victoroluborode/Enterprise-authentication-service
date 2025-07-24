const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const { PrismaClient } = require('@prisma/client')
const { addDays } = require('date-fns');
const{v4: uuidv4} = require('uuid')
require('dotenv').config();
const prisma = new PrismaClient();


const createRefreshToken = async (user) => {
    const ttlDays = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
    const expiresAt = addDays(new Date(), ttlDays)
    const jti = uuidv4();
    const payload = {
        sub: user.id,
        email: user.email,
        jti
    }
    const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: `${ttlDays}d` });

    const tokenHash = await bcrypt.hash(refreshToken, 10);

    await prisma.refreshToken.create({
        data: {
            userId: user.id,
            tokenHash,
            jti,
            expiresAt
        }
    });
    return refreshToken;
}


const verifyRefreshTokens = async (req, res, next) => {
    const refreshToken = req.body.token;
    try {
        if (!refreshToken) {
            return res.status(401).json({
                message: "Refresh token required"
            })
        }

        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = decoded.sub;

        const storedTokens = await prisma.refreshToken.findMany({
            where: {
                userId,
                expiresAt: {
                    gte: new Date()
                }
            }
        })

        if (!storedTokens.length) {
            return res.status(403).json({
                message: "No valid refresh tokens found"
            })
        }

        let match = null;
        for (const token of storedTokens) {
            const isMatch = await bcrypt.compare(refreshToken, token.tokenHash);
            if (isMatch) {
                match = token;
                break;
            }
        }

        if (!match) {
            return res.status(403).json({ message: "Invalid refresh token" });
        };

        req.user = {
          id: decoded.sub,
          email: decoded.email, 
        };

        next();

    } catch (err) {
        return res
          .status(403)
          .json({ message: "Token verification failed", error: err.message });
    }
}


const deleteRefreshToken = () => {
    
}

module.exports = { createRefreshToken, verifyRefreshTokens };