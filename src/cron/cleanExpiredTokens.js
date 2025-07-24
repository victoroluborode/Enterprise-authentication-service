const cron = require('node-cron');
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

cron.schedule('0 * * * *', async () => {
    try {
        const now = new Date();
        const result = await prisma.RefreshToken.deleteMany({
            where: {
                expiresAt: { lt: now }
            }
        });
        console.log(`[CRON] Deleted ${result.count} expired refresh tokens.`);
    } catch (err) {
        console.error("[CRON] Error deleting expired tokens:", err);
    }
})