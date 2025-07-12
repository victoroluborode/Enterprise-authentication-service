require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
    const allUsers = await prisma.user.create({
        data: {
            id: 54321,
            email: "oluborodevictor110@gmail.com",
            password: "IAMdamilare170#",
            full_name: "Oluborode Victor"
      }
    });
    allUsers = await prisma.user.findMany();
    console.log(allUsers);
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
