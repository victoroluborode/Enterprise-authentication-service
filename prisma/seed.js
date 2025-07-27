// prisma/seed.js
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  // Create roles if they don't exist
  await prisma.role.upsert({
    where: { name: "USER" },
    update: {},
    create: { name: "USER" },
  });
  await prisma.role.upsert({
    where: { name: "ADMIN" },
    update: {},
    create: { name: "ADMIN" },
  });
  await prisma.role.upsert({
    where: { name: "EDITOR" },
    update: {},
    create: { name: "EDITOR" },
  });

  console.log("Roles seeded successfully.");

  // Example: Assign 'USER' role to an existing user (e.g., your test user)
  // You'll need to find the user first
  const testUser = await prisma.user.findUnique({
    where: { email: "linkedIn110@gmail.com" }, // Use an email from your existing users
  });

  if (testUser) {
    const userRole = await prisma.role.findUnique({ where: { name: "USER" } });
    if (userRole) {
      await prisma.userRole.upsert({
        where: { userId_roleId: { userId: testUser.id, roleId: userRole.id } },
        update: {},
        create: { userId: testUser.id, roleId: userRole.id },
      });
      console.log(`Assigned 'USER' role to ${testUser.email}.`);
    }
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
