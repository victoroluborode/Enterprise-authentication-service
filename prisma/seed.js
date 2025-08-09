// prisma/seed.js
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  console.log("Starting database seeding...");

  // --- 1. Create Roles ---
  const userRole = await prisma.role.upsert({
    where: { name: "USER" },
    update: {},
    create: { name: "USER" },
  });
  const adminRole = await prisma.role.upsert({
    where: { name: "ADMIN" },
    update: {},
    create: { name: "ADMIN" },
  });
  const editorRole = await prisma.role.upsert({
    where: { name: "EDITOR" },
    update: {},
    create: { name: "EDITOR" },
  });
  console.log("Roles seeded successfully.");

  // --- 2. Create Permissions ---
  const permissionsToCreate = [
    { name: "roles:list", description: "List all roles" },
    { name: "permissions:list", description: "List all permissions" },
    { name: "user:role:assign", description: "Assign a role to a user" },
    { name: "user:role:remove", description: "Remove a role from a user" },
    {
      name: "role:permission:assign",
      description: "Assign a permission to a role",
    },
    {
      name: "role:permission:remove",
      description: "Remove a permission from a role",
    },
    { name: "post:create", description: "Create a new post" },
    { name: "post:read", description: "Read any post" },
    { name: "post:update", description: "Update any post" },
    { name: "post:delete", description: "Delete any post" },
  ];

  // We use Promise.all to create all permissions in parallel for better performance
  const createdPermissions = await Promise.all(
    permissionsToCreate.map((p) =>
      prisma.permission.upsert({
        where: { name: p.name },
        update: {},
        create: p,
      })
    )
  );
  console.log("Permissions seeded successfully.");

  // --- 3. Link Permissions to Roles (RolePermission table) ---

  // ADMIN gets all permissions
  const adminPermissions = createdPermissions.map((p) => ({
    roleId: adminRole.id,
    permissionId: p.id,
  }));

  // EDITOR gets post-related permissions and the ability to list things
  const editorPermissions = createdPermissions
    .filter((p) => p.name.includes("post") || p.name.includes("list"))
    .map((p) => ({
      roleId: editorRole.id,
      permissionId: p.id,
    }));

  // USER gets read and create permissions
  const userPermissions = createdPermissions
    .filter((p) => p.name === "post:read" || p.name === "post:create")
    .map((p) => ({
      roleId: userRole.id,
      permissionId: p.id,
    }));

  await prisma.rolePermission.createMany({
    data: [...adminPermissions, ...editorPermissions, ...userPermissions],
    skipDuplicates: true,
  });
  console.log("Role-Permission relationships seeded successfully.");

  // --- 4. Assign ADMIN role to a test user ---
  // Replace the email below with an email from a user that already exists in your database
  const testUser = await prisma.user.findUnique({
    where: { email: "collins110@gmail.com" },
  });

  if (testUser) {
    await prisma.userRole.upsert({
      where: { userId_roleId: { userId: testUser.id, roleId: adminRole.id } },
      update: {},
      create: { userId: testUser.id, roleId: adminRole.id },
    });
    console.log(`Assigned 'ADMIN' role to ${testUser.email}.`);
  } else {
    console.warn("Test user not found. Skipping role assignment.");
  }

  console.log("Database seeding complete.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
