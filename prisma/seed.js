// prisma/seed.js
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");

async function main() {
  console.log("Starting database seeding...");

  // --- 1. Create Roles ---
  const roles = ["USER", "ADMIN", "EDITOR", "MODERATOR"];
  const roleRecords = {};
  for (const role of roles) {
    roleRecords[role] = await prisma.role.upsert({
      where: { name: role },
      update: {},
      create: { name: role },
    });
  }
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
    { name: "post:update_own", description: "Update only own posts" },
    { name: "post:delete_own", description: "Delete only own posts" },
  ];

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

  // --- 3. Role-Permission linking ---
  const adminPermissions = createdPermissions.map((p) => ({
    roleId: roleRecords.ADMIN.id,
    permissionId: p.id,
  }));

  const moderatorPermissions = createdPermissions
    .filter((p) => p.name.startsWith("post"))
    .map((p) => ({
      roleId: roleRecords.MODERATOR.id,
      permissionId: p.id,
    }));

  const editorPermissions = createdPermissions
    .filter(
      (p) =>
        [
          "post:create",
          "post:read",
          "post:update_own",
          "post:delete_own",
        ].includes(p.name) || p.name.includes("list")
    )
    .map((p) => ({
      roleId: roleRecords.EDITOR.id,
      permissionId: p.id,
    }));

  const userPermissions = createdPermissions
    .filter((p) =>
      [
        "post:read",
        "post:create",
        "post:update_own",
        "post:delete_own",
      ].includes(p.name)
    )
    .map((p) => ({
      roleId: roleRecords.USER.id,
      permissionId: p.id,
    }));

  await prisma.rolePermission.createMany({
    data: [
      ...adminPermissions,
      ...moderatorPermissions,
      ...editorPermissions,
      ...userPermissions,
    ],
    skipDuplicates: true,
  });
  console.log("Role-Permission relationships seeded successfully.");

  // --- 4. Create YOURSELF as the first user and make ADMIN ---
  const myEmail = "victoroluborode@gmail.com"; // <-- change to your real email
  const myFullName = "Victor Oluborode"; // <-- your name
  const myPassword = "SuperSecurePassword123"; // <-- change this, bcrypt will hash

  const hashedPassword = await bcrypt.hash(myPassword, 10);

  const me = await prisma.user.upsert({
    where: { email: myEmail },
    update: {}, // no changes if exists
    create: {
      email: myEmail,
      fullname: myFullName,
      password: hashedPassword,
    },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: me.id, roleId: roleRecords.ADMIN.id } },
    update: {},
    create: { userId: me.id, roleId: roleRecords.ADMIN.id },
  });

  console.log(`✅ Created/ensured ${myEmail} exists and has ADMIN role.`);

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
