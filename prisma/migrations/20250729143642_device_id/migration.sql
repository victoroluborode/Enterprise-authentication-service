/*
  Warnings:

  - The required column `deviceId` was added to the `refreshToken` table with a prisma-level default value. This is not possible if the table is not empty. Please add this column as optional, then populate it before making it required.

*/
-- AlterTable
ALTER TABLE "refreshToken" ADD COLUMN     "deviceId" TEXT NOT NULL;
