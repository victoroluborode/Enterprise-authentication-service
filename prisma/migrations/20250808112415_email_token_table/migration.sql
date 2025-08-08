/*
  Warnings:

  - A unique constraint covering the columns `[tokenId]` on the table `EmailVerificationToken` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `tokenId` to the `EmailVerificationToken` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "EmailVerificationToken" ADD COLUMN     "tokenId" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "EmailVerificationToken_tokenId_key" ON "EmailVerificationToken"("tokenId");
