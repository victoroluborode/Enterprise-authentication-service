/*
  Warnings:

  - You are about to drop the column `token_hash` on the `RefreshToken` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "RefreshToken_token_hash_key";

-- AlterTable
ALTER TABLE "RefreshToken" DROP COLUMN "token_hash";
