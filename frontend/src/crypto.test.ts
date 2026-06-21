import { describe, expect, it } from "vitest";

import {
  createVaultProfile,
  decryptFile,
  decryptManifest,
  encryptFile,
  unlockVault,
  zeroKey
} from "./crypto";


describe("client-side encryption protocol", () => {
  it("wraps a vault key and round-trips an encrypted file", async () => {
    const password = "correct horse battery staple";
    const userId = 42;
    const setup = await createVaultProfile(password, userId);
    const unlockedKey = await unlockVault(password, userId, setup.profile);
    const plaintext = new TextEncoder().encode(
      "confidential file content"
    );
    const file = new File(
      [plaintext],
      "notes.txt",
      { type: "text/plain" }
    );

    try {
      expect(Array.from(unlockedKey)).toEqual(Array.from(setup.vaultKey));

      const encrypted = await encryptFile(file, unlockedKey);
      const manifest = await decryptManifest(
        encrypted.encryptedFilename,
        encrypted.metadata,
        unlockedKey
      );
      const decrypted = await decryptFile(
        encrypted.ciphertext,
        encrypted.encryptedFilename,
        encrypted.metadata,
        unlockedKey
      );

      expect(manifest).toEqual({ name: "notes.txt", type: "text/plain" });
      expect(decrypted.manifest).toEqual(manifest);
      expect(new Uint8Array(await decrypted.content.arrayBuffer())).toEqual(
        plaintext
      );
    } finally {
      await zeroKey(setup.vaultKey);
      await zeroKey(unlockedKey);
    }
  });

  it("rejects an incorrect vault password", async () => {
    const setup = await createVaultProfile("right-password", 7);

    try {
      await expect(
        unlockVault("wrong-password", 7, setup.profile)
      ).rejects.toThrow();
    } finally {
      await zeroKey(setup.vaultKey);
    }
  });

  it("rejects modified ciphertext", async () => {
    const setup = await createVaultProfile("tamper-test-password", 9);
    const file = new File(
      [new Uint8Array([1, 2, 3, 4, 5])],
      "payload.bin",
      { type: "application/octet-stream" }
    );

    try {
      const encrypted = await encryptFile(file, setup.vaultKey);
      const tamperedBytes = new Uint8Array(
        await encrypted.ciphertext.arrayBuffer()
      );
      tamperedBytes[0] ^= 0xff;

      await expect(
        decryptFile(
          new Blob([tamperedBytes]),
          encrypted.encryptedFilename,
          encrypted.metadata,
          setup.vaultKey
        )
      ).rejects.toThrow();
    } finally {
      await zeroKey(setup.vaultKey);
    }
  });
});
