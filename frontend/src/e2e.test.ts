import { describe, expect, it } from "vitest";

import {
  createCryptoProfile,
  deleteFile,
  downloadEncryptedFile,
  getCryptoProfile,
  listFiles,
  login,
  requestRegistrationOtp,
  uploadEncryptedFile,
  verifyRegistrationOtp
} from "./api";
import {
  createVaultProfile,
  decryptFile,
  encryptFile,
  unlockVault,
  zeroKey
} from "./crypto";


const runIntegration = Boolean(import.meta.env.VITE_E2E_API_URL);
const smtpCaptureUrl = import.meta.env.VITE_E2E_SMTP_CAPTURE_URL;


async function waitForOtp(email: string): Promise<string> {
  if (!smtpCaptureUrl) {
    throw new Error("VITE_E2E_SMTP_CAPTURE_URL is not configured");
  }

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const response = await fetch(
      `${smtpCaptureUrl}/otp?email=${encodeURIComponent(email)}`
    );

    if (response.ok) {
      const body = await response.json() as { otp: string };
      return body.otp;
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error("Verification email was not captured");
}


describe.runIf(runIntegration)("encrypted API integration", () => {
  it("registers, initializes a vault, and round-trips ciphertext", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 12);
    const username = `e2e_${suffix}`;
    const email = `${username}@example.com`;
    const password = `Strong-${crypto.randomUUID()}`;
    const plaintext = new TextEncoder().encode("full-stack secret payload");
    const file = new File([plaintext], "secret.txt", { type: "text/plain" });
    let vaultKey: Uint8Array | null = null;
    let unlockedKey: Uint8Array | null = null;
    let token = "";
    let fileId: number | null = null;

    try {
      const challenge = await requestRegistrationOtp(
        username,
        email,
        password
      );
      const otp = await waitForOtp(email);
      const user = await verifyRegistrationOtp(
        challenge.verification_id,
        otp
      );
      token = (await login(username, password)).access_token;
      const setup = await createVaultProfile(password, user.id);
      vaultKey = setup.vaultKey;
      await createCryptoProfile(token, setup.profile);

      const storedProfile = await getCryptoProfile(token);
      unlockedKey = await unlockVault(password, user.id, storedProfile);
      const encrypted = await encryptFile(file, unlockedKey);
      const ciphertextBytes = new Uint8Array(
        await encrypted.ciphertext.arrayBuffer()
      );
      expect(new TextDecoder().decode(ciphertextBytes)).not.toContain(
        "full-stack secret payload"
      );
      const uploaded = await uploadEncryptedFile(
        token,
        encrypted.ciphertext,
        encrypted.encryptedFilename,
        encrypted.metadata
      );
      fileId = uploaded.id;

      const records = await listFiles(token);
      expect(records).toHaveLength(1);
      expect(records[0].encrypted_filename).not.toContain("secret.txt");

      const downloadedCiphertext = await downloadEncryptedFile(token, fileId);

      if (!uploaded.encryption_metadata) {
        throw new Error("Uploaded encryption metadata is missing");
      }

      const decrypted = await decryptFile(
        downloadedCiphertext,
        uploaded.encrypted_filename,
        uploaded.encryption_metadata,
        unlockedKey
      );

      expect(decrypted.manifest).toEqual({
        name: "secret.txt",
        type: "text/plain"
      });
      expect(new Uint8Array(await decrypted.content.arrayBuffer())).toEqual(
        plaintext
      );
    } finally {
      if (token && fileId !== null) {
        await deleteFile(token, fileId).catch(() => undefined);
      }
      if (vaultKey) await zeroKey(vaultKey);
      if (unlockedKey) await zeroKey(unlockedKey);
    }
  });
});
