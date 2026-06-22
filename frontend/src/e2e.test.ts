import { describe, expect, it } from "vitest";

import {
  changePassword,
  completePasswordRecovery,
  createCryptoProfile,
  createFileShare,
  deleteFile,
  downloadSharedFile,
  downloadEncryptedFile,
  getCryptoProfile,
  getShareAccessInfo,
  listFiles,
  login,
  requestPasswordRecoveryOtp,
  requestRegistrationOtp,
  revokeFileShare,
  uploadEncryptedFile,
  unlockFileShare,
  verifyPasswordRecoveryOtp,
  verifyRegistrationOtp
} from "./api";
import {
  createPasswordProtectedShare,
  createVaultProfile,
  decryptFile,
  decryptSharedFile,
  deriveShareAccess,
  encryptFile,
  rewrapVaultKey,
  unlockVault,
  unlockVaultWithRecoveryKey,
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
    let recoveredKey: Uint8Array | null = null;
    let sharedKey: Uint8Array | null = null;
    let recoveryKey = "";
    let token = "";
    let fileId: number | null = null;
    let shareId: string | null = null;
    let shareToken = "";

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
      recoveryKey = setup.recoveryKey;
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

      const sharePassword = `Share-${crypto.randomUUID()}`;
      const shareSetup = await createPasswordProtectedShare(
        sharePassword,
        uploaded.encryption_metadata,
        unlockedKey
      );
      shareToken = shareSetup.token;
      const shareRecord = await createFileShare(
        token,
        fileId,
        shareSetup.payload,
        new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      );
      shareId = shareRecord.id;
      const shareInfo = await getShareAccessInfo(shareToken);
      const shareAccess = await deriveShareAccess(
        sharePassword,
        shareToken,
        shareInfo
      );
      sharedKey = shareAccess.shareKey;
      const sharedFile = await unlockFileShare(
        shareToken,
        shareAccess.passwordVerifier
      );
      const sharedCiphertext = await downloadSharedFile(
        shareToken,
        sharedFile.download_token
      );
      const sharedPlaintext = await decryptSharedFile(
        sharedCiphertext,
        shareToken,
        sharedFile,
        sharedKey
      );
      expect(sharedPlaintext.manifest.name).toBe("secret.txt");
      expect(
        new Uint8Array(await sharedPlaintext.content.arrayBuffer())
      ).toEqual(plaintext);
      await revokeFileShare(token, fileId, shareId);
      shareId = null;
      await expect(getShareAccessInfo(shareToken)).rejects.toThrow();

      const changedPassword = `Changed-${crypto.randomUUID()}`;
      const changedProfile = await rewrapVaultKey(
        changedPassword,
        user.id,
        unlockedKey
      );
      token = (await changePassword(
        token,
        password,
        changedPassword,
        changedProfile
      )).access_token;
      await expect(login(username, password)).rejects.toThrow();
      expect((await login(username, changedPassword)).access_token).toBeTruthy();

      const recoveryChallenge = await requestPasswordRecoveryOtp(email);
      const recoveryOtp = await waitForOtp(email);
      const recoveryGrant = await verifyPasswordRecoveryOtp(
        recoveryChallenge.verification_id,
        recoveryOtp
      );
      recoveredKey = await unlockVaultWithRecoveryKey(
        recoveryKey,
        user.id,
        recoveryGrant.recovery_profile
      );
      const recoveredPassword = `Recovered-${crypto.randomUUID()}`;
      const recoveredProfile = await rewrapVaultKey(
        recoveredPassword,
        user.id,
        recoveredKey
      );
      token = (await completePasswordRecovery(
        recoveryGrant.recovery_token,
        recoveredPassword,
        recoveredProfile
      )).access_token;

      const ciphertextAfterRecovery = await downloadEncryptedFile(
        token,
        fileId
      );
      const decryptedAfterRecovery = await decryptFile(
        ciphertextAfterRecovery,
        uploaded.encrypted_filename,
        uploaded.encryption_metadata,
        recoveredKey
      );
      expect(
        new Uint8Array(await decryptedAfterRecovery.content.arrayBuffer())
      ).toEqual(plaintext);
    } finally {
      if (token && fileId !== null) {
        if (shareId) {
          await revokeFileShare(token, fileId, shareId).catch(() => undefined);
        }
        await deleteFile(token, fileId).catch(() => undefined);
      }
      if (vaultKey) await zeroKey(vaultKey);
      if (unlockedKey) await zeroKey(unlockedKey);
      if (recoveredKey) await zeroKey(recoveredKey);
      if (sharedKey) await zeroKey(sharedKey);
    }
  }, 20_000);
});
