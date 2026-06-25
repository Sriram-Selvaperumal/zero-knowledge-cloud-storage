import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createVaultPasscodeEnvelope,
  createPasswordProtectedShare,
  createVaultProfile,
  decryptFile,
  decryptManifest,
  decryptSharedFile,
  decryptSharedManifest,
  deriveShareAccess,
  encryptFile,
  hasLocalVaultPasscode,
  rewrapVaultKey,
  removeLocalVaultPasscode,
  saveLocalVaultPasscode,
  unlockVault,
  unlockVaultWithLocalPasscode,
  unlockVaultWithPasscode,
  unlockVaultWithRecoveryKey,
  zeroKey
} from "./crypto";


afterEach(() => {
  vi.unstubAllGlobals();
});


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

  it("wraps the vault key with a local files passcode", async () => {
    const setup = await createVaultProfile("vault-password", 71);
    const envelope = await createVaultPasscodeEnvelope(
      "123456",
      71,
      setup.vaultKey,
      6
    );
    const unlockedWithPasscode = await unlockVaultWithPasscode(
      "123456",
      71,
      envelope
    );

    try {
      expect(Array.from(unlockedWithPasscode)).toEqual(
        Array.from(setup.vaultKey)
      );
      await expect(
        unlockVaultWithPasscode("654321", 71, envelope)
      ).rejects.toThrow();
      await expect(
        createVaultPasscodeEnvelope("12345", 71, setup.vaultKey, 6)
      ).rejects.toThrow();
    } finally {
      await zeroKey(setup.vaultKey);
      await zeroKey(unlockedWithPasscode);
    }
  });

  it("stores and removes a local files passcode envelope", async () => {
    const localStore = new Map<string, string>();
    const localStorageMock = {
      get length() {
        return localStore.size;
      },
      clear: () => localStore.clear(),
      getItem: (key: string) => localStore.get(key) ?? null,
      key: (index: number) => Array.from(localStore.keys())[index] ?? null,
      removeItem: (key: string) => {
        localStore.delete(key);
      },
      setItem: (key: string, value: string) => {
        localStore.set(key, value);
      }
    } as Storage;
    vi.stubGlobal("localStorage", localStorageMock);

    const setup = await createVaultProfile("vault-password", 72);
    const envelope = await saveLocalVaultPasscode(
      "1234",
      72,
      setup.vaultKey,
      4
    );
    const unlockedWithPasscode = await unlockVaultWithLocalPasscode(
      "1234",
      72
    );

    try {
      expect(envelope.wrapped_vault_key).not.toBe("");
      expect(hasLocalVaultPasscode(72)).toBe(true);
      expect(Array.from(unlockedWithPasscode)).toEqual(
        Array.from(setup.vaultKey)
      );

      removeLocalVaultPasscode(72);
      expect(hasLocalVaultPasscode(72)).toBe(false);
    } finally {
      await zeroKey(setup.vaultKey);
      await zeroKey(unlockedWithPasscode);
    }
  });

  it("recovers and rewraps the same vault key", async () => {
    const setup = await createVaultProfile("old-password", 18);
    const recoveredKey = await unlockVaultWithRecoveryKey(
      setup.recoveryKey,
      18,
      setup.profile
    );
    const newProfile = await rewrapVaultKey(
      "new-password",
      18,
      recoveredKey
    );
    const unlockedWithNewPassword = await unlockVault(
      "new-password",
      18,
      { ...setup.profile, ...newProfile }
    );

    try {
      expect(Array.from(recoveredKey)).toEqual(Array.from(setup.vaultKey));
      expect(Array.from(unlockedWithNewPassword)).toEqual(
        Array.from(setup.vaultKey)
      );
      await expect(
        unlockVaultWithRecoveryKey(
          `${setup.recoveryKey}damaged`,
          18,
          setup.profile
        )
      ).rejects.toThrow();
    } finally {
      await zeroKey(setup.vaultKey);
      await zeroKey(recoveredKey);
      await zeroKey(unlockedWithNewPassword);
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

  it("creates a password-protected share without exposing the vault key", async () => {
    const setup = await createVaultProfile("vault-password", 27);
    const plaintext = new TextEncoder().encode("shared secret content");
    const file = new File([plaintext], "shared.txt", { type: "text/plain" });
    let shareKey: Uint8Array | null = null;

    try {
      const encrypted = await encryptFile(file, setup.vaultKey);
      const share = await createPasswordProtectedShare(
        "strong-share-password",
        encrypted.metadata,
        setup.vaultKey
      );
      const accessInfo = {
        id: "share-id",
        version: share.payload.version,
        kdf_algorithm: share.payload.kdf_algorithm,
        kdf_salt: share.payload.kdf_salt,
        kdf_parameters: share.payload.kdf_parameters,
        expires_at: null
      } as const;
      const access = await deriveShareAccess(
        "strong-share-password",
        share.token,
        accessInfo
      );
      shareKey = access.shareKey;
      expect(access.passwordVerifier).toBe(share.payload.password_verifier);

      const sharedFile = {
        share_id: "share-id",
        encrypted_filename: encrypted.encryptedFilename,
        size_bytes: encrypted.ciphertext.size,
        encryption_metadata: {
          version: encrypted.metadata.version,
          cipher: encrypted.metadata.cipher,
          file_id: encrypted.metadata.file_id,
          chunk_size: encrypted.metadata.chunk_size,
          plaintext_size: encrypted.metadata.plaintext_size,
          stream_header: encrypted.metadata.stream_header,
          manifest_nonce: encrypted.metadata.manifest_nonce
        },
        share_envelope: {
          version: share.payload.version,
          wrap_algorithm: share.payload.wrap_algorithm,
          wrapped_file_key: share.payload.wrapped_file_key,
          wrap_nonce: share.payload.wrap_nonce
        },
        download_token: "test-grant",
        download_expires_in_seconds: 300,
        expires_at: null
      } as const;
      const manifest = await decryptSharedManifest(
        share.token,
        sharedFile,
        shareKey
      );
      const decrypted = await decryptSharedFile(
        encrypted.ciphertext,
        share.token,
        sharedFile,
        shareKey
      );

      expect(manifest).toEqual({ name: "shared.txt", type: "text/plain" });
      expect(decrypted.manifest).toEqual(manifest);
      expect(new Uint8Array(await decrypted.content.arrayBuffer())).toEqual(
        plaintext
      );

      const wrongAccess = await deriveShareAccess(
        "incorrect-share-password",
        share.token,
        accessInfo
      );
      try {
        expect(wrongAccess.passwordVerifier).not.toBe(
          share.payload.password_verifier
        );
        await expect(
          decryptSharedManifest(share.token, sharedFile, wrongAccess.shareKey)
        ).rejects.toThrow();
      } finally {
        await zeroKey(wrongAccess.shareKey);
      }
    } finally {
      await zeroKey(setup.vaultKey);
      if (shareKey) await zeroKey(shareKey);
    }
  });
});
