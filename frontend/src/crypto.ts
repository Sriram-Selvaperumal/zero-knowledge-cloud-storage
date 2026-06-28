import sodium from "libsodium-wrappers-sumo";

import type {
  CompleteCryptoProfile,
  DecryptedManifest,
  FileEncryptionMetadata,
  FolderEncryptionMetadata,
  PasswordCryptoProfile,
  RecoveryProfile,
  ShareAccessInfo,
  ShareCreatePayload,
  ShareKeyEnvelope,
  SharedFileEncryptionMetadata,
  ShareUnlockResponse
} from "./types";


const CHUNK_SIZE = 4 * 1024 * 1024;
const VAULT_KEY_BYTES = 32;
const FILE_ID_BYTES = 16;
const FOLDER_ID_BYTES = 16;
const VAULT_AAD_PREFIX = "cloud-storage:v1:vault:";
const RECOVERY_AAD_PREFIX = "cloud-storage:v1:recovery:";
const RECOVERY_KEY_PREFIX = "prototype-recovery-v1:";
const DEVICE_UNLOCK_AAD_PREFIX = "cloud-storage:v1:device-unlock:";
const DEVICE_UNLOCK_STORAGE_PREFIX = "prototype:vault-device-unlock:v1:";
const DEVICE_SECRET_STORAGE_PREFIX = "prototype:vault-device-secret:v1:";
const FILE_KEY_AAD_PREFIX = "cloud-storage:v1:file-key:";
const MANIFEST_AAD_PREFIX = "cloud-storage:v1:manifest:";
const CHUNK_AAD_PREFIX = "cloud-storage:v1:chunk:";
const FOLDER_KEY_AAD_PREFIX = "cloud-storage:v1:folder-key:";
const FOLDER_NAME_AAD_PREFIX = "cloud-storage:v1:folder-name:";
const SHARE_TOKEN_PREFIX = "prototype-share-v1_";
const SHARE_FILE_KEY_AAD_PREFIX = "cloud-storage:v1:share-file-key:";
const SHARE_VERIFIER_PREFIX = "cloud-storage:v1:share-verifier:";


export interface VaultSetup {
  profile: CompleteCryptoProfile;
  vaultKey: Uint8Array;
  recoveryKey: string;
}

export interface RecoverySetup {
  recoveryProfile: RecoveryProfile;
  recoveryKey: string;
}

export interface EncryptedFile {
  ciphertext: Blob;
  encryptedFilename: string;
  metadata: FileEncryptionMetadata;
}

export interface EncryptedFolderName {
  encryptedName: string;
  metadata: FolderEncryptionMetadata;
}

export interface DecryptedFile {
  content: Blob;
  manifest: DecryptedManifest;
}

export interface ShareSetup {
  token: string;
  payload: ShareCreatePayload;
}

export interface ShareAccess {
  shareKey: Uint8Array;
  passwordVerifier: string;
}

export interface LocalDeviceVaultEnvelope {
  version: 1;
  user_id: number;
  wrap_algorithm: "xchacha20-poly1305-ietf";
  wrapped_vault_key: string;
  wrap_nonce: string;
  created_at: string;
  updated_at: string;
}


async function ready(): Promise<void> {
  await sodium.ready;
}


function toBase64(value: Uint8Array): string {
  return sodium.to_base64(value, sodium.base64_variants.ORIGINAL);
}


function fromBase64(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
}


function vaultAad(userId: number): string {
  return `${VAULT_AAD_PREFIX}${userId}`;
}


function recoveryAad(userId: number): string {
  return `${RECOVERY_AAD_PREFIX}${userId}`;
}


function deviceUnlockAad(userId: number): string {
  return `${DEVICE_UNLOCK_AAD_PREFIX}${userId}`;
}


function fileKeyAad(fileId: string): string {
  return `${FILE_KEY_AAD_PREFIX}${fileId}`;
}


function manifestAad(fileId: string): string {
  return `${MANIFEST_AAD_PREFIX}${fileId}`;
}


function chunkAad(fileId: string, index: number): string {
  return `${CHUNK_AAD_PREFIX}${fileId}:${index}`;
}


function folderKeyAad(folderId: string): string {
  return `${FOLDER_KEY_AAD_PREFIX}${folderId}`;
}


function folderNameAad(folderId: string): string {
  return `${FOLDER_NAME_AAD_PREFIX}${folderId}`;
}


function shareFileKeyAad(fileId: string, tokenHash: string): string {
  return `${SHARE_FILE_KEY_AAD_PREFIX}${fileId}:${tokenHash}`;
}


function shareTokenHash(token: string): string {
  return sodium.to_hex(
    sodium.crypto_generichash(32, sodium.from_string(token), null)
  );
}


function sharePasswordVerifier(
  shareKey: Uint8Array,
  tokenHash: string
): string {
  return toBase64(sodium.crypto_generichash(
    32,
    sodium.from_string(`${SHARE_VERIFIER_PREFIX}${tokenHash}`),
    shareKey
  ));
}


function deriveKey(
  password: string,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number
): Uint8Array {
  return sodium.crypto_pwhash(
    VAULT_KEY_BYTES,
    password,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}


function deviceUnlockStorageKey(userId: number): string {
  return `${DEVICE_UNLOCK_STORAGE_PREFIX}${userId}`;
}


function deviceSecretStorageKey(userId: number): string {
  return `${DEVICE_SECRET_STORAGE_PREFIX}${userId}`;
}


function isLocalDeviceVaultEnvelope(
  value: unknown,
  userId: number
): value is LocalDeviceVaultEnvelope {
  if (typeof value !== "object" || value === null) return false;

  const envelope = value as Partial<LocalDeviceVaultEnvelope>;
  return (
    envelope.version === 1
    && envelope.user_id === userId
    && envelope.wrap_algorithm === "xchacha20-poly1305-ietf"
    && typeof envelope.wrapped_vault_key === "string"
    && typeof envelope.wrap_nonce === "string"
  );
}


function loadLocalDeviceSecret(userId: number): Uint8Array | null {
  if (typeof localStorage === "undefined") return null;

  const encodedSecret = localStorage.getItem(deviceSecretStorageKey(userId));
  if (!encodedSecret) return null;

  try {
    const secret = fromBase64(encodedSecret);
    return secret.length === VAULT_KEY_BYTES ? secret : null;
  } catch {
    return null;
  }
}


function hasLocalDeviceSecret(userId: number): boolean {
  if (typeof localStorage === "undefined") return false;
  return localStorage.getItem(deviceSecretStorageKey(userId)) !== null;
}


function getOrCreateLocalDeviceSecret(userId: number): Uint8Array {
  if (typeof localStorage === "undefined") {
    throw new Error("Local device storage is not available");
  }

  const existingSecret = loadLocalDeviceSecret(userId);
  if (existingSecret) return existingSecret;

  const secret = sodium.randombytes_buf(VAULT_KEY_BYTES);
  localStorage.setItem(deviceSecretStorageKey(userId), toBase64(secret));

  return secret;
}


async function wrapVaultKey(
  password: string,
  userId: number,
  vaultKey: Uint8Array
): Promise<PasswordCryptoProfile> {
  await ready();

  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  const derivedKey = deriveKey(password, salt, opslimit, memlimit);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  try {
    const wrappedVaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      vaultAad(userId),
      null,
      nonce,
      derivedKey
    );

    return {
      version: 1,
      kdf_algorithm: "argon2id",
      kdf_salt: toBase64(salt),
      kdf_parameters: { opslimit, memlimit },
      wrap_algorithm: "xchacha20-poly1305-ietf",
      wrapped_vault_key: toBase64(wrappedVaultKey),
      wrap_nonce: toBase64(nonce)
    };
  } finally {
    sodium.memzero(derivedKey);
  }
}


export async function createLocalDeviceVaultEnvelope(
  userId: number,
  vaultKey: Uint8Array
): Promise<LocalDeviceVaultEnvelope> {
  await ready();

  const deviceSecret = getOrCreateLocalDeviceSecret(userId);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const timestamp = new Date().toISOString();

  try {
    const wrappedVaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      deviceUnlockAad(userId),
      null,
      nonce,
      deviceSecret
    );

    return {
      version: 1,
      user_id: userId,
      wrap_algorithm: "xchacha20-poly1305-ietf",
      wrapped_vault_key: toBase64(wrappedVaultKey),
      wrap_nonce: toBase64(nonce),
      created_at: timestamp,
      updated_at: timestamp
    };
  } finally {
    sodium.memzero(deviceSecret);
  }
}


export async function unlockVaultWithLocalDevice(
  userId: number,
  envelope?: LocalDeviceVaultEnvelope | null
): Promise<Uint8Array> {
  await ready();

  const activeEnvelope = envelope ?? loadLocalDeviceVaultEnvelope(userId);
  const deviceSecret = loadLocalDeviceSecret(userId);

  if (!activeEnvelope || !deviceSecret) {
    throw new Error("This device is not trusted for automatic file unlock");
  }

  if (
    activeEnvelope.version !== 1
    || activeEnvelope.user_id !== userId
    || activeEnvelope.wrap_algorithm !== "xchacha20-poly1305-ietf"
  ) {
    sodium.memzero(deviceSecret);
    throw new Error("Unsupported device unlock profile");
  }

  try {
    const vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(activeEnvelope.wrapped_vault_key),
      deviceUnlockAad(userId),
      fromBase64(activeEnvelope.wrap_nonce),
      deviceSecret
    );

    if (vaultKey.length !== VAULT_KEY_BYTES) {
      throw new Error("Invalid vault key length");
    }

    return vaultKey;
  } catch {
    throw new Error("Device unlock data is incorrect or damaged");
  } finally {
    sodium.memzero(deviceSecret);
  }
}


export function loadLocalDeviceVaultEnvelope(
  userId: number
): LocalDeviceVaultEnvelope | null {
  if (typeof localStorage === "undefined") return null;

  const rawEnvelope = localStorage.getItem(deviceUnlockStorageKey(userId));
  if (!rawEnvelope) return null;

  try {
    const envelope = JSON.parse(rawEnvelope) as unknown;
    return isLocalDeviceVaultEnvelope(envelope, userId) ? envelope : null;
  } catch {
    return null;
  }
}


export function hasLocalDeviceVault(userId: number): boolean {
  return (
    loadLocalDeviceVaultEnvelope(userId) !== null
    && hasLocalDeviceSecret(userId)
  );
}


export async function saveLocalDeviceVault(
  userId: number,
  vaultKey: Uint8Array
): Promise<LocalDeviceVaultEnvelope> {
  if (typeof localStorage === "undefined") {
    throw new Error("Local device storage is not available");
  }

  const existing = loadLocalDeviceVaultEnvelope(userId);
  const envelope = await createLocalDeviceVaultEnvelope(
    userId,
    vaultKey
  );
  const envelopeToStore = {
    ...envelope,
    created_at: existing?.created_at ?? envelope.created_at
  };

  localStorage.setItem(
    deviceUnlockStorageKey(userId),
    JSON.stringify(envelopeToStore)
  );

  return envelopeToStore;
}


export function removeLocalDeviceVault(userId: number): void {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem(deviceUnlockStorageKey(userId));
  localStorage.removeItem(deviceSecretStorageKey(userId));
}


export async function rewrapVaultKey(
  password: string,
  userId: number,
  vaultKey: Uint8Array
): Promise<PasswordCryptoProfile> {
  return wrapVaultKey(password, userId, vaultKey);
}


export async function createRecoveryProfile(
  vaultKey: Uint8Array,
  userId: number
): Promise<RecoverySetup> {
  await ready();

  const recoveryKeyBytes = sodium.randombytes_buf(VAULT_KEY_BYTES);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  try {
    const wrappedVaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      recoveryAad(userId),
      null,
      nonce,
      recoveryKeyBytes
    );

    return {
      recoveryKey: RECOVERY_KEY_PREFIX + sodium.to_base64(
        recoveryKeyBytes,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
      recoveryProfile: {
        recovery_version: 1,
        recovery_wrap_algorithm: "xchacha20-poly1305-ietf",
        recovery_wrapped_vault_key: toBase64(wrappedVaultKey),
        recovery_wrap_nonce: toBase64(nonce)
      }
    };
  } finally {
    sodium.memzero(recoveryKeyBytes);
  }
}


export async function createVaultProfile(
  password: string,
  userId: number
): Promise<VaultSetup> {
  await ready();

  const vaultKey = sodium.randombytes_buf(VAULT_KEY_BYTES);

  try {
    const passwordProfile = await wrapVaultKey(password, userId, vaultKey);
    const recovery = await createRecoveryProfile(vaultKey, userId);

    return {
      profile: { ...passwordProfile, ...recovery.recoveryProfile },
      vaultKey,
      recoveryKey: recovery.recoveryKey
    };
  } catch (error) {
    sodium.memzero(vaultKey);
    throw error;
  }
}


export async function unlockVault(
  password: string,
  userId: number,
  profile: PasswordCryptoProfile
): Promise<Uint8Array> {
  await ready();

  if (
    profile.version !== 1
    || profile.kdf_algorithm !== "argon2id"
    || profile.wrap_algorithm !== "xchacha20-poly1305-ietf"
    || profile.kdf_parameters.opslimit < 1
    || profile.kdf_parameters.opslimit > 20
    || profile.kdf_parameters.memlimit < 8 * 1024 * 1024
    || profile.kdf_parameters.memlimit > 512 * 1024 * 1024
  ) {
    throw new Error("Unsupported vault profile");
  }

  const salt = fromBase64(profile.kdf_salt);
  const derivedKey = deriveKey(
    password,
    salt,
    profile.kdf_parameters.opslimit,
    profile.kdf_parameters.memlimit
  );

  try {
    const vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(profile.wrapped_vault_key),
      vaultAad(userId),
      fromBase64(profile.wrap_nonce),
      derivedKey
    );

    if (vaultKey.length !== VAULT_KEY_BYTES) {
      throw new Error("Invalid vault key length");
    }

    return vaultKey;
  } finally {
    sodium.memzero(derivedKey);
  }
}


export async function unlockVaultWithRecoveryKey(
  recoveryKey: string,
  userId: number,
  profile: RecoveryProfile
): Promise<Uint8Array> {
  await ready();

  if (
    profile.recovery_version !== 1
    || profile.recovery_wrap_algorithm !== "xchacha20-poly1305-ietf"
    || !recoveryKey.startsWith(RECOVERY_KEY_PREFIX)
  ) {
    throw new Error("Unsupported recovery profile or key");
  }

  let recoveryKeyBytes: Uint8Array;

  try {
    recoveryKeyBytes = sodium.from_base64(
      recoveryKey.slice(RECOVERY_KEY_PREFIX.length).trim(),
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  } catch {
    throw new Error("Recovery key is invalid");
  }

  if (recoveryKeyBytes.length !== VAULT_KEY_BYTES) {
    sodium.memzero(recoveryKeyBytes);
    throw new Error("Recovery key is invalid");
  }

  try {
    const vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(profile.recovery_wrapped_vault_key),
      recoveryAad(userId),
      fromBase64(profile.recovery_wrap_nonce),
      recoveryKeyBytes
    );

    if (vaultKey.length !== VAULT_KEY_BYTES) {
      throw new Error("Invalid recovered vault key length");
    }

    return vaultKey;
  } catch {
    throw new Error("Recovery key is incorrect or damaged");
  } finally {
    sodium.memzero(recoveryKeyBytes);
  }
}


function unwrapFileKey(
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(metadata.wrapped_file_key),
    fileKeyAad(metadata.file_id),
    fromBase64(metadata.wrapped_file_key_nonce),
    vaultKey
  );
}


function unwrapFolderKey(
  metadata: FolderEncryptionMetadata,
  vaultKey: Uint8Array
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(metadata.wrapped_folder_key),
    folderKeyAad(metadata.folder_id),
    fromBase64(metadata.wrapped_folder_key_nonce),
    vaultKey
  );
}


function unwrapSharedFileKey(
  metadata: SharedFileEncryptionMetadata,
  envelope: ShareKeyEnvelope,
  token: string,
  shareKey: Uint8Array
): Uint8Array {
  if (
    envelope.version !== 1
    || envelope.wrap_algorithm !== "xchacha20-poly1305-ietf"
    || !token.startsWith(SHARE_TOKEN_PREFIX)
  ) {
    throw new Error("Unsupported encrypted share");
  }

  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(envelope.wrapped_file_key),
    shareFileKeyAad(metadata.file_id, shareTokenHash(token)),
    fromBase64(envelope.wrap_nonce),
    shareKey
  );
}


function decryptManifestWithKey(
  encryptedFilename: string,
  metadata: FileEncryptionMetadata | SharedFileEncryptionMetadata,
  fileKey: Uint8Array
): DecryptedManifest {
  const manifestBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(encryptedFilename),
    manifestAad(metadata.file_id),
    fromBase64(metadata.manifest_nonce),
    fileKey
  );
  const manifest = JSON.parse(
    sodium.to_string(manifestBytes)
  ) as DecryptedManifest;

  if (!manifest.name || typeof manifest.name !== "string") {
    throw new Error("Invalid encrypted file manifest");
  }

  return {
    name: manifest.name,
    type: typeof manifest.type === "string"
      ? manifest.type
      : "application/octet-stream"
  };
}


export async function createPasswordProtectedShare(
  password: string,
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array
): Promise<ShareSetup> {
  await ready();

  if (password.length < 12) {
    throw new Error("Share password must contain at least 12 characters");
  }

  const token = SHARE_TOKEN_PREFIX + sodium.to_base64(
    sodium.randombytes_buf(32),
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const tokenHash = shareTokenHash(token);
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  const shareKey = deriveKey(password, salt, opslimit, memlimit);
  const fileKey = unwrapFileKey(metadata, vaultKey);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  try {
    const wrappedFileKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      fileKey,
      shareFileKeyAad(metadata.file_id, tokenHash),
      null,
      nonce,
      shareKey
    );

    return {
      token,
      payload: {
        token_hash: tokenHash,
        version: 1,
        kdf_algorithm: "argon2id",
        kdf_salt: toBase64(salt),
        kdf_parameters: { opslimit, memlimit },
        wrap_algorithm: "xchacha20-poly1305-ietf",
        wrapped_file_key: toBase64(wrappedFileKey),
        wrap_nonce: toBase64(nonce),
        password_verifier: sharePasswordVerifier(shareKey, tokenHash)
      }
    };
  } finally {
    sodium.memzero(fileKey);
    sodium.memzero(shareKey);
  }
}


export async function deriveShareAccess(
  password: string,
  token: string,
  info: ShareAccessInfo
): Promise<ShareAccess> {
  await ready();

  if (
    info.version !== 1
    || info.kdf_algorithm !== "argon2id"
    || !token.startsWith(SHARE_TOKEN_PREFIX)
    || info.kdf_parameters.opslimit < 1
    || info.kdf_parameters.opslimit > 20
    || info.kdf_parameters.memlimit < 8 * 1024 * 1024
    || info.kdf_parameters.memlimit > 512 * 1024 * 1024
  ) {
    throw new Error("Unsupported encrypted share");
  }

  const shareKey = deriveKey(
    password,
    fromBase64(info.kdf_salt),
    info.kdf_parameters.opslimit,
    info.kdf_parameters.memlimit
  );

  return {
    shareKey,
    passwordVerifier: sharePasswordVerifier(
      shareKey,
      shareTokenHash(token)
    )
  };
}


export async function decryptSharedManifest(
  token: string,
  sharedFile: ShareUnlockResponse,
  shareKey: Uint8Array
): Promise<DecryptedManifest> {
  await ready();
  const fileKey = unwrapSharedFileKey(
    sharedFile.encryption_metadata,
    sharedFile.share_envelope,
    token,
    shareKey
  );

  try {
    return decryptManifestWithKey(
      sharedFile.encrypted_filename,
      sharedFile.encryption_metadata,
      fileKey
    );
  } finally {
    sodium.memzero(fileKey);
  }
}


export async function decryptManifest(
  encryptedFilename: string,
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array
): Promise<DecryptedManifest> {
  await ready();
  const fileKey = unwrapFileKey(metadata, vaultKey);

  try {
    return decryptManifestWithKey(encryptedFilename, metadata, fileKey);
  } finally {
    sodium.memzero(fileKey);
  }
}


export async function encryptFolderName(
  name: string,
  vaultKey: Uint8Array
): Promise<EncryptedFolderName> {
  await ready();

  const normalizedName = name.trim();

  if (!normalizedName) {
    throw new Error("Folder name is required");
  }

  if (normalizedName.length > 160) {
    throw new Error("Folder name is too long");
  }

  const folderKey = sodium.randombytes_buf(VAULT_KEY_BYTES);
  const folderId = toBase64(sodium.randombytes_buf(FOLDER_ID_BYTES));
  const wrappedFolderKeyNonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const nameNonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  try {
    const wrappedFolderKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      folderKey,
      folderKeyAad(folderId),
      null,
      wrappedFolderKeyNonce,
      vaultKey
    );
    const encryptedName = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string(JSON.stringify({ name: normalizedName })),
      folderNameAad(folderId),
      null,
      nameNonce,
      folderKey
    );

    return {
      encryptedName: toBase64(encryptedName),
      metadata: {
        version: 1,
        cipher: "xchacha20-poly1305-folder",
        folder_id: folderId,
        wrapped_folder_key: toBase64(wrappedFolderKey),
        wrapped_folder_key_nonce: toBase64(wrappedFolderKeyNonce),
        name_nonce: toBase64(nameNonce)
      }
    };
  } finally {
    sodium.memzero(folderKey);
  }
}


export async function decryptFolderName(
  encryptedName: string,
  metadata: FolderEncryptionMetadata,
  vaultKey: Uint8Array
): Promise<string> {
  await ready();

  if (
    metadata.version !== 1
    || metadata.cipher !== "xchacha20-poly1305-folder"
  ) {
    throw new Error("Unsupported encrypted folder format");
  }

  const folderKey = unwrapFolderKey(metadata, vaultKey);

  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(encryptedName),
      folderNameAad(metadata.folder_id),
      fromBase64(metadata.name_nonce),
      folderKey
    );
    const manifest = JSON.parse(sodium.to_string(plaintext)) as {
      name?: unknown;
    };

    if (!manifest.name || typeof manifest.name !== "string") {
      throw new Error("Invalid encrypted folder name");
    }

    return manifest.name;
  } finally {
    sodium.memzero(folderKey);
  }
}


export async function encryptFile(
  file: File,
  vaultKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<EncryptedFile> {
  await ready();

  const fileKey = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  const fileId = toBase64(sodium.randombytes_buf(FILE_ID_BYTES));
  const wrappedFileKeyNonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const manifestNonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  try {
    const wrappedFileKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      fileKey,
      fileKeyAad(fileId),
      null,
      wrappedFileKeyNonce,
      vaultKey
    );
    const encryptedManifest = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string(JSON.stringify({
        name: file.name,
        type: file.type || "application/octet-stream"
      })),
      manifestAad(fileId),
      null,
      manifestNonce,
      fileKey
    );
    const stream = sodium.crypto_secretstream_xchacha20poly1305_init_push(
      fileKey
    );
    const encryptedChunks: BlobPart[] = [];
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));

    for (let index = 0; index < totalChunks; index += 1) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(file.size, start + CHUNK_SIZE);
      const plaintext = new Uint8Array(
        await file.slice(start, end).arrayBuffer()
      );
      const isFinal = index === totalChunks - 1;
      const tag = isFinal
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      const encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
        stream.state,
        plaintext,
        chunkAad(fileId, index),
        tag
      );

      encryptedChunks.push(encryptedChunk.slice().buffer);
      onProgress?.(Math.round(((index + 1) / totalChunks) * 100));
    }

    return {
      ciphertext: new Blob(encryptedChunks, {
        type: "application/octet-stream"
      }),
      encryptedFilename: toBase64(encryptedManifest),
      metadata: {
        version: 1,
        cipher: "xchacha20-poly1305-secretstream",
        file_id: fileId,
        chunk_size: CHUNK_SIZE,
        plaintext_size: file.size,
        stream_header: toBase64(stream.header),
        wrapped_file_key: toBase64(wrappedFileKey),
        wrapped_file_key_nonce: toBase64(wrappedFileKeyNonce),
        manifest_nonce: toBase64(manifestNonce)
      }
    };
  } finally {
    sodium.memzero(fileKey);
  }
}


async function decryptFileWithKey(
  ciphertext: Blob,
  encryptedFilename: string,
  metadata: FileEncryptionMetadata | SharedFileEncryptionMetadata,
  fileKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<DecryptedFile> {
  if (
    metadata.version !== 1
    || metadata.cipher !== "xchacha20-poly1305-secretstream"
  ) {
    throw new Error("Unsupported encrypted file format");
  }

  const manifest = decryptManifestWithKey(
    encryptedFilename,
    metadata,
    fileKey
  );
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    fromBase64(metadata.stream_header),
    fileKey
  );
  const plaintextChunks: BlobPart[] = [];
  const totalChunks = Math.max(
    1,
    Math.ceil(metadata.plaintext_size / metadata.chunk_size)
  );
  let cipherOffset = 0;
  let plaintextOffset = 0;

  for (let index = 0; index < totalChunks; index += 1) {
    const plaintextLength = Math.min(
      metadata.chunk_size,
      metadata.plaintext_size - plaintextOffset
    );
    const cipherLength = plaintextLength
      + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
    const cipherChunk = new Uint8Array(
      await ciphertext.slice(
        cipherOffset,
        cipherOffset + cipherLength
      ).arrayBuffer()
    );
    const result = sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      cipherChunk,
      chunkAad(metadata.file_id, index)
    );

    if (!result) {
      throw new Error("Ciphertext authentication failed");
    }

    const isFinal = index === totalChunks - 1;
    const expectedTag = isFinal
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    if (result.tag !== expectedTag) {
      throw new Error("Encrypted stream ended unexpectedly");
    }

    plaintextChunks.push(result.message.slice().buffer);
    cipherOffset += cipherLength;
    plaintextOffset += result.message.length;
    onProgress?.(Math.round(((index + 1) / totalChunks) * 100));
  }

  if (
    cipherOffset !== ciphertext.size
    || plaintextOffset !== metadata.plaintext_size
  ) {
    throw new Error("Encrypted file length does not match its metadata");
  }

  return {
    content: new Blob(plaintextChunks, { type: manifest.type }),
    manifest
  };
}


export async function decryptFile(
  ciphertext: Blob,
  encryptedFilename: string,
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<DecryptedFile> {
  await ready();
  const fileKey = unwrapFileKey(metadata, vaultKey);

  try {
    return await decryptFileWithKey(
      ciphertext,
      encryptedFilename,
      metadata,
      fileKey,
      onProgress
    );
  } finally {
    sodium.memzero(fileKey);
  }
}


export async function decryptSharedFile(
  ciphertext: Blob,
  token: string,
  sharedFile: ShareUnlockResponse,
  shareKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<DecryptedFile> {
  await ready();
  const fileKey = unwrapSharedFileKey(
    sharedFile.encryption_metadata,
    sharedFile.share_envelope,
    token,
    shareKey
  );

  try {
    return await decryptFileWithKey(
      ciphertext,
      sharedFile.encrypted_filename,
      sharedFile.encryption_metadata,
      fileKey,
      onProgress
    );
  } finally {
    sodium.memzero(fileKey);
  }
}


export async function zeroKey(key: Uint8Array): Promise<void> {
  await ready();
  sodium.memzero(key);
}
