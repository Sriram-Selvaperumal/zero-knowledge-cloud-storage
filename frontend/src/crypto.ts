import sodium from "libsodium-wrappers-sumo";

import type {
  CryptoProfile,
  DecryptedManifest,
  FileEncryptionMetadata
} from "./types";


const CHUNK_SIZE = 4 * 1024 * 1024;
const VAULT_KEY_BYTES = 32;
const FILE_ID_BYTES = 16;
const VAULT_AAD_PREFIX = "cloud-storage:v1:vault:";
const FILE_KEY_AAD_PREFIX = "cloud-storage:v1:file-key:";
const MANIFEST_AAD_PREFIX = "cloud-storage:v1:manifest:";
const CHUNK_AAD_PREFIX = "cloud-storage:v1:chunk:";


export interface VaultSetup {
  profile: CryptoProfile;
  vaultKey: Uint8Array;
}

export interface EncryptedFile {
  ciphertext: Blob;
  encryptedFilename: string;
  metadata: FileEncryptionMetadata;
}

export interface DecryptedFile {
  content: Blob;
  manifest: DecryptedManifest;
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


function fileKeyAad(fileId: string): string {
  return `${FILE_KEY_AAD_PREFIX}${fileId}`;
}


function manifestAad(fileId: string): string {
  return `${MANIFEST_AAD_PREFIX}${fileId}`;
}


function chunkAad(fileId: string, index: number): string {
  return `${CHUNK_AAD_PREFIX}${fileId}:${index}`;
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


async function wrapVaultKey(
  password: string,
  userId: number,
  vaultKey: Uint8Array
): Promise<CryptoProfile> {
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


export async function createVaultProfile(
  password: string,
  userId: number
): Promise<VaultSetup> {
  await ready();

  const vaultKey = sodium.randombytes_buf(VAULT_KEY_BYTES);
  const profile = await wrapVaultKey(password, userId, vaultKey);

  return { profile, vaultKey };
}


export async function unlockVault(
  password: string,
  userId: number,
  profile: CryptoProfile
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


function decryptManifestWithKey(
  encryptedFilename: string,
  metadata: FileEncryptionMetadata,
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


export async function decryptFile(
  ciphertext: Blob,
  encryptedFilename: string,
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<DecryptedFile> {
  await ready();

  if (
    metadata.version !== 1
    || metadata.cipher !== "xchacha20-poly1305-secretstream"
  ) {
    throw new Error("Unsupported encrypted file format");
  }

  const fileKey = unwrapFileKey(metadata, vaultKey);

  try {
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
  } finally {
    sodium.memzero(fileKey);
  }
}


export async function zeroKey(key: Uint8Array): Promise<void> {
  await ready();
  sodium.memzero(key);
}
