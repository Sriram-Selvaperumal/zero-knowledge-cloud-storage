export interface User {
  id: number;
  username: string;
  email: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in_seconds: number;
}

export interface RegistrationOtpChallenge {
  verification_id: string;
  expires_in_seconds: number;
  resend_after_seconds: number;
  message: string;
}

export interface KdfParameters {
  opslimit: number;
  memlimit: number;
}

export interface PasswordCryptoProfile {
  version: 1;
  kdf_algorithm: "argon2id";
  kdf_salt: string;
  kdf_parameters: KdfParameters;
  wrap_algorithm: "xchacha20-poly1305-ietf";
  wrapped_vault_key: string;
  wrap_nonce: string;
}

export interface RecoveryProfile {
  recovery_version: 1;
  recovery_wrap_algorithm: "xchacha20-poly1305-ietf";
  recovery_wrapped_vault_key: string;
  recovery_wrap_nonce: string;
}

export interface CompleteCryptoProfile extends PasswordCryptoProfile, RecoveryProfile {}

export interface CryptoProfile extends PasswordCryptoProfile {
  recovery_version: 1 | null;
  recovery_wrap_algorithm: "xchacha20-poly1305-ietf" | null;
  recovery_wrapped_vault_key: string | null;
  recovery_wrap_nonce: string | null;
}

export interface PasswordRecoveryGrant {
  recovery_token: string;
  user_id: number;
  recovery_profile: RecoveryProfile;
}

export interface FileEncryptionMetadata {
  version: 1;
  cipher: "xchacha20-poly1305-secretstream";
  file_id: string;
  chunk_size: number;
  plaintext_size: number;
  stream_header: string;
  wrapped_file_key: string;
  wrapped_file_key_nonce: string;
  manifest_nonce: string;
}

export interface FolderEncryptionMetadata {
  version: 1;
  cipher: "xchacha20-poly1305-folder";
  folder_id: string;
  wrapped_folder_key: string;
  wrapped_folder_key_nonce: string;
  name_nonce: string;
}

export interface FileMetadata {
  id: number;
  folder_id: number | null;
  encrypted_filename: string;
  content_type: string | null;
  size_bytes: number;
  encryption_metadata: FileEncryptionMetadata | null;
  created_at: string;
  updated_at: string;
}

export interface DecryptedManifest {
  name: string;
  type: string;
}

export interface DisplayFile extends FileMetadata {
  manifest: DecryptedManifest | null;
}

export interface FolderMetadata {
  id: number;
  parent_id: number | null;
  encrypted_name: string;
  encryption_metadata: FolderEncryptionMetadata;
  created_at: string;
  updated_at: string;
}

export interface DisplayFolder extends FolderMetadata {
  name: string | null;
}

export interface ShareCreatePayload {
  token_hash: string;
  version: 1;
  kdf_algorithm: "argon2id";
  kdf_salt: string;
  kdf_parameters: KdfParameters;
  wrap_algorithm: "xchacha20-poly1305-ietf";
  wrapped_file_key: string;
  wrap_nonce: string;
  password_verifier: string;
}

export interface FileShare {
  id: string;
  file_id: number;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ShareAccessInfo {
  id: string;
  version: 1;
  kdf_algorithm: "argon2id";
  kdf_salt: string;
  kdf_parameters: KdfParameters;
  expires_at: string | null;
}

export interface SharedFileEncryptionMetadata {
  version: 1;
  cipher: "xchacha20-poly1305-secretstream";
  file_id: string;
  chunk_size: number;
  plaintext_size: number;
  stream_header: string;
  manifest_nonce: string;
}

export interface ShareKeyEnvelope {
  version: 1;
  wrap_algorithm: "xchacha20-poly1305-ietf";
  wrapped_file_key: string;
  wrap_nonce: string;
}

export interface ShareUnlockResponse {
  share_id: string;
  encrypted_filename: string;
  size_bytes: number;
  encryption_metadata: SharedFileEncryptionMetadata;
  share_envelope: ShareKeyEnvelope;
  download_token: string;
  download_expires_in_seconds: number;
  expires_at: string | null;
}
