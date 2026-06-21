export interface User {
  id: number;
  username: string;
  email: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
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

export interface CryptoProfile {
  version: 1;
  kdf_algorithm: "argon2id";
  kdf_salt: string;
  kdf_parameters: KdfParameters;
  wrap_algorithm: "xchacha20-poly1305-ietf";
  wrapped_vault_key: string;
  wrap_nonce: string;
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

export interface FileMetadata {
  id: number;
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
