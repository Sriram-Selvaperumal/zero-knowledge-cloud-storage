import type {
  CryptoProfile,
  CompleteCryptoProfile,
  FileEncryptionMetadata,
  FileShare,
  FileMetadata,
  PasswordCryptoProfile,
  PasswordRecoveryGrant,
  RecoveryProfile,
  RegistrationOtpChallenge,
  ShareAccessInfo,
  ShareCreatePayload,
  ShareUnlockResponse,
  TokenResponse,
  User
} from "./types";


const API_URL = (
  import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

let accessTokenListener: ((token: string) => void) | null = null;


export function setAccessTokenListener(
  listener: ((token: string) => void) | null
): void {
  accessTokenListener = listener;
}


export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}


async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string
): Promise<T> {
  const headers = new Headers(options.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
    credentials: "include"
  });

  if (response.status === 401 && token && path !== "/auth/refresh") {
    const refreshed = await refreshSession();
    accessTokenListener?.(refreshed.access_token);
    headers.set("Authorization", `Bearer ${refreshed.access_token}`);
    response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers,
      credentials: "include"
    });
  }

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;

    try {
      const body = await response.json() as { detail?: string };
      message = body.detail ?? message;
    } catch {
      // Non-JSON errors keep the status message.
    }

    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}


export function requestRegistrationOtp(
  username: string,
  email: string,
  password: string
): Promise<RegistrationOtpChallenge> {
  return request<RegistrationOtpChallenge>("/auth/register/request-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password })
  });
}


export function verifyRegistrationOtp(
  verificationId: string,
  otp: string
): Promise<User> {
  return request<User>("/auth/register/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      verification_id: verificationId,
      otp
    })
  });
}


export function login(
  username: string,
  password: string
): Promise<TokenResponse> {
  const body = new URLSearchParams({ username, password });

  return request<TokenResponse>("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
}


export function refreshSession(): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/refresh", { method: "POST" });
}


export function logout(token: string): Promise<void> {
  return request<void>("/auth/logout", { method: "POST" }, token);
}


export function logoutAll(token: string): Promise<void> {
  return request<void>("/auth/logout-all", { method: "POST" }, token);
}


export function getCurrentUser(token: string): Promise<User> {
  return request<User>("/auth/me", {}, token);
}


export function createCryptoProfile(
  token: string,
  profile: CompleteCryptoProfile
): Promise<CryptoProfile> {
  return request<CryptoProfile>("/auth/crypto-profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile)
  }, token);
}


export function getCryptoProfile(token: string): Promise<CryptoProfile> {
  return request<CryptoProfile>("/auth/crypto-profile", {}, token);
}


export function changePassword(
  token: string,
  currentPassword: string,
  newPassword: string,
  cryptoProfile: PasswordCryptoProfile
): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/password/change", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      crypto_profile: cryptoProfile
    })
  }, token);
}


export function replaceRecoveryKey(
  token: string,
  recoveryProfile: RecoveryProfile
): Promise<RecoveryProfile> {
  return request<RecoveryProfile>("/auth/recovery-key", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ recovery_profile: recoveryProfile })
  }, token);
}


export function requestPasswordRecoveryOtp(
  identifier: string
): Promise<RegistrationOtpChallenge> {
  return request<RegistrationOtpChallenge>(
    "/auth/password/recovery/request-otp",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier })
    }
  );
}


export function verifyPasswordRecoveryOtp(
  verificationId: string,
  otp: string
): Promise<PasswordRecoveryGrant> {
  return request<PasswordRecoveryGrant>(
    "/auth/password/recovery/verify",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        verification_id: verificationId,
        otp
      })
    }
  );
}


export function completePasswordRecovery(
  recoveryToken: string,
  newPassword: string,
  cryptoProfile: PasswordCryptoProfile
): Promise<TokenResponse> {
  return request<TokenResponse>(
    "/auth/password/recovery/complete",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recovery_token: recoveryToken,
        new_password: newPassword,
        crypto_profile: cryptoProfile
      })
    }
  );
}


export function listFiles(token: string): Promise<FileMetadata[]> {
  return request<FileMetadata[]>("/files", {}, token);
}


export function uploadEncryptedFile(
  token: string,
  ciphertext: Blob,
  encryptedFilename: string,
  encryptionMetadata: FileEncryptionMetadata
): Promise<FileMetadata> {
  const form = new FormData();
  form.append("file", ciphertext, "ciphertext.enc");
  form.append("encrypted_filename", encryptedFilename);
  form.append("encryption_metadata", JSON.stringify(encryptionMetadata));

  return request<FileMetadata>("/files/upload", {
    method: "POST",
    body: form
  }, token);
}


export async function downloadEncryptedFile(
  token: string,
  fileId: number
): Promise<Blob> {
  let activeToken = token;
  let response = await fetch(`${API_URL}/files/${fileId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include"
  });

  if (response.status === 401) {
    const refreshed = await refreshSession();
    activeToken = refreshed.access_token;
    accessTokenListener?.(activeToken);
    response = await fetch(`${API_URL}/files/${fileId}/download`, {
      headers: { Authorization: `Bearer ${activeToken}` },
      credentials: "include"
    });
  }

  if (!response.ok) {
    throw new ApiError(response.status, "Unable to download encrypted file");
  }

  return response.blob();
}


export function deleteFile(token: string, fileId: number): Promise<void> {
  return request<void>(`/files/${fileId}`, { method: "DELETE" }, token);
}


export function createFileShare(
  token: string,
  fileId: number,
  payload: ShareCreatePayload,
  expiresAt: string | null
): Promise<FileShare> {
  return request<FileShare>(`/files/${fileId}/shares`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, expires_at: expiresAt })
  }, token);
}


export function listFileShares(
  token: string,
  fileId: number
): Promise<FileShare[]> {
  return request<FileShare[]>(`/files/${fileId}/shares`, {}, token);
}


export function revokeFileShare(
  token: string,
  fileId: number,
  shareId: string
): Promise<void> {
  return request<void>(
    `/files/${fileId}/shares/${shareId}`,
    { method: "DELETE" },
    token
  );
}


export function getShareAccessInfo(token: string): Promise<ShareAccessInfo> {
  return request<ShareAccessInfo>(`/shares/${encodeURIComponent(token)}`);
}


export function unlockFileShare(
  token: string,
  passwordVerifier: string
): Promise<ShareUnlockResponse> {
  return request<ShareUnlockResponse>(
    `/shares/${encodeURIComponent(token)}/unlock`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password_verifier: passwordVerifier })
    }
  );
}


export async function downloadSharedFile(
  token: string,
  downloadToken: string
): Promise<Blob> {
  const response = await fetch(
    `${API_URL}/shares/${encodeURIComponent(token)}/download`,
    { headers: { Authorization: `Share ${downloadToken}` } }
  );

  if (!response.ok) {
    let message = "Unable to download shared file";

    try {
      const body = await response.json() as { detail?: string };
      message = body.detail ?? message;
    } catch {
      // Non-JSON errors keep the default message.
    }

    throw new ApiError(response.status, message);
  }

  return response.blob();
}
