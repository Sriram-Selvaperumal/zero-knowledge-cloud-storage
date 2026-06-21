import type {
  CryptoProfile,
  FileEncryptionMetadata,
  FileMetadata,
  RegistrationOtpChallenge,
  TokenResponse,
  User
} from "./types";


const API_URL = (
  import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");


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

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers
  });

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


export function getCurrentUser(token: string): Promise<User> {
  return request<User>("/auth/me", {}, token);
}


export function createCryptoProfile(
  token: string,
  profile: CryptoProfile
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
  const response = await fetch(`${API_URL}/files/${fileId}/download`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!response.ok) {
    throw new ApiError(response.status, "Unable to download encrypted file");
  }

  return response.blob();
}


export function deleteFile(token: string, fileId: number): Promise<void> {
  return request<void>(`/files/${fileId}`, { method: "DELETE" }, token);
}
