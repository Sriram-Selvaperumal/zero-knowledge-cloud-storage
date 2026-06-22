import { decryptFile, decryptSharedFile, encryptFile, zeroKey } from "./crypto";
import type { FileEncryptionMetadata, ShareUnlockResponse } from "./types";


type WorkerRequest =
  | {
      type: "encrypt";
      requestId: string;
      file: File;
      vaultKey: Uint8Array;
    }
  | {
      type: "decrypt";
      requestId: string;
      ciphertext: Blob;
      encryptedFilename: string;
      metadata: FileEncryptionMetadata;
      vaultKey: Uint8Array;
    }
  | {
      type: "decrypt-share";
      requestId: string;
      ciphertext: Blob;
      token: string;
      sharedFile: ShareUnlockResponse;
      vaultKey: Uint8Array;
    };


self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;

  try {
    if (request.type === "encrypt") {
      const result = await encryptFile(
        request.file,
        request.vaultKey,
        (progress) => self.postMessage({
          type: "progress",
          requestId: request.requestId,
          progress
        })
      );
      self.postMessage({
        type: "encrypted",
        requestId: request.requestId,
        result
      });
    } else if (request.type === "decrypt") {
      const result = await decryptFile(
        request.ciphertext,
        request.encryptedFilename,
        request.metadata,
        request.vaultKey,
        (progress) => self.postMessage({
          type: "progress",
          requestId: request.requestId,
          progress
        })
      );
      self.postMessage({
        type: "decrypted",
        requestId: request.requestId,
        result
      });
    } else {
      const result = await decryptSharedFile(
        request.ciphertext,
        request.token,
        request.sharedFile,
        request.vaultKey,
        (progress) => self.postMessage({
          type: "progress",
          requestId: request.requestId,
          progress
        })
      );
      self.postMessage({
        type: "decrypted",
        requestId: request.requestId,
        result
      });
    }
  } catch (error) {
    self.postMessage({
      type: "error",
      requestId: request.requestId,
      message: error instanceof Error ? error.message : "Crypto operation failed"
    });
  } finally {
    await zeroKey(request.vaultKey);
  }
};
