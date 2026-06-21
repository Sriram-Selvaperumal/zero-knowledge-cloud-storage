import type { DecryptedFile, EncryptedFile } from "./crypto";
import type { FileEncryptionMetadata } from "./types";


type WorkerResult = EncryptedFile | DecryptedFile;


function runWorker<T extends WorkerResult>(
  message: Record<string, unknown>,
  resultType: "encrypted" | "decrypted",
  onProgress?: (progress: number) => void
): Promise<T> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL("./crypto.worker.ts", import.meta.url),
      { type: "module" }
    );
    const requestId = crypto.randomUUID();

    worker.onmessage = (event: MessageEvent) => {
      const response = event.data as {
        type: string;
        requestId: string;
        progress?: number;
        result?: T;
        message?: string;
      };

      if (response.requestId !== requestId) {
        return;
      }

      if (response.type === "progress") {
        onProgress?.(response.progress ?? 0);
        return;
      }

      worker.terminate();

      if (response.type === resultType && response.result) {
        resolve(response.result);
      } else {
        reject(new Error(response.message ?? "Crypto worker failed"));
      }
    };

    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || "Crypto worker failed"));
    };

    worker.postMessage({
      ...message,
      requestId,
      vaultKey: new Uint8Array(message.vaultKey as Uint8Array)
    });
  });
}


export function encryptFileInWorker(
  file: File,
  vaultKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<EncryptedFile> {
  return runWorker<EncryptedFile>(
    { type: "encrypt", file, vaultKey },
    "encrypted",
    onProgress
  );
}


export function decryptFileInWorker(
  ciphertext: Blob,
  encryptedFilename: string,
  metadata: FileEncryptionMetadata,
  vaultKey: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<DecryptedFile> {
  return runWorker<DecryptedFile>(
    {
      type: "decrypt",
      ciphertext,
      encryptedFilename,
      metadata,
      vaultKey
    },
    "decrypted",
    onProgress
  );
}
