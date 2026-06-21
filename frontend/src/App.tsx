import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Cloud,
  Download,
  FileLock2,
  FolderOpen,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MailCheck,
  RotateCw,
  ShieldCheck,
  Trash2,
  UploadCloud
} from "lucide-react";
import {
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";

import {
  ApiError,
  createCryptoProfile,
  deleteFile,
  downloadEncryptedFile,
  getCryptoProfile,
  getCurrentUser,
  listFiles,
  login,
  requestRegistrationOtp,
  verifyRegistrationOtp,
  uploadEncryptedFile
} from "./api";
import {
  decryptFileInWorker,
  encryptFileInWorker
} from "./crypto-worker-client";
import type { DisplayFile, User } from "./types";


interface Session {
  token: string;
  user: User;
  vaultKey: Uint8Array;
}

interface Notice {
  tone: "success" | "error";
  message: string;
}

interface PendingRegistration {
  verificationId: string;
  username: string;
  email: string;
  password: string;
  expiresInSeconds: number;
  resendAfterSeconds: number;
}

const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;


function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";

  const units = ["B", "KB", "MB", "GB"];
  const unitIndex = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const value = bytes / (1024 ** unitIndex);

  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}


function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}


function getErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return error.message;
  }

  return "Something went wrong";
}


export default function App() {
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [session, setSession] = useState<Session | null>(null);
  const [files, setFiles] = useState<DisplayFile[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [fileBusy, setFileBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [pendingRegistration, setPendingRegistration] = (
    useState<PendingRegistration | null>(null)
  );
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadFiles = useCallback(async (activeSession: Session) => {
    setLoadingFiles(true);

    try {
      const { decryptManifest } = await import("./crypto");
      const records = await listFiles(activeSession.token);
      const displayRecords = await Promise.all(
        records.map(async (record): Promise<DisplayFile> => {
          if (!record.encryption_metadata) {
            return { ...record, manifest: null };
          }

          try {
            const manifest = await decryptManifest(
              record.encrypted_filename,
              record.encryption_metadata,
              activeSession.vaultKey
            );
            return { ...record, manifest };
          } catch {
            return { ...record, manifest: null };
          }
        })
      );

      setFiles(displayRecords);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setLoadingFiles(false);
    }
  }, []);

  useEffect(() => {
    if (session) {
      void loadFiles(session);
    }
  }, [loadFiles, session]);

  useEffect(() => {
    if (!pendingRegistration || pendingRegistration.resendAfterSeconds <= 0) {
      return;
    }

    const timer = window.setTimeout(() => {
      setPendingRegistration((current) => current ? {
        ...current,
        resendAfterSeconds: Math.max(0, current.resendAfterSeconds - 1)
      } : null);
    }, 1000);

    return () => window.clearTimeout(timer);
  }, [pendingRegistration]);

  useEffect(() => {
    return () => {
      if (session) {
        void import("./crypto").then(({ zeroKey }) => (
          zeroKey(session.vaultKey)
        ));
      }
    };
  }, [session]);

  const totalPlaintextBytes = useMemo(
    () => files.reduce(
      (total, file) => total + (
        file.encryption_metadata?.plaintext_size ?? 0
      ),
      0
    ),
    [files]
  );

  async function establishSession(
    username: string,
    password: string,
    registeredUser?: User
  ) {
      const tokenResponse = await login(username, password);
      const token = tokenResponse.access_token;
      const user = registeredUser ?? await getCurrentUser(token);

      let vaultKey: Uint8Array;
      const { createVaultProfile, unlockVault } = await import("./crypto");

      try {
        const profile = await getCryptoProfile(token);
        vaultKey = await unlockVault(password, user.id, profile);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          const setup = await createVaultProfile(password, user.id);

          try {
            await createCryptoProfile(token, setup.profile);
            vaultKey = setup.vaultKey;
          } catch (profileError) {
            const { zeroKey } = await import("./crypto");
            await zeroKey(setup.vaultKey);
            throw profileError;
          }
        } else {
          throw error;
        }
      }

      setSession({ token, user, vaultKey });
      setNotice({ tone: "success", message: "Vault unlocked" });
  }

  async function handleAuthentication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthBusy(true);
    setNotice(null);

    const form = new FormData(event.currentTarget);
    const username = String(form.get("username") ?? "").trim();
    const email = String(form.get("email") ?? "").trim();
    const password = String(form.get("password") ?? "");

    try {
      if (authMode === "register") {
        const challenge = await requestRegistrationOtp(
          username,
          email,
          password
        );
        setPendingRegistration({
          verificationId: challenge.verification_id,
          username,
          email,
          password,
          expiresInSeconds: challenge.expires_in_seconds,
          resendAfterSeconds: challenge.resend_after_seconds
        });
        setNotice({
          tone: "success",
          message: "Verification code sent"
        });
        return;
      }

      await establishSession(username, password);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleOtpVerification(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    if (!pendingRegistration) return;

    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const otp = String(form.get("otp") ?? "").trim();

    try {
      const user = await verifyRegistrationOtp(
        pendingRegistration.verificationId,
        otp
      );
      await establishSession(
        pendingRegistration.username,
        pendingRegistration.password,
        user
      );
      setPendingRegistration(null);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleResendOtp() {
    if (!pendingRegistration) return;

    setAuthBusy(true);
    setNotice(null);

    try {
      const challenge = await requestRegistrationOtp(
        pendingRegistration.username,
        pendingRegistration.email,
        pendingRegistration.password
      );
      setPendingRegistration({
        ...pendingRegistration,
        verificationId: challenge.verification_id,
        expiresInSeconds: challenge.expires_in_seconds,
        resendAfterSeconds: challenge.resend_after_seconds
      });
      setNotice({ tone: "success", message: "New code sent" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleUpload(file: File) {
    if (!session || fileBusy) return;

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setNotice({
        tone: "error",
        message: "File exceeds the 100 MB limit"
      });
      return;
    }

    setFileBusy(true);
    setProgress(0);
    setNotice(null);

    try {
      const encrypted = await encryptFileInWorker(
        file,
        session.vaultKey,
        setProgress
      );
      await uploadEncryptedFile(
        session.token,
        encrypted.ciphertext,
        encrypted.encryptedFilename,
        encrypted.metadata
      );
      await loadFiles(session);
      setNotice({ tone: "success", message: `${file.name} uploaded` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
      setProgress(0);

      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  }

  function handleFileSelection(event: ChangeEvent<HTMLInputElement>) {
    const selectedFile = event.target.files?.[0];

    if (selectedFile) {
      void handleUpload(selectedFile);
    }
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files[0];

    if (droppedFile) {
      void handleUpload(droppedFile);
    }
  }

  async function handleDownload(file: DisplayFile) {
    if (!session || fileBusy || !file.encryption_metadata) return;

    setFileBusy(true);
    setProgress(0);
    setNotice(null);

    try {
      const ciphertext = await downloadEncryptedFile(session.token, file.id);
      const decrypted = await decryptFileInWorker(
        ciphertext,
        file.encrypted_filename,
        file.encryption_metadata,
        session.vaultKey,
        setProgress
      );
      const url = URL.createObjectURL(decrypted.content);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = decrypted.manifest.name;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setNotice({ tone: "success", message: `${decrypted.manifest.name} ready` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
      setProgress(0);
    }
  }

  async function handleDelete(file: DisplayFile) {
    if (!session || fileBusy) return;

    const name = file.manifest?.name ?? "this encrypted file";

    if (!window.confirm(`Delete ${name}?`)) {
      return;
    }

    setFileBusy(true);
    setNotice(null);

    try {
      await deleteFile(session.token, file.id);
      await loadFiles(session);
      setNotice({ tone: "success", message: `${name} deleted` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
    }
  }

  async function handleLogout() {
    setSession(null);
    setFiles([]);
    setNotice(null);
  }

  if (!session) {
    return (
      <main className="auth-shell">
        <section className="auth-brand" aria-label="Prototype">
          <div className="brand-lockup">
            <div className="brand-mark"><LockKeyhole size={24} /></div>
            <span>Prototype</span>
          </div>
          <div className="auth-state">
            <ShieldCheck size={34} />
            <h1>Your private vault</h1>
            <p>Unlock on this device.</p>
          </div>
          <div className="protocol-label">E2EE protocol v1</div>
        </section>

        <section className="auth-panel">
          <div className="auth-form-wrap">
            <div className="auth-heading">
              {pendingRegistration ? (
                <MailCheck size={26} />
              ) : (
                <KeyRound size={26} />
              )}
              <div>
                <h2>{pendingRegistration ? "Verify email" : authMode === "login" ? "Sign in" : "Create vault"}</h2>
                <p>{pendingRegistration ? `Code sent to ${pendingRegistration.email}. Expires in ${Math.ceil(pendingRegistration.expiresInSeconds / 60)} minutes.` : authMode === "login" ? "Enter your vault credentials" : "Set your vault credentials"}</p>
              </div>
            </div>

            {!pendingRegistration && (
              <div className="segmented-control" role="tablist" aria-label="Authentication mode">
                <button
                  type="button"
                  className={authMode === "login" ? "active" : ""}
                  onClick={() => {
                    setAuthMode("login");
                    setNotice(null);
                  }}
                  role="tab"
                  aria-selected={authMode === "login"}
                >
                  Sign in
                </button>
                <button
                  type="button"
                  className={authMode === "register" ? "active" : ""}
                  onClick={() => {
                    setAuthMode("register");
                    setNotice(null);
                  }}
                  role="tab"
                  aria-selected={authMode === "register"}
                >
                  Register
                </button>
              </div>
            )}

            {pendingRegistration ? (
              <form key="otp-form" className="auth-form" onSubmit={handleOtpVerification}>
                <label>
                  Verification code
                  <input
                    name="otp"
                    required
                    minLength={6}
                    maxLength={6}
                    pattern="[0-9]{6}"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    autoFocus
                  />
                </label>

                <button className="primary-button" type="submit" disabled={authBusy}>
                  {authBusy ? <LoaderCircle className="spin" size={18} /> : <MailCheck size={18} />}
                  Verify and create vault
                </button>

                <div className="auth-actions">
                  <button className="secondary-button" type="button" onClick={() => void handleResendOtp()} disabled={authBusy || pendingRegistration.resendAfterSeconds > 0}>
                    <RotateCw size={16} />
                    {pendingRegistration.resendAfterSeconds > 0 ? `Resend in ${pendingRegistration.resendAfterSeconds}s` : "Resend code"}
                  </button>
                  <button className="secondary-button" type="button" onClick={() => {
                    setPendingRegistration(null);
                    setNotice(null);
                  }} disabled={authBusy}>
                    <ArrowLeft size={16} />
                    Start over
                  </button>
                </div>
              </form>
            ) : (
              <form key="credentials-form" className="auth-form" onSubmit={handleAuthentication}>
                <label>
                  Username
                  <input name="username" required minLength={3} autoComplete="username" />
                </label>

                {authMode === "register" && (
                  <label>
                    Email
                    <input name="email" type="email" required autoComplete="email" />
                  </label>
                )}

                <label>
                  Password
                  <input
                    name="password"
                    type="password"
                    required
                    minLength={8}
                    autoComplete={authMode === "login" ? "current-password" : "new-password"}
                  />
                </label>

                <button className="primary-button" type="submit" disabled={authBusy}>
                  {authBusy ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
                  {authMode === "login" ? "Unlock vault" : "Send verification code"}
                </button>
              </form>
            )}

            {notice && <NoticeBanner notice={notice} />}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup dark-text">
          <div className="brand-mark"><LockKeyhole size={21} /></div>
          <span>Prototype</span>
        </div>

        <div className="account-area">
          <div className="account-copy">
            <strong>{session.user.username}</strong>
            <span>{session.user.email}</span>
          </div>
          <button className="icon-button" type="button" onClick={handleLogout} title="Lock vault" aria-label="Lock vault">
            <LogOut size={19} />
          </button>
        </div>
      </header>

      <section className="status-strip">
        <div>
          <span>Files</span>
          <strong>{files.length}</strong>
        </div>
        <div>
          <span>Plaintext size</span>
          <strong>{formatBytes(totalPlaintextBytes)}</strong>
        </div>
        <div className="security-state">
          <ShieldCheck size={20} />
          <span>Vault unlocked</span>
        </div>
      </section>

      <section className="workspace">
        <div className="workspace-header">
          <div>
            <h1>Files</h1>
            <p>{loadingFiles ? "Refreshing" : `${files.length} encrypted item${files.length === 1 ? "" : "s"}`}</p>
          </div>
          <button
            className="primary-button compact"
            type="button"
            disabled={fileBusy}
            onClick={() => fileInputRef.current?.click()}
          >
            <UploadCloud size={18} />
            Upload
          </button>
          <input
            ref={fileInputRef}
            className="visually-hidden"
            type="file"
            onChange={handleFileSelection}
          />
        </div>

        {notice && <NoticeBanner notice={notice} />}

        {fileBusy && (
          <div className="progress-row" aria-live="polite">
            <LoaderCircle className="spin" size={18} />
            <div className="progress-track"><span style={{ width: `${progress}%` }} /></div>
            <strong>{progress}%</strong>
          </div>
        )}

        <div
          className="drop-zone"
          onDragOver={(event) => event.preventDefault()}
          onDrop={handleDrop}
        >
          <UploadCloud size={26} />
          <div>
            <strong>Drop a file</strong>
            <span>Maximum 100 MB</span>
          </div>
          <button type="button" className="secondary-button" onClick={() => fileInputRef.current?.click()} disabled={fileBusy}>
            Choose file
          </button>
        </div>

        <div className="file-table-wrap">
          <table className="file-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Added</th>
                <th><span className="visually-hidden">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.id}>
                  <td>
                    <div className="file-name-cell">
                      <FileLock2 size={20} />
                      <div>
                        <strong>{file.manifest?.name ?? "Unreadable encrypted file"}</strong>
                        <span>{file.manifest?.type ?? "Authentication failed"}</span>
                      </div>
                    </div>
                  </td>
                  <td>{formatBytes(file.encryption_metadata?.plaintext_size ?? 0)}</td>
                  <td>{formatDate(file.created_at)}</td>
                  <td>
                    <div className="row-actions">
                      <button type="button" className="icon-button" title="Download and decrypt" aria-label={`Download ${file.manifest?.name ?? "file"}`} onClick={() => void handleDownload(file)} disabled={fileBusy || !file.manifest}>
                        <Download size={18} />
                      </button>
                      <button type="button" className="icon-button danger" title="Delete" aria-label={`Delete ${file.manifest?.name ?? "file"}`} onClick={() => void handleDelete(file)} disabled={fileBusy}>
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!loadingFiles && files.length === 0 && (
            <div className="empty-state">
              <FolderOpen size={32} />
              <strong>No files</strong>
              <span>Your vault is empty.</span>
            </div>
          )}

          {loadingFiles && (
            <div className="empty-state">
              <LoaderCircle className="spin" size={28} />
              <strong>Loading vault</strong>
            </div>
          )}
        </div>
      </section>

      <footer className="app-footer">
        <span><Cloud size={15} /> API connected</span>
        <span><ShieldCheck size={15} /> Protocol v1</span>
      </footer>
    </main>
  );
}


function NoticeBanner({ notice }: { notice: Notice }) {
  return (
    <div className={`notice ${notice.tone}`} role="status">
      {notice.tone === "success"
        ? <CheckCircle2 size={18} />
        : <AlertCircle size={18} />}
      <span>{notice.message}</span>
    </div>
  );
}
