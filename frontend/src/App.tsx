import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Cloud,
  ClipboardPaste,
  Copy,
  Download,
  Eye,
  EyeOff,
  File as FileIcon,
  FileArchive,
  FileCode,
  FileImage,
  FileLock2,
  FileText,
  Folder,
  FolderPlus,
  FolderOpen,
  Grid2x2,
  Grid3x3,
  LayoutGrid,
  List,
  KeyRound,
  Link2,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MailCheck,
  Music,
  RotateCw,
  Settings,
  Share2,
  ShieldCheck,
  Scissors,
  Trash2,
  UploadCloud,
  Video,
  X
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
  changePassword,
  completePasswordRecovery,
  copyFile,
  createFolder,
  createCryptoProfile,
  createFileShare,
  deleteFile,
  deleteFolder,
  downloadSharedFile,
  downloadEncryptedFile,
  getCryptoProfile,
  getCurrentUser,
  getShareAccessInfo,
  listFileShares,
  listFiles,
  listFolders,
  login,
  logout,
  logoutAll,
  refreshSession,
  replaceRecoveryKey,
  requestPasswordRecoveryOtp,
  requestRegistrationOtp,
  revokeFileShare,
  setAccessTokenListener,
  verifyPasswordRecoveryOtp,
  verifyRegistrationOtp,
  moveFile,
  uploadEncryptedFile,
  unlockFileShare
} from "./api";
import {
  decryptFileInWorker,
  decryptSharedFileInWorker,
  encryptFileInWorker
} from "./crypto-worker-client";
import type {
  DisplayFile,
  DisplayFolder,
  FileShare,
  PasswordRecoveryGrant,
  ShareAccessInfo,
  ShareUnlockResponse,
  User
} from "./types";
import type { ShareAccess } from "./crypto";


interface Session {
  token: string;
  user: User;
  vaultKey: Uint8Array;
}

interface RestoredAuth {
  token: string;
  user: User;
}

interface Notice {
  tone: "success" | "error";
  message: string;
}

interface FileClipboard {
  mode: "copy" | "move";
  file: DisplayFile;
}

interface PendingRegistration {
  verificationId: string;
  username: string;
  email: string;
  password: string;
  expiresInSeconds: number;
  resendAfterSeconds: number;
}

interface PendingPasswordRecovery {
  verificationId: string;
  identifier: string;
  expiresInSeconds: number;
  resendAfterSeconds: number;
}

type RecoveryStage = "request" | "otp" | "complete";
type AppRoute = "home" | "vault";
type VaultViewMode = "list" | "small" | "medium" | "large";

const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const HOME_PATH = "/";
const VAULT_PATH = "/vault";
const LEGACY_FILES_PATH = "/files";
const MANUAL_LOCK_STORAGE_KEY = "prototype:manual-vault-lock";
const LEGACY_MANUAL_LOCK_STORAGE_KEY = "prototype:manual-file-lock";
const VAULT_VIEW_MODE_STORAGE_KEY = "prototype:vault-view-mode";
const VAULT_THUMBNAILS_HIDDEN_STORAGE_KEY = "prototype:vault-thumbnails-hidden";


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


function getShareTokenFromLocation(): string | null {
  const match = window.location.pathname.match(/^\/share\/([^/]+)\/?$/);

  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}


function getAppRouteFromLocation(): AppRoute {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";

  return (
    path === VAULT_PATH || path === LEGACY_FILES_PATH
      ? "vault"
      : "home"
  );
}


function appRoutePath(route: AppRoute): string {
  return route === "vault" ? VAULT_PATH : HOME_PATH;
}


function isLegacyFilesRoute(): boolean {
  return (window.location.pathname.replace(/\/+$/, "") || "/") === (
    LEGACY_FILES_PATH
  );
}


function getStoredVaultViewMode(): VaultViewMode {
  if (typeof localStorage === "undefined") {
    return "list";
  }

  const stored = localStorage.getItem(VAULT_VIEW_MODE_STORAGE_KEY);

  return (
    stored === "small"
    || stored === "medium"
    || stored === "large"
    || stored === "list"
  ) ? stored : "list";
}


function getStoredVaultThumbnailsHidden(): boolean {
  if (typeof localStorage === "undefined") {
    return false;
  }

  return localStorage.getItem(VAULT_THUMBNAILS_HIDDEN_STORAGE_KEY) === "1";
}


function isImageFile(file: DisplayFile): boolean {
  const type = file.manifest?.type.toLowerCase() ?? "";
  const name = file.manifest?.name.toLowerCase() ?? "";

  return (
    type.startsWith("image/")
    || /\.(avif|bmp|gif|jpe?g|png|svg|webp)$/i.test(name)
  );
}


function getFileTypeLabel(file: DisplayFile): string {
  const type = file.manifest?.type.toLowerCase() ?? "";
  const name = file.manifest?.name.toLowerCase() ?? "";

  if (isImageFile(file)) return "Image";
  if (type.includes("pdf") || name.endsWith(".pdf")) return "PDF";
  if (type.startsWith("video/")) return "Video";
  if (type.startsWith("audio/")) return "Audio";
  if (
    type.includes("zip")
    || type.includes("compressed")
    || /\.(7z|gz|rar|tar|zip)$/i.test(name)
  ) {
    return "Archive";
  }
  if (
    type.startsWith("text/")
    || /\.(css|csv|html|js|json|md|py|sql|ts|tsx|txt|xml|yaml|yml)$/i.test(name)
  ) {
    return "Text";
  }

  return file.manifest?.type ?? "Encrypted file";
}


function renderFileTypeIcon(file: DisplayFile, size: number) {
  const type = file.manifest?.type.toLowerCase() ?? "";
  const name = file.manifest?.name.toLowerCase() ?? "";

  if (isImageFile(file)) return <FileImage size={size} />;
  if (type.includes("pdf") || name.endsWith(".pdf")) {
    return <FileText size={size} />;
  }
  if (type.startsWith("video/")) return <Video size={size} />;
  if (type.startsWith("audio/")) return <Music size={size} />;
  if (
    type.includes("zip")
    || type.includes("compressed")
    || /\.(7z|gz|rar|tar|zip)$/i.test(name)
  ) {
    return <FileArchive size={size} />;
  }
  if (
    type.startsWith("text/")
    || /\.(css|html|js|json|md|py|sql|ts|tsx|xml|yaml|yml)$/i.test(name)
  ) {
    return <FileCode size={size} />;
  }

  return <FileIcon size={size} />;
}


export default function App() {
  const shareToken = getShareTokenFromLocation();
  return shareToken ? <SharedFilePage token={shareToken} /> : <VaultApp />;
}


function ProductHome({
  checkingStoredSession,
  onRegister,
  onSignIn,
  restoredAuth,
  session,
  onOpenVault
}: {
  checkingStoredSession: boolean;
  onRegister: () => void;
  onSignIn: () => void;
  restoredAuth: RestoredAuth | null;
  session: Session | null;
  onOpenVault: () => void;
}) {
  const activeUser = session?.user ?? restoredAuth?.user ?? null;

  return (
    <main className="home-shell">
      <header className="home-topbar">
        <div className="brand-lockup dark-text">
          <div className="brand-mark"><LockKeyhole size={21} /></div>
          <span>Prototype</span>
        </div>

        <div className="home-account">
          {activeUser ? (
            <div className="account-copy">
              <strong>{activeUser.username}</strong>
              <span>{activeUser.email}</span>
            </div>
          ) : checkingStoredSession ? (
            <span>Checking session</span>
          ) : (
            <div className="home-actions">
              <button className="secondary-button" type="button" onClick={onSignIn}>
                Sign in
              </button>
              <button className="primary-button compact" type="button" onClick={onRegister}>
                Register
              </button>
            </div>
          )}
        </div>
      </header>

      <section className="product-workspace">
        <div className="product-heading">
          <span className="section-label">Products</span>
          <h1>Prototype</h1>
        </div>

        <div className="product-grid" aria-label="Available products">
          <button className="product-card" type="button" onClick={onOpenVault}>
            <div className="product-icon">
              <FileLock2 size={28} />
            </div>
            <div>
              <h2>Vault</h2>
              <p>End-to-end encrypted storage</p>
            </div>
            <span className="product-status">
              {session
                ? "Unlocked"
                : restoredAuth
                  ? "Locked"
                  : "Open"}
            </span>
          </button>
        </div>
      </section>
    </main>
  );
}


function VaultApp() {
  const [route, setRoute] = useState<AppRoute>(getAppRouteFromLocation);
  const [authReturnRoute, setAuthReturnRoute] = useState<AppRoute>(
    getAppRouteFromLocation() === "vault" ? "vault" : "home"
  );
  const [authMode, setAuthMode] = useState<"login" | "register">(
    () => {
      const stored = sessionStorage.getItem("zkcs:authMode");
      return stored === "register" ? "register" : "login";
    }
  );

  const navigateTo = useCallback((nextRoute: AppRoute, replace = false) => {
    const nextPath = appRoutePath(nextRoute);

    setRoute(nextRoute);

    if (window.location.pathname === nextPath) {
      return;
    }

    if (replace) {
      window.history.replaceState(null, "", nextPath);
      return;
    }

    window.history.pushState(null, "", nextPath);
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      setRoute(getAppRouteFromLocation());
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    if (isLegacyFilesRoute()) {
      navigateTo("vault", true);
    }
  }, [navigateTo]);

  // Keep sessionStorage in sync whenever authMode changes
  useEffect(() => {
    sessionStorage.setItem("zkcs:authMode", authMode);
  }, [authMode]);

  useEffect(() => {
    sessionStorage.removeItem("zkcs:vaultKey");
    sessionStorage.removeItem(LEGACY_MANUAL_LOCK_STORAGE_KEY);
  }, []);

  const [session, setSession] = useState<Session | null>(null);
  const [restoredAuth, setRestoredAuth] = useState<RestoredAuth | null>(null);
  const [checkingStoredSession, setCheckingStoredSession] = useState(true);
  const [deviceUnlockAvailable, setDeviceUnlockAvailable] = useState(false);
  const [folders, setFolders] = useState<DisplayFolder[]>([]);
  const [files, setFiles] = useState<DisplayFile[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [currentFolderId, setCurrentFolderId] = useState<number | null>(null);
  const [folderTrail, setFolderTrail] = useState<DisplayFolder[]>([]);
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [fileClipboard, setFileClipboard] = useState<FileClipboard | null>(
    null
  );
  const [vaultViewMode, setVaultViewMode] = useState<VaultViewMode>(
    getStoredVaultViewMode
  );
  const [thumbnailsHidden, setThumbnailsHidden] = useState(
    getStoredVaultThumbnailsHidden
  );
  const [previewFile, setPreviewFile] = useState<DisplayFile | null>(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [fileBusy, setFileBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [pendingRegistration, setPendingRegistration] = (
    useState<PendingRegistration | null>(null)
  );
  const [recoveryStage, setRecoveryStage] = (
    useState<RecoveryStage | null>(null)
  );
  const [pendingPasswordRecovery, setPendingPasswordRecovery] = (
    useState<PendingPasswordRecovery | null>(null)
  );
  const [passwordRecoveryGrant, setPasswordRecoveryGrant] = (
    useState<PasswordRecoveryGrant | null>(null)
  );
  const [recoveryKeyToSave, setRecoveryKeyToSave] = useState<string | null>(
    null
  );
  const [securityOpen, setSecurityOpen] = useState(false);
  const [shareFile, setShareFile] = useState<DisplayFile | null>(null);
  const [fileShares, setFileShares] = useState<FileShare[]>([]);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareLink, setShareLink] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sessionRef = useRef<Session | null>(null);

  const loadVaultItems = useCallback(async (
    activeSession: Session,
    folderId: number | null
  ) => {
    setLoadingFiles(true);

    try {
      const { decryptFolderName, decryptManifest } = await import("./crypto");
      const [folderRecords, records] = await Promise.all([
        listFolders(activeSession.token, folderId),
        listFiles(activeSession.token, folderId)
      ]);
      const displayFolders = await Promise.all(
        folderRecords.map(async (record): Promise<DisplayFolder> => {
          try {
            const name = await decryptFolderName(
              record.encrypted_name,
              record.encryption_metadata,
              activeSession.vaultKey
            );
            return { ...record, name };
          } catch {
            return { ...record, name: null };
          }
        })
      );
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

      setFolders(displayFolders);
      setFiles(displayRecords);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setLoadingFiles(false);
    }
  }, []);

  useEffect(() => {
    if (session) {
      void loadVaultItems(session, currentFolderId);
    }
  }, [currentFolderId, loadVaultItems, session]);

  useEffect(() => {
    localStorage.setItem(VAULT_VIEW_MODE_STORAGE_KEY, vaultViewMode);
  }, [vaultViewMode]);

  useEffect(() => {
    localStorage.setItem(
      VAULT_THUMBNAILS_HIDDEN_STORAGE_KEY,
      thumbnailsHidden ? "1" : "0"
    );
  }, [thumbnailsHidden]);

  useEffect(() => {
    if (!pendingRegistration || pendingRegistration.resendAfterSeconds <= 0) {
      return;
    }

    const timer = window.setTimeout(() => {
      setPendingRegistration((current) => current ? {
        ...current,
        expiresInSeconds: Math.max(0, current.expiresInSeconds - 1),
        resendAfterSeconds: Math.max(0, current.resendAfterSeconds - 1)
      } : null);
    }, 1000);

    return () => window.clearTimeout(timer);
  }, [pendingRegistration]);

  useEffect(() => {
    if (
      !pendingPasswordRecovery
      || pendingPasswordRecovery.resendAfterSeconds <= 0
    ) {
      return;
    }

    const timer = window.setTimeout(() => {
      setPendingPasswordRecovery((current) => current ? {
        ...current,
        resendAfterSeconds: Math.max(0, current.resendAfterSeconds - 1)
      } : null);
    }, 1000);

    return () => window.clearTimeout(timer);
  }, [pendingPasswordRecovery]);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    setAccessTokenListener((token) => {
      setSession((current) => current ? { ...current, token } : null);
      setRestoredAuth((current) => current ? { ...current, token } : null);
    });

    return () => {
      setAccessTokenListener(null);

      if (sessionRef.current) {
        void import("./crypto").then(({ zeroKey }) => (
          zeroKey(sessionRef.current!.vaultKey)
        ));
      }
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function restoreStoredSession() {
      try {
        const tokenResponse = await refreshSession();
        const user = await getCurrentUser(tokenResponse.access_token);
        const {
          hasLocalDeviceVault,
          unlockVaultWithLocalDevice
        } = await import("./crypto");

        if (cancelled) return;

        const shouldAutoUnlockVault = (
          getAppRouteFromLocation() === "vault"
          && sessionStorage.getItem(MANUAL_LOCK_STORAGE_KEY) !== "1"
        );

        if (shouldAutoUnlockVault && hasLocalDeviceVault(user.id)) {
          try {
            const vaultKey = await unlockVaultWithLocalDevice(user.id);

            if (cancelled) {
              const { zeroKey } = await import("./crypto");
              await zeroKey(vaultKey);
              return;
            }

            sessionStorage.removeItem(MANUAL_LOCK_STORAGE_KEY);
            setSession({
              token: tokenResponse.access_token,
              user,
              vaultKey
            });
            setRestoredAuth(null);
            setDeviceUnlockAvailable(true);
            return;
          } catch {
            setDeviceUnlockAvailable(false);
          }
        }

        setRestoredAuth({
          token: tokenResponse.access_token,
          user
        });
        setDeviceUnlockAvailable(hasLocalDeviceVault(user.id));
      } catch {
        // No valid refresh cookie means the normal sign-in form is shown.
        if (!cancelled) {
          setDeviceUnlockAvailable(false);
        }
      } finally {
        if (!cancelled) {
          setCheckingStoredSession(false);
        }
      }
    }

    void restoreStoredSession();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function unlockTrustedVaultRoute() {
      if (
        route !== "vault"
        || session
        || !restoredAuth
        || sessionStorage.getItem(MANUAL_LOCK_STORAGE_KEY) === "1"
      ) {
        return;
      }

      const {
        hasLocalDeviceVault,
        unlockVaultWithLocalDevice,
        zeroKey
      } = await import("./crypto");

      if (!hasLocalDeviceVault(restoredAuth.user.id)) {
        return;
      }

      try {
        const vaultKey = await unlockVaultWithLocalDevice(
          restoredAuth.user.id
        );

        if (cancelled) {
          await zeroKey(vaultKey);
          return;
        }

        sessionStorage.removeItem(MANUAL_LOCK_STORAGE_KEY);
        setSession({
          token: restoredAuth.token,
          user: restoredAuth.user,
          vaultKey
        });
        setRestoredAuth(null);
        setDeviceUnlockAvailable(true);
        setNotice(null);
      } catch {
        setDeviceUnlockAvailable(false);
      }
    }

    void unlockTrustedVaultRoute();

    return () => {
      cancelled = true;
    };
  }, [restoredAuth, route, session]);

  const totalPlaintextBytes = useMemo(
    () => files.reduce(
      (total, file) => total + (
        file.encryption_metadata?.plaintext_size ?? 0
      ),
      0
    ),
    [files]
  );
  const totalVisibleItems = folders.length + files.length;
  const currentFolderName = folderTrail.at(-1)?.name ?? "Vault";

  async function unlockVaultSession(
    token: string,
    user: User,
    password: string,
    nextRoute: AppRoute = "vault"
  ) {
    let vaultKey: Uint8Array;
    let recoveryKey: string | null = null;
    const {
      createVaultProfile,
      hasLocalDeviceVault,
      saveLocalDeviceVault,
      unlockVault
    } = await import("./crypto");

    try {
      const profile = await getCryptoProfile(token);
      vaultKey = await unlockVault(password, user.id, profile);

      if (
        profile.recovery_version === null
        || profile.recovery_wrap_algorithm === null
        || profile.recovery_wrapped_vault_key === null
        || profile.recovery_wrap_nonce === null
      ) {
        const { createRecoveryProfile, zeroKey } = await import("./crypto");
        const recovery = await createRecoveryProfile(vaultKey, user.id);

        try {
          await replaceRecoveryKey(token, recovery.recoveryProfile);
          recoveryKey = recovery.recoveryKey;
        } catch (recoveryError) {
          await zeroKey(vaultKey);
          throw recoveryError;
        }
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        const setup = await createVaultProfile(password, user.id);

        try {
          await createCryptoProfile(token, setup.profile);
          vaultKey = setup.vaultKey;
          recoveryKey = setup.recoveryKey;
        } catch (profileError) {
          const { zeroKey } = await import("./crypto");
          await zeroKey(setup.vaultKey);
          throw profileError;
        }
      } else {
        throw error;
      }
    }

    try {
      await saveLocalDeviceVault(user.id, vaultKey);
    } catch {
      // File refresh still works after password unlock; auto-unlock is optional.
    }

    sessionStorage.removeItem(MANUAL_LOCK_STORAGE_KEY);
    setSession({ token, user, vaultKey });
    setRestoredAuth(null);
    setDeviceUnlockAvailable(hasLocalDeviceVault(user.id));
    setRecoveryKeyToSave(recoveryKey);
    setNotice({ tone: "success", message: "Vault unlocked" });
    navigateTo(nextRoute);
  }

  async function establishSession(
    username: string,
    password: string,
    registeredUser?: User,
    nextRoute: AppRoute = "vault"
  ) {
    const tokenResponse = await login(username, password);
    const token = tokenResponse.access_token;
    const user = registeredUser ?? await getCurrentUser(token);

    await unlockVaultSession(token, user, password, nextRoute);
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

      await establishSession(username, password, undefined, authReturnRoute);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleRestoredUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!restoredAuth) return;

    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");

    try {
      await unlockVaultSession(
        restoredAuth.token,
        restoredAuth.user,
        password,
        authReturnRoute
      );
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleUseAnotherAccount() {
    if (!restoredAuth) return;

    setAuthBusy(true);
    setNotice(null);

    try {
      await logout(restoredAuth.token);
    } catch {
      // The local sign-in form can still reset even if the server session ended.
    } finally {
      setRestoredAuth(null);
      setDeviceUnlockAvailable(false);
      setAuthMode("login");
      navigateTo("vault");
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
        user,
        authReturnRoute
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

  async function handlePasswordRecoveryRequest(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();
    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const identifier = String(form.get("identifier") ?? "").trim();

    try {
      const challenge = await requestPasswordRecoveryOtp(identifier);
      setPendingPasswordRecovery({
        verificationId: challenge.verification_id,
        identifier,
        expiresInSeconds: challenge.expires_in_seconds,
        resendAfterSeconds: challenge.resend_after_seconds
      });
      setRecoveryStage("otp");
      setNotice({ tone: "success", message: challenge.message });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handlePasswordRecoveryOtp(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    if (!pendingPasswordRecovery) return;

    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const otp = String(form.get("otp") ?? "").trim();

    try {
      const grant = await verifyPasswordRecoveryOtp(
        pendingPasswordRecovery.verificationId,
        otp
      );
      setPasswordRecoveryGrant(grant);
      setRecoveryStage("complete");
      setNotice(null);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handlePasswordRecoveryComplete(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    if (!passwordRecoveryGrant) return;

    const form = new FormData(event.currentTarget);
    const recoveryKey = String(form.get("recovery_key") ?? "").trim();
    const newPassword = String(form.get("new_password") ?? "");
    const confirmPassword = String(form.get("confirm_password") ?? "");

    if (newPassword !== confirmPassword) {
      setNotice({ tone: "error", message: "New passwords do not match" });
      return;
    }

    setAuthBusy(true);
    setNotice(null);
    let recoveredVaultKey: Uint8Array | null = null;

    try {
      const {
        hasLocalDeviceVault,
        rewrapVaultKey,
        saveLocalDeviceVault,
        unlockVaultWithRecoveryKey
      } = await import("./crypto");
      recoveredVaultKey = await unlockVaultWithRecoveryKey(
        recoveryKey,
        passwordRecoveryGrant.user_id,
        passwordRecoveryGrant.recovery_profile
      );
      const profile = await rewrapVaultKey(
        newPassword,
        passwordRecoveryGrant.user_id,
        recoveredVaultKey
      );
      const tokenResponse = await completePasswordRecovery(
        passwordRecoveryGrant.recovery_token,
        newPassword,
        profile
      );
      const user = await getCurrentUser(tokenResponse.access_token);
      try {
        await saveLocalDeviceVault(user.id, recoveredVaultKey);
      } catch {
        // Auto-unlock is optional; recovery should still complete.
      }
      sessionStorage.removeItem(MANUAL_LOCK_STORAGE_KEY);
      setSession({
        token: tokenResponse.access_token,
        user,
        vaultKey: recoveredVaultKey
      });
      setRestoredAuth(null);
      setDeviceUnlockAvailable(hasLocalDeviceVault(user.id));
      recoveredVaultKey = null;
      setRecoveryStage(null);
      setPendingPasswordRecovery(null);
      setPasswordRecoveryGrant(null);
      setNotice({ tone: "success", message: "Password recovered" });
      navigateTo(authReturnRoute);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      if (recoveredVaultKey) {
        const { zeroKey } = await import("./crypto");
        await zeroKey(recoveredVaultKey);
      }

      setAuthBusy(false);
    }
  }

  async function handleRecoveryOtpResend() {
    if (!pendingPasswordRecovery) return;

    setAuthBusy(true);
    setNotice(null);

    try {
      const challenge = await requestPasswordRecoveryOtp(
        pendingPasswordRecovery.identifier
      );
      setPendingPasswordRecovery({
        ...pendingPasswordRecovery,
        verificationId: challenge.verification_id,
        expiresInSeconds: challenge.expires_in_seconds,
        resendAfterSeconds: challenge.resend_after_seconds
      });
      setNotice({ tone: "success", message: challenge.message });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handlePasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session) return;

    const form = new FormData(event.currentTarget);
    const currentPassword = String(form.get("current_password") ?? "");
    const newPassword = String(form.get("new_password") ?? "");
    const confirmPassword = String(form.get("confirm_password") ?? "");

    if (newPassword !== confirmPassword) {
      setNotice({ tone: "error", message: "New passwords do not match" });
      return;
    }

    setAuthBusy(true);
    setNotice(null);

    try {
      const { rewrapVaultKey } = await import("./crypto");
      const profile = await rewrapVaultKey(
        newPassword,
        session.user.id,
        session.vaultKey
      );
      const tokenResponse = await changePassword(
        session.token,
        currentPassword,
        newPassword,
        profile
      );
      setSession({ ...session, token: tokenResponse.access_token });
      setSecurityOpen(false);
      setNotice({ tone: "success", message: "Password changed" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleTrustedDeviceRemoval() {
    if (!session) return;

    if (!window.confirm("Forget this device for automatic file unlock?")) {
      return;
    }

    setAuthBusy(true);
    setNotice(null);

    try {
      const { removeLocalDeviceVault } = await import("./crypto");
      removeLocalDeviceVault(session.user.id);
      setDeviceUnlockAvailable(false);
      setNotice({ tone: "success", message: "Device forgotten" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleRecoveryKeyRotation() {
    if (!session) return;

    setAuthBusy(true);
    setNotice(null);

    try {
      const { createRecoveryProfile } = await import("./crypto");
      const recovery = await createRecoveryProfile(
        session.vaultKey,
        session.user.id
      );
      await replaceRecoveryKey(
        session.token,
        recovery.recoveryProfile
      );
      setSecurityOpen(false);
      setRecoveryKeyToSave(recovery.recoveryKey);
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
        encrypted.metadata,
        currentFolderId
      );
      await loadVaultItems(session, currentFolderId);
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

  function openFolder(folder: DisplayFolder) {
    setFolderTrail((current) => [...current, folder]);
    setCurrentFolderId(folder.id);
    setNotice(null);
  }

  function openRootFolder() {
    setFolderTrail([]);
    setCurrentFolderId(null);
    setNotice(null);
  }

  function openTrailFolder(index: number) {
    const nextTrail = folderTrail.slice(0, index + 1);
    const folder = nextTrail.at(-1) ?? null;

    setFolderTrail(nextTrail);
    setCurrentFolderId(folder?.id ?? null);
    setNotice(null);
  }

  async function handleCreateFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session || fileBusy) return;

    const form = new FormData(event.currentTarget);
    const name = String(form.get("folder_name") ?? "").trim();

    if (!name) {
      setNotice({ tone: "error", message: "Folder name is required" });
      return;
    }

    setFileBusy(true);
    setNotice(null);

    try {
      const { encryptFolderName } = await import("./crypto");
      const encrypted = await encryptFolderName(name, session.vaultKey);

      await createFolder(
        session.token,
        encrypted.encryptedName,
        encrypted.metadata,
        currentFolderId
      );
      await loadVaultItems(session, currentFolderId);
      setCreateFolderOpen(false);
      setNotice({ tone: "success", message: `${name} created` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
    }
  }

  async function handleDeleteFolder(folder: DisplayFolder) {
    if (!session || fileBusy) return;

    const name = folder.name ?? "this encrypted folder";

    if (!window.confirm(`Delete ${name} and everything inside it?`)) {
      return;
    }

    setFileBusy(true);
    setNotice(null);

    try {
      await deleteFolder(session.token, folder.id);
      await loadVaultItems(session, currentFolderId);
      setNotice({ tone: "success", message: `${name} deleted` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
    }
  }

  function handleCopyFile(file: DisplayFile) {
    setFileClipboard({ mode: "copy", file });
    setNotice({
      tone: "success",
      message: `${file.manifest?.name ?? "Encrypted file"} copied`
    });
  }

  function handleMoveFile(file: DisplayFile) {
    setFileClipboard({ mode: "move", file });
    setNotice({
      tone: "success",
      message: `${file.manifest?.name ?? "Encrypted file"} ready to move`
    });
  }

  async function handlePasteFile() {
    if (!session || !fileClipboard || fileBusy) return;

    setFileBusy(true);
    setNotice(null);

    try {
      if (fileClipboard.mode === "copy") {
        await copyFile(session.token, fileClipboard.file.id, currentFolderId);
        setNotice({ tone: "success", message: "File copied" });
      } else {
        await moveFile(session.token, fileClipboard.file.id, currentFolderId);
        setFileClipboard(null);
        setNotice({ tone: "success", message: "File moved" });
      }

      await loadVaultItems(session, currentFolderId);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
    }
  }

  function openImagePreview(file: DisplayFile) {
    if (!session || !file.encryption_metadata || !isImageFile(file)) return;

    setPreviewFile(file);
    setNotice(null);
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
      await loadVaultItems(session, currentFolderId);
      setNotice({ tone: "success", message: `${name} deleted` });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setFileBusy(false);
    }
  }

  async function openShareDialog(file: DisplayFile) {
    if (!session || !file.encryption_metadata) return;

    setShareFile(file);
    setShareLink(null);
    setFileShares([]);
    setShareBusy(true);
    setNotice(null);

    try {
      setFileShares(await listFileShares(session.token, file.id));
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setShareBusy(false);
    }
  }

  async function handleCreateShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session || !shareFile?.encryption_metadata) return;

    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const password = String(form.get("share_password") ?? "");
    const confirmation = String(form.get("confirm_share_password") ?? "");
    const expiryDays = String(form.get("expiry_days") ?? "7");

    if (password !== confirmation) {
      setNotice({ tone: "error", message: "Share passwords do not match" });
      return;
    }

    setShareBusy(true);
    setShareLink(null);
    setNotice(null);

    try {
      const { createPasswordProtectedShare } = await import("./crypto");
      const setup = await createPasswordProtectedShare(
        password,
        shareFile.encryption_metadata,
        session.vaultKey
      );
      const expiresAt = expiryDays === "never"
        ? null
        : new Date(
          Date.now() + Number(expiryDays) * 24 * 60 * 60 * 1000
        ).toISOString();

      await createFileShare(
        session.token,
        shareFile.id,
        setup.payload,
        expiresAt
      );
      setShareLink(`${window.location.origin}/share/${setup.token}`);
      setFileShares(await listFileShares(session.token, shareFile.id));
      formElement.reset();
      setNotice({ tone: "success", message: "Encrypted share created" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setShareBusy(false);
    }
  }

  async function handleRevokeShare(share: FileShare) {
    if (!session || !shareFile || share.revoked_at) return;

    if (!window.confirm("Revoke this share link?")) return;

    setShareBusy(true);
    setNotice(null);

    try {
      await revokeFileShare(session.token, shareFile.id, share.id);
      setFileShares(await listFileShares(session.token, shareFile.id));
      setShareLink(null);
      setNotice({ tone: "success", message: "Share revoked" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setShareBusy(false);
    }
  }

  async function copyShareLink() {
    if (!shareLink) return;
    await navigator.clipboard.writeText(shareLink);
    setNotice({ tone: "success", message: "Share link copied" });
  }

  async function clearLocalSession(activeSession: Session) {
    const { zeroKey } = await import("./crypto");
    await zeroKey(activeSession.vaultKey);
    setSession(null);
    setRestoredAuth(null);
    setDeviceUnlockAvailable(false);
    setFolders([]);
    setFiles([]);
    setCurrentFolderId(null);
    setFolderTrail([]);
    setFileClipboard(null);
    setSecurityOpen(false);
    setShareFile(null);
    setPreviewFile(null);
  }

  async function handleLockVault() {
    if (!session) return;

    const activeSession = session;
    const restoredSession = {
      token: activeSession.token,
      user: activeSession.user
    };
    const { hasLocalDeviceVault } = await import("./crypto");
    const hasDeviceUnlock = hasLocalDeviceVault(activeSession.user.id);

    sessionStorage.setItem(MANUAL_LOCK_STORAGE_KEY, "1");
    await clearLocalSession(activeSession);
    setRestoredAuth(restoredSession);
    setDeviceUnlockAvailable(hasDeviceUnlock);
    navigateTo("vault");
    setNotice(null);
  }

  async function handleLogout(allDevices = false) {
    if (!session) return;

    const activeSession = session;

    try {
      if (allDevices) {
        await logoutAll(activeSession.token);
        const { removeLocalDeviceVault } = await import("./crypto");
        removeLocalDeviceVault(activeSession.user.id);
      } else {
        await logout(activeSession.token);
      }
    } catch {
      // The local vault still locks if the network session is already invalid.
    } finally {
      await clearLocalSession(activeSession);
      sessionStorage.removeItem(MANUAL_LOCK_STORAGE_KEY);
      navigateTo("home");
      setNotice(null);
    }
  }

  async function copyRecoveryKey() {
    if (!recoveryKeyToSave) return;

    await navigator.clipboard.writeText(recoveryKeyToSave);
    setNotice({ tone: "success", message: "Recovery key copied" });
  }

  function downloadRecoveryKey() {
    if (!recoveryKeyToSave) return;

    const content = [
      "Prototype recovery key",
      "Keep this file private. It can unlock your encrypted vault.",
      "",
      recoveryKeyToSave,
      ""
    ].join("\n");
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "prototype-recovery-key.txt";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function renderRestoredUnlockForm(formClassName = "auth-form") {
    if (!restoredAuth) return null;

    return (
      <form key="restored-unlock-form" className={formClassName} onSubmit={handleRestoredUnlock}>
        <div className="restored-account">
          <strong>{restoredAuth.user.username}</strong>
          <span>{restoredAuth.user.email}</span>
        </div>

        <label>
          Password
          <input
            name="password"
            type="password"
            required
            minLength={8}
            autoComplete="current-password"
            autoFocus
          />
        </label>

        <button className="primary-button" type="submit" disabled={authBusy}>
          {authBusy ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
          Unlock vault
        </button>

        <button className="text-button" type="button" onClick={() => void handleUseAnotherAccount()} disabled={authBusy}>
          Use another account
        </button>
      </form>
    );
  }

  function openVaultAuthentication(
    mode: "login" | "register",
    returnRoute: AppRoute = "home"
  ) {
    setAuthReturnRoute(returnRoute);
    setAuthMode(mode);
    setPendingRegistration(null);
    setRecoveryStage(null);
    setPendingPasswordRecovery(null);
    setPasswordRecoveryGrant(null);
    setNotice(null);
    navigateTo("vault");
  }

  const showRestoredUnlock = Boolean(
    restoredAuth && !pendingRegistration && !recoveryStage
  );
  const authTitle = checkingStoredSession
    ? "Checking session"
    : showRestoredUnlock
      ? "Unlock vault"
      : recoveryStage === "request"
        ? "Recover account"
        : recoveryStage === "otp"
          ? "Verify recovery email"
          : recoveryStage === "complete"
            ? "Unlock with recovery key"
            : pendingRegistration
              ? "Verify email"
              : authMode === "login"
                ? "Sign in"
                : "Create vault";
  const authDescription = checkingStoredSession
    ? "Looking for an active session"
    : restoredAuth && showRestoredUnlock
      ? `Signed in as ${restoredAuth.user.username}. Enter your password to decrypt Vault.`
      : recoveryStage === "request"
        ? "Request a recovery code"
        : recoveryStage === "otp" && pendingPasswordRecovery
          ? `Code sent for ${pendingPasswordRecovery.identifier}`
          : recoveryStage === "complete"
            ? "Enter the recovery key saved when the vault was created"
            : pendingRegistration
              ? `Code sent to ${pendingRegistration.email}. Expires in ${Math.ceil(pendingRegistration.expiresInSeconds / 60)} minutes.`
              : authMode === "login"
                ? "Enter your vault credentials"
                : "Set your vault credentials";
  if (route === "home") {
    return (
      <ProductHome
        checkingStoredSession={checkingStoredSession}
        onRegister={() => openVaultAuthentication("register", "home")}
        onSignIn={() => openVaultAuthentication("login", "home")}
        restoredAuth={restoredAuth}
        session={session}
        onOpenVault={() => {
          setAuthReturnRoute("vault");
          navigateTo("vault");
        }}
      />
    );
  }

  const shouldRenderLockedVaultRoute = (
    route === "vault"
    && !pendingRegistration
    && !recoveryStage
    && (checkingStoredSession || Boolean(restoredAuth))
  );

  if (!session && shouldRenderLockedVaultRoute) {
    return (
      <main className="app-shell">
        <header className="topbar">
          <button className="brand-lockup brand-home-button dark-text" type="button" onClick={() => navigateTo("home")}>
            <div className="brand-mark"><LockKeyhole size={21} /></div>
            <span>Prototype</span>
          </button>

          {restoredAuth && (
            <div className="account-area">
              <div className="account-copy">
                <strong>{restoredAuth.user.username}</strong>
                <span>{restoredAuth.user.email}</span>
              </div>
            </div>
          )}
        </header>

        <section className="status-strip">
          <div>
            <span>Vault</span>
            <strong>Locked</strong>
          </div>
          <div>
            <span>Plaintext size</span>
            <strong>Hidden</strong>
          </div>
          <div className="security-state">
            {checkingStoredSession ? (
              <LoaderCircle className="spin" size={20} />
            ) : (
              <LockKeyhole size={20} />
            )}
            <span>{checkingStoredSession ? "Restoring session" : "Vault locked"}</span>
          </div>
        </section>

        <section className="workspace locked-workspace">
          <div className="workspace-header">
            <div>
              <h1>Vault</h1>
              <p>
                {checkingStoredSession
                  ? "Checking saved session"
                  : "Enter your vault password to continue"}
              </p>
            </div>
          </div>

          <div className="locked-vault-panel">
            {checkingStoredSession ? (
              <div className="auth-loading" aria-live="polite">
                <LoaderCircle className="spin" size={24} />
                <span>Restoring your encrypted workspace</span>
              </div>
            ) : restoredAuth ? (
              renderRestoredUnlockForm("auth-form locked-vault-form")
            ) : null}
          </div>

          {notice && <NoticeBanner notice={notice} />}
        </section>

        <footer className="app-footer">
          <span><Cloud size={15} /> API connected</span>
          <span><ShieldCheck size={15} /> Protocol v1</span>
        </footer>
      </main>
    );
  }

  if (!session) {
    return (
      <main className="auth-shell">
        <section className="auth-brand" aria-label="Prototype">
          <button className="brand-lockup brand-home-button light-text" type="button" onClick={() => navigateTo("home")}>
            <div className="brand-mark"><LockKeyhole size={24} /></div>
            <span>Prototype</span>
          </button>
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
              {pendingRegistration || recoveryStage ? (
                <MailCheck size={26} />
              ) : (
                <KeyRound size={26} />
              )}
              <div>
                <h2>{authTitle}</h2>
                <p>{authDescription}</p>
              </div>
            </div>

            {!checkingStoredSession
              && !restoredAuth
              && !pendingRegistration
              && !recoveryStage && (
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

            {checkingStoredSession ? (
              <div className="auth-form auth-loading" aria-live="polite">
                <LoaderCircle className="spin" size={22} />
                <span>Checking saved session</span>
              </div>
            ) : showRestoredUnlock && restoredAuth ? (
              renderRestoredUnlockForm()
            ) : recoveryStage === "request" ? (
              <form key="recovery-request-form" className="auth-form" onSubmit={handlePasswordRecoveryRequest}>
                <label>
                  Username or email
                  <input name="identifier" required minLength={3} autoComplete="username" autoFocus />
                </label>

                <button className="primary-button" type="submit" disabled={authBusy}>
                  {authBusy ? <LoaderCircle className="spin" size={18} /> : <MailCheck size={18} />}
                  Send recovery code
                </button>

                <button className="secondary-button" type="button" onClick={() => {
                  setRecoveryStage(null);
                  setNotice(null);
                }} disabled={authBusy}>
                  <ArrowLeft size={16} />
                  Back to sign in
                </button>
              </form>
            ) : recoveryStage === "otp" && pendingPasswordRecovery ? (
              <form key="recovery-otp-form" className="auth-form" onSubmit={handlePasswordRecoveryOtp}>
                <label>
                  Recovery code
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
                  {authBusy ? <LoaderCircle className="spin" size={18} /> : <ShieldCheck size={18} />}
                  Verify recovery code
                </button>

                <div className="auth-actions">
                  <button className="secondary-button" type="button" onClick={() => void handleRecoveryOtpResend()} disabled={authBusy || pendingPasswordRecovery.resendAfterSeconds > 0}>
                    <RotateCw size={16} />
                    {pendingPasswordRecovery.resendAfterSeconds > 0 ? `Resend in ${pendingPasswordRecovery.resendAfterSeconds}s` : "Resend code"}
                  </button>
                  <button className="secondary-button" type="button" onClick={() => {
                    setRecoveryStage("request");
                    setPendingPasswordRecovery(null);
                    setNotice(null);
                  }} disabled={authBusy}>
                    <ArrowLeft size={16} />
                    Start over
                  </button>
                </div>
              </form>
            ) : recoveryStage === "complete" && passwordRecoveryGrant ? (
              <form key="recovery-complete-form" className="auth-form" onSubmit={handlePasswordRecoveryComplete}>
                <label>
                  Recovery key
                  <textarea name="recovery_key" required rows={4} autoComplete="off" autoFocus />
                </label>
                <label>
                  New password
                  <input name="new_password" type="password" required minLength={8} autoComplete="new-password" />
                </label>
                <label>
                  Confirm new password
                  <input name="confirm_password" type="password" required minLength={8} autoComplete="new-password" />
                </label>

                <button className="primary-button" type="submit" disabled={authBusy}>
                  {authBusy ? <LoaderCircle className="spin" size={18} /> : <KeyRound size={18} />}
                  Recover encrypted vault
                </button>

                <button className="secondary-button" type="button" onClick={() => {
                  setRecoveryStage(null);
                  setPendingPasswordRecovery(null);
                  setPasswordRecoveryGrant(null);
                  setNotice(null);
                }} disabled={authBusy}>
                  <X size={16} />
                  Cancel recovery
                </button>
              </form>
            ) : pendingRegistration ? (
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

                {authMode === "login" && (
                  <button className="text-button" type="button" onClick={() => {
                    setRecoveryStage("request");
                    setNotice(null);
                  }} disabled={authBusy}>
                    Forgot password?
                  </button>
                )}
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
        <button className="brand-lockup brand-home-button dark-text" type="button" onClick={() => navigateTo("home")}>
          <div className="brand-mark"><LockKeyhole size={21} /></div>
          <span>Prototype</span>
        </button>

        <div className="account-area">
          <div className="account-copy">
            <strong>{session.user.username}</strong>
            <span>{session.user.email}</span>
          </div>
          <button className="icon-button" type="button" onClick={() => {
            setSecurityOpen(true);
            setNotice(null);
          }} title="Account security" aria-label="Account security">
            <Settings size={19} />
          </button>
          <button className="icon-button" type="button" onClick={() => void handleLockVault()} title="Lock Vault" aria-label="Lock Vault">
            <LogOut size={19} />
          </button>
        </div>
      </header>

      <section className="status-strip">
        <div>
          <span>Items</span>
          <strong>{totalVisibleItems}</strong>
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
            <h1>{currentFolderName}</h1>
            <p>{loadingFiles ? "Refreshing" : `${totalVisibleItems} encrypted item${totalVisibleItems === 1 ? "" : "s"}`}</p>
          </div>
          <div className="workspace-actions">
            <div className="view-controls" role="group" aria-label="Vault view">
              <button
                className={vaultViewMode === "list" ? "active" : ""}
                type="button"
                onClick={() => setVaultViewMode("list")}
                title="List view"
                aria-label="List view"
              >
                <List size={17} />
              </button>
              <button
                className={vaultViewMode === "small" ? "active" : ""}
                type="button"
                onClick={() => setVaultViewMode("small")}
                title="Small icons"
                aria-label="Small icon view"
              >
                <Grid2x2 size={15} />
              </button>
              <button
                className={vaultViewMode === "medium" ? "active" : ""}
                type="button"
                onClick={() => setVaultViewMode("medium")}
                title="Medium icons"
                aria-label="Medium icon view"
              >
                <LayoutGrid size={18} />
              </button>
              <button
                className={vaultViewMode === "large" ? "active" : ""}
                type="button"
                onClick={() => setVaultViewMode("large")}
                title="Big icons"
                aria-label="Big icon view"
              >
                <Grid3x3 size={21} />
              </button>
            </div>
            <button
              className={`secondary-button compact thumbnail-toggle${thumbnailsHidden ? " active" : ""}`}
              type="button"
              aria-pressed={thumbnailsHidden}
              title={thumbnailsHidden ? "Show image thumbnails" : "Hide image thumbnails"}
              onClick={() => setThumbnailsHidden((current) => !current)}
            >
              {thumbnailsHidden ? <Eye size={18} /> : <EyeOff size={18} />}
              {thumbnailsHidden ? "Show thumbnails" : "Hide thumbnails"}
            </button>
            {fileClipboard && (
              <button
                className="secondary-button compact"
                type="button"
                disabled={fileBusy}
                onClick={() => void handlePasteFile()}
                title={fileClipboard.mode === "copy" ? "Paste copy" : "Paste move"}
              >
                <ClipboardPaste size={18} />
                Paste
              </button>
            )}
            <button
              className="secondary-button compact"
              type="button"
              disabled={fileBusy}
              onClick={() => {
                setCreateFolderOpen(true);
                setNotice(null);
              }}
            >
              <FolderPlus size={18} />
              New folder
            </button>
            <button
              className="primary-button compact"
              type="button"
              disabled={fileBusy}
              onClick={() => fileInputRef.current?.click()}
            >
              <UploadCloud size={18} />
              Upload
            </button>
          </div>
          <input
            ref={fileInputRef}
            className="visually-hidden"
            type="file"
            onChange={handleFileSelection}
          />
        </div>

        {notice && !securityOpen && <NoticeBanner notice={notice} />}

        <nav className="vault-breadcrumb" aria-label="Vault location">
          <button type="button" onClick={openRootFolder} disabled={currentFolderId === null}>
            Vault
          </button>
          {folderTrail.map((folder, index) => (
            <button
              key={folder.id}
              type="button"
              onClick={() => openTrailFolder(index)}
              disabled={index === folderTrail.length - 1}
            >
              {folder.name ?? "Encrypted folder"}
            </button>
          ))}
        </nav>

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

        <div className={`vault-browser vault-view-${vaultViewMode}`}>
          {vaultViewMode === "list" ? (
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
                {folders.map((folder) => (
                  <tr key={`folder-${folder.id}`}>
                    <td>
                      <button className="folder-name-button" type="button" onClick={() => openFolder(folder)}>
                        <div className="file-visual file-visual-list folder-visual">
                          <Folder size={20} />
                        </div>
                        <div>
                          <strong>{folder.name ?? "Unreadable encrypted folder"}</strong>
                          <span>Folder</span>
                        </div>
                      </button>
                    </td>
                    <td>Folder</td>
                    <td>{formatDate(folder.created_at)}</td>
                    <td>
                      <div className="row-actions">
                        <button type="button" className="icon-button" title="Open folder" aria-label={`Open ${folder.name ?? "folder"}`} onClick={() => openFolder(folder)} disabled={fileBusy || !folder.name}>
                          <FolderOpen size={18} />
                        </button>
                        <button type="button" className="icon-button danger" title="Delete folder" aria-label={`Delete ${folder.name ?? "folder"}`} onClick={() => void handleDeleteFolder(folder)} disabled={fileBusy}>
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {files.map((file) => (
                  <tr key={`file-${file.id}`}>
                    <td>
                      <div className="file-name-cell">
                        <FileVisual
                          file={file}
                          session={session}
                          thumbnailsHidden={thumbnailsHidden}
                          viewMode="list"
                        />
                        <div>
                          <strong>{file.manifest?.name ?? "Unreadable encrypted file"}</strong>
                          <span>{getFileTypeLabel(file)}</span>
                        </div>
                      </div>
                    </td>
                    <td>{formatBytes(file.encryption_metadata?.plaintext_size ?? 0)}</td>
                    <td>{formatDate(file.created_at)}</td>
                    <td>
                      <div className="row-actions">
                        <button type="button" className="icon-button" title="Preview image" aria-label={`Preview ${file.manifest?.name ?? "file"}`} onClick={() => openImagePreview(file)} disabled={fileBusy || !file.manifest || !file.encryption_metadata || !isImageFile(file)}>
                          <Eye size={18} />
                        </button>
                        <button type="button" className="icon-button" title="Download and decrypt" aria-label={`Download ${file.manifest?.name ?? "file"}`} onClick={() => void handleDownload(file)} disabled={fileBusy || !file.manifest}>
                          <Download size={18} />
                        </button>
                        <button type="button" className="icon-button" title="Share securely" aria-label={`Share ${file.manifest?.name ?? "file"}`} onClick={() => void openShareDialog(file)} disabled={fileBusy || !file.manifest || !file.encryption_metadata}>
                          <Share2 size={18} />
                        </button>
                        <button type="button" className="icon-button" title="Copy file" aria-label={`Copy ${file.manifest?.name ?? "file"}`} onClick={() => handleCopyFile(file)} disabled={fileBusy || !file.manifest}>
                          <Copy size={18} />
                        </button>
                        <button type="button" className="icon-button" title="Move file" aria-label={`Move ${file.manifest?.name ?? "file"}`} onClick={() => handleMoveFile(file)} disabled={fileBusy || !file.manifest}>
                          <Scissors size={18} />
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
          ) : (
            <div className="vault-grid">
              {folders.map((folder) => (
                <div className="vault-card" key={`folder-${folder.id}`}>
                  <button className="vault-card-main" type="button" onClick={() => openFolder(folder)} disabled={fileBusy || !folder.name}>
                    <div className={`file-visual file-visual-${vaultViewMode} folder-visual`}>
                      <Folder size={fileVisualIconSize(vaultViewMode)} />
                    </div>
                    <strong>{folder.name ?? "Unreadable encrypted folder"}</strong>
                    <span>Folder</span>
                  </button>
                  <div className="row-actions card-actions">
                    <button type="button" className="icon-button" title="Open folder" aria-label={`Open ${folder.name ?? "folder"}`} onClick={() => openFolder(folder)} disabled={fileBusy || !folder.name}>
                      <FolderOpen size={18} />
                    </button>
                    <button type="button" className="icon-button danger" title="Delete folder" aria-label={`Delete ${folder.name ?? "folder"}`} onClick={() => void handleDeleteFolder(folder)} disabled={fileBusy}>
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>
              ))}
              {files.map((file) => (
                <div className="vault-card" key={`file-${file.id}`}>
                  <button className="vault-card-main" type="button" onClick={() => openImagePreview(file)} disabled={!file.manifest || !file.encryption_metadata || !isImageFile(file)}>
                    <FileVisual
                      file={file}
                      session={session}
                      thumbnailsHidden={thumbnailsHidden}
                      viewMode={vaultViewMode}
                    />
                    <strong>{file.manifest?.name ?? "Unreadable encrypted file"}</strong>
                    <span>{getFileTypeLabel(file)}</span>
                  </button>
                  <div className="row-actions card-actions">
                    <button type="button" className="icon-button" title="Preview image" aria-label={`Preview ${file.manifest?.name ?? "file"}`} onClick={() => openImagePreview(file)} disabled={fileBusy || !file.manifest || !file.encryption_metadata || !isImageFile(file)}>
                      <Eye size={18} />
                    </button>
                    <button type="button" className="icon-button" title="Download and decrypt" aria-label={`Download ${file.manifest?.name ?? "file"}`} onClick={() => void handleDownload(file)} disabled={fileBusy || !file.manifest}>
                      <Download size={18} />
                    </button>
                    <button type="button" className="icon-button" title="Share securely" aria-label={`Share ${file.manifest?.name ?? "file"}`} onClick={() => void openShareDialog(file)} disabled={fileBusy || !file.manifest || !file.encryption_metadata}>
                      <Share2 size={18} />
                    </button>
                    <button type="button" className="icon-button" title="Copy file" aria-label={`Copy ${file.manifest?.name ?? "file"}`} onClick={() => handleCopyFile(file)} disabled={fileBusy || !file.manifest}>
                      <Copy size={18} />
                    </button>
                    <button type="button" className="icon-button" title="Move file" aria-label={`Move ${file.manifest?.name ?? "file"}`} onClick={() => handleMoveFile(file)} disabled={fileBusy || !file.manifest}>
                      <Scissors size={18} />
                    </button>
                    <button type="button" className="icon-button danger" title="Delete" aria-label={`Delete ${file.manifest?.name ?? "file"}`} onClick={() => void handleDelete(file)} disabled={fileBusy}>
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {!loadingFiles && totalVisibleItems === 0 && (
            <div className="empty-state">
              <FolderOpen size={32} />
              <strong>Vault is empty</strong>
              <span>{currentFolderId === null ? "Your vault is empty." : "This folder is empty."}</span>
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

      {createFolderOpen && (
        <div className="modal-backdrop" role="presentation">
          <section className="modal-panel folder-panel" role="dialog" aria-modal="true" aria-labelledby="folder-title">
            <div className="modal-header">
              <div>
                <h2 id="folder-title">New folder</h2>
                <p>{currentFolderName}</p>
              </div>
              <button className="icon-button" type="button" onClick={() => {
                setCreateFolderOpen(false);
                setNotice(null);
              }} title="Close" aria-label="Close folder dialog">
                <X size={19} />
              </button>
            </div>

            <form className="folder-form" onSubmit={handleCreateFolder}>
              <label>
                Folder name
                <input name="folder_name" required maxLength={160} autoComplete="off" autoFocus />
              </label>

              <button className="primary-button" type="submit" disabled={fileBusy}>
                {fileBusy ? <LoaderCircle className="spin" size={18} /> : <FolderPlus size={18} />}
                Create folder
              </button>
            </form>

            {notice && <NoticeBanner notice={notice} />}
          </section>
        </div>
      )}

      {previewFile && (
        <ImagePreviewModal
          file={previewFile}
          session={session}
          onClose={() => setPreviewFile(null)}
        />
      )}

      {securityOpen && (
        <div className="modal-backdrop" role="presentation">
          <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="security-title">
            <div className="modal-header">
              <div>
                <h2 id="security-title">Account security</h2>
                <p>Manage passwords, recovery, and active sessions.</p>
              </div>
              <button className="icon-button" type="button" onClick={() => {
                setSecurityOpen(false);
                setNotice(null);
              }} title="Close" aria-label="Close account security">
                <X size={19} />
              </button>
            </div>

            <form className="security-form" onSubmit={handlePasswordChange}>
              <h3>Change password</h3>
              <label>
                Current password
                <input name="current_password" type="password" required minLength={8} autoComplete="current-password" />
              </label>
              <label>
                New password
                <input name="new_password" type="password" required minLength={8} autoComplete="new-password" />
              </label>
              <label>
                Confirm new password
                <input name="confirm_password" type="password" required minLength={8} autoComplete="new-password" />
              </label>
              <button className="primary-button" type="submit" disabled={authBusy}>
                {authBusy ? <LoaderCircle className="spin" size={18} /> : <KeyRound size={18} />}
                Change password
              </button>
            </form>

            <div className="security-section">
              <div>
                <h3>Trusted device</h3>
                <p>{deviceUnlockAvailable ? "Vault can reopen after refresh on this browser." : "This browser is not remembered."}</p>
              </div>
              {deviceUnlockAvailable && (
                <button className="secondary-button danger-command" type="button" onClick={() => void handleTrustedDeviceRemoval()} disabled={authBusy}>
                  <Trash2 size={17} />
                  Forget device
                </button>
              )}
            </div>

            <div className="security-section">
              <h3>Recovery key</h3>
              <button className="secondary-button" type="button" onClick={() => void handleRecoveryKeyRotation()} disabled={authBusy}>
                <RotateCw size={17} />
                Replace recovery key
              </button>
            </div>

            <div className="security-section danger-section">
              <h3>Sessions</h3>
              <button className="secondary-button danger-command" type="button" onClick={() => void handleLogout(true)} disabled={authBusy}>
                <LogOut size={17} />
                Log out all devices
              </button>
            </div>

            {notice && <NoticeBanner notice={notice} />}
          </section>
        </div>
      )}

      {shareFile && (
        <div className="modal-backdrop" role="presentation">
          <section className="modal-panel share-panel" role="dialog" aria-modal="true" aria-labelledby="share-title">
            <div className="modal-header">
              <div>
                <h2 id="share-title">Secure share</h2>
                <p>{shareFile.manifest?.name ?? "Encrypted file"}</p>
              </div>
              <button className="icon-button" type="button" onClick={() => {
                setShareFile(null);
                setShareLink(null);
                setNotice(null);
              }} title="Close" aria-label="Close share manager">
                <X size={19} />
              </button>
            </div>

            <form className="share-form" onSubmit={handleCreateShare}>
              <div className="share-form-grid">
                <label>
                  Share password
                  <input name="share_password" type="password" required minLength={12} autoComplete="new-password" />
                </label>
                <label>
                  Confirm password
                  <input name="confirm_share_password" type="password" required minLength={12} autoComplete="new-password" />
                </label>
              </div>
              <label>
                Expires
                <select name="expiry_days" defaultValue="7">
                  <option value="1">In 1 day</option>
                  <option value="7">In 7 days</option>
                  <option value="30">In 30 days</option>
                  <option value="never">Never</option>
                </select>
              </label>
              <button className="primary-button" type="submit" disabled={shareBusy}>
                {shareBusy ? <LoaderCircle className="spin" size={18} /> : <Link2 size={18} />}
                Create encrypted link
              </button>
            </form>

            {shareLink && (
              <div className="share-link-result">
                <input value={shareLink} readOnly aria-label="New share link" />
                <button className="icon-button" type="button" onClick={() => void copyShareLink()} title="Copy link" aria-label="Copy share link">
                  <Copy size={18} />
                </button>
              </div>
            )}

            <div className="share-list-section">
              <h3>Share history</h3>
              {shareBusy && fileShares.length === 0 ? (
                <div className="share-list-empty"><LoaderCircle className="spin" size={18} /> Loading</div>
              ) : fileShares.length === 0 ? (
                <div className="share-list-empty">No share links</div>
              ) : (
                <div className="share-list">
                  {fileShares.map((share) => {
                    const expired = share.expires_at
                      ? new Date(share.expires_at).getTime() <= Date.now()
                      : false;
                    const statusLabel = share.revoked_at
                      ? "Revoked"
                      : expired
                        ? "Expired"
                        : "Active";

                    return (
                      <div className="share-list-row" key={share.id}>
                        <div>
                          <strong>{statusLabel}</strong>
                          <span>{share.expires_at ? `Expires ${formatDate(share.expires_at)}` : "No expiration"}</span>
                        </div>
                        <button className="icon-button danger" type="button" onClick={() => void handleRevokeShare(share)} disabled={shareBusy || Boolean(share.revoked_at) || expired} title="Revoke" aria-label="Revoke share">
                          <Trash2 size={17} />
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {notice && <NoticeBanner notice={notice} />}
          </section>
        </div>
      )}

      {recoveryKeyToSave && (
        <div className="modal-backdrop" role="presentation">
          <section className="modal-panel recovery-panel" role="dialog" aria-modal="true" aria-labelledby="recovery-key-title">
            <div className="modal-header">
              <div>
                <h2 id="recovery-key-title">Save your recovery key</h2>
                <p>This is the only way to recover encrypted Vault data after a forgotten password.</p>
              </div>
              <ShieldCheck size={24} />
            </div>

            <code className="recovery-key-value">{recoveryKeyToSave}</code>

            <div className="recovery-actions">
              <button className="secondary-button" type="button" onClick={() => void copyRecoveryKey()}>
                <Copy size={17} />
                Copy
              </button>
              <button className="secondary-button" type="button" onClick={downloadRecoveryKey}>
                <Download size={17} />
                Download
              </button>
            </div>

            <button className="primary-button" type="button" onClick={() => setRecoveryKeyToSave(null)}>
              <CheckCircle2 size={18} />
              I saved the recovery key
            </button>
          </section>
        </div>
      )}

      <footer className="app-footer">
        <span><Cloud size={15} /> API connected</span>
        <span><ShieldCheck size={15} /> Protocol v1</span>
      </footer>
    </main>
  );
}


function fileVisualIconSize(viewMode: VaultViewMode): number {
  if (viewMode === "large") return 48;
  if (viewMode === "medium") return 36;
  if (viewMode === "small") return 26;
  return 20;
}


function FileVisual({
  file,
  session,
  thumbnailsHidden,
  viewMode
}: {
  file: DisplayFile;
  session: Session;
  thumbnailsHidden: boolean;
  viewMode: VaultViewMode;
}) {
  const iconSize = fileVisualIconSize(viewMode);

  if (file.encryption_metadata && isImageFile(file) && !thumbnailsHidden) {
    return (
      <ImageThumbnail
        file={file}
        session={session}
        viewMode={viewMode}
      />
    );
  }

  return (
    <div className={`file-visual file-visual-${viewMode}`}>
      {renderFileTypeIcon(file, iconSize)}
    </div>
  );
}


function ImageThumbnail({
  file,
  session,
  viewMode
}: {
  file: DisplayFile;
  session: Session;
  viewMode: VaultViewMode;
}) {
  const [thumbnailUrl, setThumbnailUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!file.encryption_metadata) return;

    let active = true;
    let objectUrl: string | null = null;

    async function loadThumbnail() {
      try {
        const ciphertext = await downloadEncryptedFile(session.token, file.id);
        const decrypted = await decryptFileInWorker(
          ciphertext,
          file.encrypted_filename,
          file.encryption_metadata!,
          session.vaultKey
        );
        const nextUrl = URL.createObjectURL(decrypted.content);

        if (!active) {
          URL.revokeObjectURL(nextUrl);
          return;
        }

        objectUrl = nextUrl;
        setThumbnailUrl(nextUrl);
      } catch {
        if (active) {
          setFailed(true);
        }
      }
    }

    void loadThumbnail();

    return () => {
      active = false;

      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
    };
  }, [
    file.encrypted_filename,
    file.encryption_metadata,
    file.id,
    session.token,
    session.vaultKey
  ]);

  return (
    <div className={`file-visual file-visual-${viewMode} image-visual`}>
      {thumbnailUrl ? (
        <img src={thumbnailUrl} alt="" loading="lazy" />
      ) : failed ? (
        <FileImage size={fileVisualIconSize(viewMode)} />
      ) : (
        <LoaderCircle className="spin" size={18} />
      )}
    </div>
  );
}


function ImagePreviewModal({
  file,
  session,
  onClose
}: {
  file: DisplayFile;
  session: Session;
  onClose: () => void;
}) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const name = file.manifest?.name ?? "Encrypted image";

  useEffect(() => {
    if (!file.encryption_metadata) {
      setBusy(false);
      setError("Image metadata is unavailable");
      return;
    }

    let active = true;
    let objectUrl: string | null = null;

    async function loadPreview() {
      setBusy(true);
      setError(null);

      try {
        const ciphertext = await downloadEncryptedFile(session.token, file.id);
        const decrypted = await decryptFileInWorker(
          ciphertext,
          file.encrypted_filename,
          file.encryption_metadata!,
          session.vaultKey
        );
        const nextUrl = URL.createObjectURL(decrypted.content);

        if (!active) {
          URL.revokeObjectURL(nextUrl);
          return;
        }

        objectUrl = nextUrl;
        setPreviewUrl(nextUrl);
      } catch (loadError) {
        if (active) {
          setError(getErrorMessage(loadError));
        }
      } finally {
        if (active) {
          setBusy(false);
        }
      }
    }

    void loadPreview();

    return () => {
      active = false;

      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
    };
  }, [
    file.encrypted_filename,
    file.encryption_metadata,
    file.id,
    session.token,
    session.vaultKey
  ]);

  return (
    <div className="modal-backdrop image-preview-backdrop" role="presentation">
      <section className="modal-panel image-preview-panel" role="dialog" aria-modal="true" aria-labelledby="image-preview-title">
        <div className="modal-header">
          <div>
            <h2 id="image-preview-title">{name}</h2>
            <p>{getFileTypeLabel(file)}</p>
          </div>
          <button className="icon-button" type="button" onClick={onClose} title="Close" aria-label="Close preview">
            <X size={19} />
          </button>
        </div>

        <div className="image-preview-stage">
          {busy ? (
            <div className="image-preview-state">
              <LoaderCircle className="spin" size={26} />
              <span>Decrypting preview</span>
            </div>
          ) : error ? (
            <div className="image-preview-state error-state">
              <AlertCircle size={26} />
              <span>{error}</span>
            </div>
          ) : previewUrl ? (
            <img src={previewUrl} alt={name} />
          ) : null}
        </div>

        {previewUrl && (
          <div className="image-preview-actions">
            <a className="secondary-button" href={previewUrl} download={name}>
              <Download size={17} />
              Download
            </a>
          </div>
        )}
      </section>
    </div>
  );
}


function SharedFilePage({ token }: { token: string }) {
  const [info, setInfo] = useState<ShareAccessInfo | null>(null);
  const [sharedFile, setSharedFile] = useState<ShareUnlockResponse | null>(null);
  const [manifestName, setManifestName] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState<Notice | null>(null);
  const shareKeyRef = useRef<Uint8Array | null>(null);

  useEffect(() => {
    void getShareAccessInfo(token)
      .then(setInfo)
      .catch((error) => setNotice({
        tone: "error",
        message: getErrorMessage(error)
      }))
      .finally(() => setBusy(false));

    return () => {
      if (shareKeyRef.current) {
        void import("./crypto").then(({ zeroKey }) => (
          zeroKey(shareKeyRef.current!)
        ));
      }
    };
  }, [token]);

  async function handleShareUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!info) return;

    setBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const password = String(form.get("share_password") ?? "");
    let access: ShareAccess | null = null;

    try {
      const { decryptSharedManifest, deriveShareAccess, zeroKey } = await import("./crypto");
      access = await deriveShareAccess(password, token, info);
      const unlocked = await unlockFileShare(token, access.passwordVerifier);
      const manifest = await decryptSharedManifest(
        token,
        unlocked,
        access.shareKey
      );

      if (shareKeyRef.current) await zeroKey(shareKeyRef.current);
      shareKeyRef.current = access.shareKey;
      access = null;
      setSharedFile(unlocked);
      setManifestName(manifest.name);
      setNotice({ tone: "success", message: "Encrypted share unlocked" });
    } catch (error) {
      if (access) {
        const { zeroKey } = await import("./crypto");
        await zeroKey(access.shareKey);
      }
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setBusy(false);
    }
  }

  async function handleSharedDownload() {
    if (!sharedFile || !shareKeyRef.current) return;

    setBusy(true);
    setProgress(0);
    setNotice(null);

    try {
      const ciphertext = await downloadSharedFile(
        token,
        sharedFile.download_token
      );
      const decrypted = await decryptSharedFileInWorker(
        ciphertext,
        token,
        sharedFile,
        shareKeyRef.current,
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
      setBusy(false);
      setProgress(0);
    }
  }

  return (
    <main className="shared-shell">
      <header className="shared-topbar">
        <div className="brand-lockup dark-text">
          <div className="brand-mark"><LockKeyhole size={21} /></div>
          <span>Prototype</span>
        </div>
        <span className="shared-security"><ShieldCheck size={17} /> End-to-end encrypted</span>
      </header>

      <section className="shared-workspace">
        <div className="shared-file-mark"><FileLock2 size={30} /></div>
        <div className="shared-heading">
          <h1>{manifestName ?? "Encrypted file share"}</h1>
          <p>{info?.expires_at ? `Expires ${formatDate(info.expires_at)}` : "No expiration"}</p>
        </div>

        {!sharedFile && info && (
          <form className="shared-unlock-form" onSubmit={handleShareUnlock}>
            <label>
              Share password
              <input name="share_password" type="password" required minLength={12} autoComplete="current-password" autoFocus />
            </label>
            <button className="primary-button" type="submit" disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={18} /> : <KeyRound size={18} />}
              Unlock file
            </button>
          </form>
        )}

        {sharedFile && (
          <div className="shared-download">
            <div>
              <span>File size</span>
              <strong>{formatBytes(sharedFile.encryption_metadata.plaintext_size)}</strong>
            </div>
            <button className="primary-button" type="button" onClick={() => void handleSharedDownload()} disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={18} /> : <Download size={18} />}
              Download and decrypt
            </button>
          </div>
        )}

        {busy && progress > 0 && (
          <div className="progress-row" aria-live="polite">
            <div className="progress-track"><span style={{ width: `${progress}%` }} /></div>
            <strong>{progress}%</strong>
          </div>
        )}

        {notice && <NoticeBanner notice={notice} />}
      </section>
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
