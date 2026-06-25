import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Cloud,
  Copy,
  Download,
  FileLock2,
  FolderOpen,
  KeyRound,
  Link2,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MailCheck,
  RotateCw,
  Settings,
  Share2,
  ShieldCheck,
  Trash2,
  UploadCloud,
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
  createCryptoProfile,
  createFileShare,
  deleteFile,
  downloadSharedFile,
  downloadEncryptedFile,
  getCryptoProfile,
  getCurrentUser,
  getShareAccessInfo,
  listFileShares,
  listFiles,
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
  FileShare,
  PasswordRecoveryGrant,
  ShareAccessInfo,
  ShareUnlockResponse,
  User
} from "./types";
import type { ShareAccess, VaultPasscodeLength } from "./crypto";


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
type VaultRoute = "auth" | "files";

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


function getShareTokenFromLocation(): string | null {
  const match = window.location.pathname.match(/^\/share\/([^/]+)\/?$/);

  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}


function getVaultRouteFromLocation(): VaultRoute {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";

  return path === "/files" ? "files" : "auth";
}


function vaultRoutePath(route: VaultRoute): string {
  return route === "files" ? "/files" : "/";
}


export default function App() {
  const shareToken = getShareTokenFromLocation();
  return shareToken ? <SharedFilePage token={shareToken} /> : <VaultApp />;
}


function VaultApp() {
  const [route, setRoute] = useState<VaultRoute>(getVaultRouteFromLocation);
  const [authMode, setAuthMode] = useState<"login" | "register">(
    () => {
      const stored = sessionStorage.getItem("zkcs:authMode");
      return stored === "register" ? "register" : "login";
    }
  );

  const navigateTo = useCallback((nextRoute: VaultRoute, replace = false) => {
    const nextPath = vaultRoutePath(nextRoute);

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
      setRoute(getVaultRouteFromLocation());
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  // Keep sessionStorage in sync whenever authMode changes
  useEffect(() => {
    sessionStorage.setItem("zkcs:authMode", authMode);
  }, [authMode]);

  useEffect(() => {
    sessionStorage.removeItem("zkcs:vaultKey");
  }, []);

  const [session, setSession] = useState<Session | null>(null);
  const [restoredAuth, setRestoredAuth] = useState<RestoredAuth | null>(null);
  const [checkingStoredSession, setCheckingStoredSession] = useState(true);
  const [passcodeAvailable, setPasscodeAvailable] = useState(false);
  const [unlockMethod, setUnlockMethod] = useState<"passcode" | "password">(
    "password"
  );
  const [files, setFiles] = useState<DisplayFile[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
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
        const { hasLocalVaultPasscode } = await import("./crypto");

        if (cancelled) return;

        setRestoredAuth({
          token: tokenResponse.access_token,
          user
        });
        setPasscodeAvailable(hasLocalVaultPasscode(user.id));
      } catch {
        // No valid refresh cookie means the normal sign-in form is shown.
        if (!cancelled) {
          setPasscodeAvailable(false);
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
    if (restoredAuth) {
      setUnlockMethod(passcodeAvailable ? "passcode" : "password");
    }
  }, [passcodeAvailable, restoredAuth]);

  const totalPlaintextBytes = useMemo(
    () => files.reduce(
      (total, file) => total + (
        file.encryption_metadata?.plaintext_size ?? 0
      ),
      0
    ),
    [files]
  );

  async function unlockVaultSession(
    token: string,
    user: User,
    password: string,
  ) {
    let vaultKey: Uint8Array;
    let recoveryKey: string | null = null;
    const {
      createVaultProfile,
      hasLocalVaultPasscode,
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

    setSession({ token, user, vaultKey });
    setRestoredAuth(null);
    setPasscodeAvailable(hasLocalVaultPasscode(user.id));
    setUnlockMethod("password");
    setRecoveryKeyToSave(recoveryKey);
    setNotice({ tone: "success", message: "Vault unlocked" });
    navigateTo("files");
  }

  async function establishSession(
    username: string,
    password: string,
    registeredUser?: User
  ) {
    const tokenResponse = await login(username, password);
    const token = tokenResponse.access_token;
    const user = registeredUser ?? await getCurrentUser(token);

    await unlockVaultSession(token, user, password);
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

  async function handleRestoredUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!restoredAuth) return;

    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");

    try {
      await unlockVaultSession(restoredAuth.token, restoredAuth.user, password);
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handlePasscodeUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!restoredAuth) return;

    setAuthBusy(true);
    setNotice(null);
    const form = new FormData(event.currentTarget);
    const passcode = String(form.get("passcode") ?? "").trim();
    let vaultKey: Uint8Array | null = null;

    try {
      const { unlockVaultWithLocalPasscode } = await import("./crypto");
      vaultKey = await unlockVaultWithLocalPasscode(
        passcode,
        restoredAuth.user.id
      );
      setSession({
        token: restoredAuth.token,
        user: restoredAuth.user,
        vaultKey
      });
      vaultKey = null;
      setRestoredAuth(null);
      setNotice({ tone: "success", message: "Files unlocked" });
      navigateTo("files");
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      if (vaultKey) {
        const { zeroKey } = await import("./crypto");
        await zeroKey(vaultKey);
      }

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
      setPasscodeAvailable(false);
      setUnlockMethod("password");
      setAuthMode("login");
      navigateTo("auth");
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
        hasLocalVaultPasscode,
        rewrapVaultKey,
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
      setSession({
        token: tokenResponse.access_token,
        user,
        vaultKey: recoveredVaultKey
      });
      setRestoredAuth(null);
      setPasscodeAvailable(hasLocalVaultPasscode(user.id));
      setUnlockMethod("password");
      recoveredVaultKey = null;
      setRecoveryStage(null);
      setPendingPasswordRecovery(null);
      setPasswordRecoveryGrant(null);
      setNotice({ tone: "success", message: "Password recovered" });
      navigateTo("files");
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

  async function handlePasscodeChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session) return;

    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const passcodeLength = Number(
      form.get("passcode_length") ?? "6"
    ) as VaultPasscodeLength;
    const passcode = String(form.get("passcode") ?? "").trim();
    const confirmPasscode = String(
      form.get("confirm_passcode") ?? ""
    ).trim();

    if (![4, 6, 8].includes(passcodeLength)) {
      setNotice({ tone: "error", message: "Choose a valid passcode length" });
      return;
    }

    if (!/^\d+$/.test(passcode) || passcode.length !== passcodeLength) {
      setNotice({
        tone: "error",
        message: `Passcode must be exactly ${passcodeLength} digits`
      });
      return;
    }

    if (passcode !== confirmPasscode) {
      setNotice({ tone: "error", message: "Passcodes do not match" });
      return;
    }

    setAuthBusy(true);
    setNotice(null);

    try {
      const { saveLocalVaultPasscode } = await import("./crypto");
      await saveLocalVaultPasscode(
        passcode,
        session.user.id,
        session.vaultKey,
        passcodeLength
      );
      setPasscodeAvailable(true);
      formElement.reset();
      setNotice({ tone: "success", message: "Files passcode saved" });
    } catch (error) {
      setNotice({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setAuthBusy(false);
    }
  }

  async function handlePasscodeRemoval() {
    if (!session) return;

    if (!window.confirm("Remove the files passcode from this device?")) {
      return;
    }

    setAuthBusy(true);
    setNotice(null);

    try {
      const { removeLocalVaultPasscode } = await import("./crypto");
      removeLocalVaultPasscode(session.user.id);
      setPasscodeAvailable(false);
      setUnlockMethod("password");
      setNotice({ tone: "success", message: "Files passcode removed" });
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
    setPasscodeAvailable(false);
    setUnlockMethod("password");
    setFiles([]);
    setSecurityOpen(false);
    setShareFile(null);
  }

  async function handleLockVault() {
    if (!session) return;

    const activeSession = session;
    const restoredSession = {
      token: activeSession.token,
      user: activeSession.user
    };
    const { hasLocalVaultPasscode } = await import("./crypto");
    const hasPasscode = hasLocalVaultPasscode(activeSession.user.id);

    await clearLocalSession(activeSession);
    setRestoredAuth(restoredSession);
    setPasscodeAvailable(hasPasscode);
    setUnlockMethod(hasPasscode ? "passcode" : "password");
    navigateTo("files");
    setNotice(null);
  }

  async function handleLogout(allDevices = false) {
    if (!session) return;

    const activeSession = session;

    try {
      if (allDevices) {
        await logoutAll(activeSession.token);
      } else {
        await logout(activeSession.token);
      }
    } catch {
      // The local vault still locks if the network session is already invalid.
    } finally {
      await clearLocalSession(activeSession);
      navigateTo("auth");
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

    if (passcodeAvailable && unlockMethod === "passcode") {
      return (
        <form key="restored-passcode-form" className={formClassName} onSubmit={handlePasscodeUnlock}>
          <div className="restored-account">
            <strong>{restoredAuth.user.username}</strong>
            <span>{restoredAuth.user.email}</span>
          </div>

          <label>
            Files passcode
            <input
              name="passcode"
              type="password"
              required
              minLength={4}
              maxLength={8}
              pattern="[0-9]{4}|[0-9]{6}|[0-9]{8}"
              inputMode="numeric"
              autoComplete="off"
              autoFocus
            />
          </label>

          <button className="primary-button" type="submit" disabled={authBusy}>
            {authBusy ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
            Unlock files
          </button>

          <button className="text-button" type="button" onClick={() => setUnlockMethod("password")} disabled={authBusy}>
            Use account password
          </button>

          <button className="text-button" type="button" onClick={() => void handleUseAnotherAccount()} disabled={authBusy}>
            Use another account
          </button>
        </form>
      );
    }

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

        {passcodeAvailable && (
          <button className="text-button" type="button" onClick={() => setUnlockMethod("passcode")} disabled={authBusy}>
            Use files passcode
          </button>
        )}

        <button className="text-button" type="button" onClick={() => void handleUseAnotherAccount()} disabled={authBusy}>
          Use another account
        </button>
      </form>
    );
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
      ? passcodeAvailable && unlockMethod === "passcode"
        ? `Signed in as ${restoredAuth.user.username}. Enter your files passcode.`
        : `Signed in as ${restoredAuth.user.username}. Enter your password to decrypt files.`
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
  const shouldRenderLockedFilesRoute = (
    route === "files"
    && !pendingRegistration
    && !recoveryStage
    && (checkingStoredSession || Boolean(restoredAuth))
  );

  if (!session && shouldRenderLockedFilesRoute) {
    return (
      <main className="app-shell">
        <header className="topbar">
          <div className="brand-lockup dark-text">
            <div className="brand-mark"><LockKeyhole size={21} /></div>
            <span>Prototype</span>
          </div>

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
            <span>Files</span>
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
              <h1>Files</h1>
              <p>
                {checkingStoredSession
                  ? "Checking saved session"
                  : passcodeAvailable && unlockMethod === "passcode"
                    ? "Enter your files passcode to continue"
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
        <div className="brand-lockup dark-text">
          <div className="brand-mark"><LockKeyhole size={21} /></div>
          <span>Prototype</span>
        </div>

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
          <button className="icon-button" type="button" onClick={() => void handleLockVault()} title="Lock files" aria-label="Lock files">
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

        {notice && !securityOpen && <NoticeBanner notice={notice} />}

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
                      <button type="button" className="icon-button" title="Share securely" aria-label={`Share ${file.manifest?.name ?? "file"}`} onClick={() => void openShareDialog(file)} disabled={fileBusy || !file.manifest || !file.encryption_metadata}>
                        <Share2 size={18} />
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

            <form className="security-form" onSubmit={handlePasscodeChange}>
              <h3>{passcodeAvailable ? "Update files passcode" : "Create files passcode"}</h3>
              <label>
                Passcode length
                <select name="passcode_length" defaultValue="6">
                  <option value="4">4 digits</option>
                  <option value="6">6 digits</option>
                  <option value="8">8 digits</option>
                </select>
              </label>
              <label>
                Files passcode
                <input
                  name="passcode"
                  type="password"
                  required
                  minLength={4}
                  maxLength={8}
                  pattern="[0-9]{4}|[0-9]{6}|[0-9]{8}"
                  inputMode="numeric"
                  autoComplete="off"
                />
              </label>
              <label>
                Confirm passcode
                <input
                  name="confirm_passcode"
                  type="password"
                  required
                  minLength={4}
                  maxLength={8}
                  pattern="[0-9]{4}|[0-9]{6}|[0-9]{8}"
                  inputMode="numeric"
                  autoComplete="off"
                />
              </label>
              <button className="primary-button" type="submit" disabled={authBusy}>
                {authBusy ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
                {passcodeAvailable ? "Update passcode" : "Save passcode"}
              </button>
            </form>

            {passcodeAvailable && (
              <div className="security-section">
                <h3>Files passcode</h3>
                <button className="secondary-button danger-command" type="button" onClick={() => void handlePasscodeRemoval()} disabled={authBusy}>
                  <Trash2 size={17} />
                  Remove from device
                </button>
              </div>
            )}

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
                <p>This is the only way to recover encrypted files after a forgotten password.</p>
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
