from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.config import settings
from app.database.dependencies import (
    get_current_session,
    get_current_user,
    get_db
)
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.account import (
    PasswordChangeRequest,
    PasswordRecoveryComplete,
    PasswordRecoveryGrantResponse,
    PasswordRecoveryRequest,
    PasswordRecoveryVerify,
    RecoveryKeyRotateRequest
)
from app.schemas.crypto import (
    CryptoProfileCreate,
    CryptoProfileResponse,
    RecoveryProfileBase,
    RecoveryProfileResponse
)
from app.schemas.registration import (
    RegistrationOtpResponse,
    RegistrationOtpVerify
)
from app.schemas.user import (
    ProtectedRouteResponse,
    TokenResponse,
    UserRegister,
    UserResponse
)
from app.services.account_security_service import (
    AccountPasswordError,
    PasswordRecoveryError,
    PasswordRecoveryExpiredError,
    PasswordRecoveryNotConfiguredError,
    PasswordRecoveryRateLimitError,
    cancel_password_recovery_verification,
    change_password,
    complete_password_recovery,
    create_password_recovery_verification,
    rotate_recovery_key,
    verify_password_recovery_otp
)
from app.services.auth_service import authenticate_user
from app.services.crypto_profile_service import (
    CryptoProfileExistsError,
    create_crypto_profile,
    get_crypto_profile
)
from app.services.email_service import (
    EmailDeliveryError,
    EmailSender,
    get_email_sender,
    get_password_recovery_email_sender
)
from app.services.login_throttle_service import (
    LoginRateLimitError,
    check_login_allowed,
    clear_login_failures,
    login_throttle_key,
    record_login_failure
)
from app.services.registration_service import (
    RegistrationConflictError,
    RegistrationRateLimitError,
    RegistrationVerificationError,
    RegistrationVerificationExpiredError,
    cancel_registration_verification,
    create_registration_verification,
    verify_registration
)
from app.services.session_service import (
    InvalidRefreshTokenError,
    SessionTokens,
    create_user_session,
    revoke_all_user_sessions,
    revoke_session,
    rotate_refresh_token
)


REFRESH_COOKIE_PATH = (
    f"{settings.api_prefix}/auth"
    if settings.api_prefix
    else "/auth"
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH
    )


def _token_response(tokens: SessionTokens) -> TokenResponse:
    return TokenResponse(
        access_token=tokens.access_token,
        token_type="bearer",
        expires_in_seconds=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/register/request-otp",
    response_model=RegistrationOtpResponse,
    status_code=status.HTTP_202_ACCEPTED
)
def request_registration_otp(
    user: UserRegister,
    db: Session = Depends(get_db),
    send_otp: EmailSender = Depends(get_email_sender)
):
    try:
        verification, otp = create_registration_verification(db, user)
    except RegistrationRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)}
        ) from exc
    except RegistrationConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration verification is not configured"
        ) from exc

    try:
        send_otp(verification.email, otp)
    except EmailDeliveryError as exc:
        cancel_registration_verification(db, verification.id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send verification email"
        ) from exc

    return RegistrationOtpResponse(
        verification_id=verification.id,
        expires_in_seconds=settings.registration_otp_expire_minutes * 60,
        resend_after_seconds=(
            settings.registration_otp_resend_cooldown_seconds
        ),
        message="Verification code sent"
    )


@router.post(
    "/register/verify",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def complete_registration(
    verification_data: RegistrationOtpVerify,
    db: Session = Depends(get_db)
):
    try:
        return verify_registration(db, verification_data)
    except RegistrationConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc)
        ) from exc
    except RegistrationVerificationExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=str(exc)
        ) from exc
    except RegistrationVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        ) from exc


@router.post("/login", response_model=TokenResponse)
def login_user(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_host = request.client.host if request.client else "unknown"

    try:
        throttle_key = login_throttle_key(form_data.username, client_host)
        check_login_allowed(db, throttle_key)
    except LoginRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)}
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication throttling is not configured"
        ) from exc

    user = authenticate_user(
        db,
        form_data.username,
        form_data.password
    )

    if user is None:
        record_login_failure(db, throttle_key)

        try:
            check_login_allowed(db, throttle_key)
        except LoginRateLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(exc),
                headers={"Retry-After": str(exc.retry_after_seconds)}
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    clear_login_failures(db, throttle_key)

    try:
        tokens = create_user_session(db, user)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session management is not configured"
        ) from exc

    _set_refresh_cookie(response, tokens.refresh_token)
    return _token_response(tokens)


@router.post("/refresh", response_model=TokenResponse)
def refresh_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    refresh_token = request.cookies.get(settings.refresh_cookie_name)

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is missing"
        )

    try:
        _, tokens = rotate_refresh_token(db, refresh_token)
    except (InvalidRefreshTokenError, RuntimeError) as exc:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh session is invalid"
        ) from exc

    _set_refresh_cookie(response, tokens.refresh_token)
    return _token_response(tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_current_session(
    response: Response,
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    revoke_session(db, current_session)
    _clear_refresh_cookie(response)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all_sessions(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    revoke_all_user_sessions(db, current_user)
    _clear_refresh_cookie(response)


@router.get("/me", response_model=UserResponse)
def read_current_user(
    current_user: User = Depends(get_current_user)
):
    return current_user


@router.post(
    "/crypto-profile",
    response_model=CryptoProfileResponse,
    status_code=status.HTTP_201_CREATED
)
def create_current_user_crypto_profile(
    profile_data: CryptoProfileCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        return create_crypto_profile(db, current_user.id, profile_data)
    except CryptoProfileExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Crypto profile already exists"
        ) from exc


@router.get("/crypto-profile", response_model=CryptoProfileResponse)
def read_current_user_crypto_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    profile = get_crypto_profile(db, current_user.id)

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Crypto profile not found"
        )

    return profile


@router.post("/password/change", response_model=TokenResponse)
def change_current_password(
    data: PasswordChangeRequest,
    response: Response,
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    try:
        tokens = change_password(
            db,
            current_session.user,
            current_session,
            data
        )
    except AccountPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        ) from exc
    except PasswordRecoveryNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc)
        ) from exc

    _set_refresh_cookie(response, tokens.refresh_token)
    return _token_response(tokens)


@router.put(
    "/recovery-key",
    response_model=RecoveryProfileResponse
)
def replace_recovery_key(
    data: RecoveryKeyRotateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        return rotate_recovery_key(db, current_user, data)
    except PasswordRecoveryNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc)
        ) from exc


@router.post(
    "/password/recovery/request-otp",
    response_model=RegistrationOtpResponse,
    status_code=status.HTTP_202_ACCEPTED
)
def request_password_recovery_otp(
    data: PasswordRecoveryRequest,
    db: Session = Depends(get_db),
    send_otp: EmailSender = Depends(get_password_recovery_email_sender)
):
    try:
        verification, otp, recipient = (
            create_password_recovery_verification(db, data.identifier)
        )
    except PasswordRecoveryRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)}
        ) from exc

    if recipient:
        try:
            send_otp(recipient, otp)
        except EmailDeliveryError as exc:
            cancel_password_recovery_verification(db, verification.id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to send recovery email"
            ) from exc

    return RegistrationOtpResponse(
        verification_id=verification.id,
        expires_in_seconds=(
            settings.password_recovery_otp_expire_minutes * 60
        ),
        resend_after_seconds=(
            settings.registration_otp_resend_cooldown_seconds
        ),
        message="If the account exists, a recovery code was sent"
    )


@router.post(
    "/password/recovery/verify",
    response_model=PasswordRecoveryGrantResponse
)
def verify_password_recovery_code(
    data: PasswordRecoveryVerify,
    db: Session = Depends(get_db)
):
    try:
        recovery_token, user, profile = verify_password_recovery_otp(db, data)
    except PasswordRecoveryExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=str(exc)
        ) from exc
    except PasswordRecoveryNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc)
        ) from exc
    except PasswordRecoveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        ) from exc

    return PasswordRecoveryGrantResponse(
        recovery_token=recovery_token,
        user_id=user.id,
        recovery_profile=RecoveryProfileBase.model_validate(
            profile,
            from_attributes=True
        )
    )


@router.post(
    "/password/recovery/complete",
    response_model=TokenResponse
)
def recover_password(
    data: PasswordRecoveryComplete,
    response: Response,
    db: Session = Depends(get_db)
):
    try:
        _, tokens = complete_password_recovery(db, data)
    except PasswordRecoveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        ) from exc

    _set_refresh_cookie(response, tokens.refresh_token)
    return _token_response(tokens)


@router.get("/protected", response_model=ProtectedRouteResponse)
def protected_route(
    current_user: User = Depends(get_current_user)
):
    return ProtectedRouteResponse(
        message="Authenticated request successful",
        username=current_user.username
    )
