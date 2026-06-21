from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database.dependencies import get_current_user, get_db
from app.models.user import User
from app.config import settings
from app.schemas.crypto import (
    CryptoProfileCreate,
    CryptoProfileResponse,
    CryptoProfileRewrap
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
from app.services.auth_service import (
    authenticate_user,
    create_user_access_token,
)
from app.services.crypto_profile_service import (
    CryptoProfileExistsError,
    create_crypto_profile,
    get_crypto_profile,
    rewrap_crypto_profile
)
from app.services.email_service import (
    EmailDeliveryError,
    EmailSender,
    get_email_sender
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

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
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
        expires_in_seconds=(
            settings.registration_otp_expire_minutes * 60
        ),
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


@router.post(
    "/login",
    response_model=TokenResponse
)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(
        db,
        form_data.username,
        form_data.password
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_user_access_token(user)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer"
    )


@router.get(
    "/me",
    response_model=UserResponse
)
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
        return create_crypto_profile(
            db,
            current_user.id,
            profile_data
        )
    except CryptoProfileExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Crypto profile already exists"
        ) from exc


@router.get(
    "/crypto-profile",
    response_model=CryptoProfileResponse
)
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


@router.put(
    "/crypto-profile/rewrap",
    response_model=CryptoProfileResponse
)
def rewrap_current_user_crypto_profile(
    profile_data: CryptoProfileRewrap,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    profile = get_crypto_profile(db, current_user.id)

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Crypto profile not found"
        )

    return rewrap_crypto_profile(db, profile, profile_data)


@router.get(
    "/protected",
    response_model=ProtectedRouteResponse
)
def protected_route(
    current_user: User = Depends(get_current_user)
):
    return ProtectedRouteResponse(
        message="Authenticated request successful",
        username=current_user.username
    )
