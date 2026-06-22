from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.crypto_profile import UserCryptoProfile
from app.schemas.crypto import CryptoProfileBase, CryptoProfileCreate


class CryptoProfileExistsError(Exception):
    pass


def get_crypto_profile(
    db: Session,
    user_id: int
) -> UserCryptoProfile | None:
    return db.get(UserCryptoProfile, user_id)


def create_crypto_profile(
    db: Session,
    user_id: int,
    data: CryptoProfileCreate
) -> UserCryptoProfile:
    if get_crypto_profile(db, user_id) is not None:
        raise CryptoProfileExistsError

    profile = UserCryptoProfile(
        user_id=user_id,
        version=data.version,
        kdf_algorithm=data.kdf_algorithm,
        kdf_salt=data.kdf_salt,
        kdf_parameters=data.kdf_parameters.model_dump(),
        wrap_algorithm=data.wrap_algorithm,
        wrapped_vault_key=data.wrapped_vault_key,
        wrap_nonce=data.wrap_nonce,
        recovery_version=data.recovery_version,
        recovery_wrap_algorithm=data.recovery_wrap_algorithm,
        recovery_wrapped_vault_key=data.recovery_wrapped_vault_key,
        recovery_wrap_nonce=data.recovery_wrap_nonce
    )

    try:
        db.add(profile)
        db.commit()
        db.refresh(profile)
    except IntegrityError as exc:
        db.rollback()
        raise CryptoProfileExistsError from exc

    return profile


def rewrap_crypto_profile(
    db: Session,
    profile: UserCryptoProfile,
    data: CryptoProfileBase
) -> UserCryptoProfile:
    profile.version = data.version
    profile.kdf_algorithm = data.kdf_algorithm
    profile.kdf_salt = data.kdf_salt
    profile.kdf_parameters = data.kdf_parameters.model_dump()
    profile.wrap_algorithm = data.wrap_algorithm
    profile.wrapped_vault_key = data.wrapped_vault_key
    profile.wrap_nonce = data.wrap_nonce

    db.commit()
    db.refresh(profile)

    return profile
