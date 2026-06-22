from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.share import (
    FileShareResponse,
    ShareAccessInfo,
    ShareCreateRequest,
    ShareKeyEnvelope,
    SharedFileEncryptionMetadata,
    ShareUnlockRequest,
    ShareUnlockResponse
)
from app.services.file_service import (
    FileStorageError,
    get_download_path,
    get_owned_file
)
from app.services.share_service import (
    ShareConflictError,
    ShareError,
    ShareInactiveError,
    ShareNotFoundError,
    SharePasswordError,
    ShareRateLimitError,
    authorize_share_download,
    create_file_share,
    get_share_by_token,
    list_file_shares,
    revoke_file_share,
    verify_share_password
)


router = APIRouter(tags=["Shares"])


def _owned_file_or_404(db: Session, file_id: int, user_id: int):
    file_metadata = get_owned_file(db, file_id, user_id)

    if file_metadata is None:
        raise HTTPException(status_code=404, detail="File not found")

    return file_metadata


def _public_share_or_error(db: Session, token: str):
    try:
        return get_share_by_token(db, token)
    except ShareNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ShareInactiveError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc


@router.post(
    "/files/{file_id}/shares",
    response_model=FileShareResponse,
    status_code=status.HTTP_201_CREATED
)
def create_share(
    file_id: int,
    data: ShareCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_metadata = _owned_file_or_404(db, file_id, current_user.id)

    try:
        return create_file_share(db, file_metadata, data)
    except ShareConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ShareError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/files/{file_id}/shares",
    response_model=list[FileShareResponse]
)
def list_shares(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    _owned_file_or_404(db, file_id, current_user.id)
    return list_file_shares(db, file_id)


@router.delete(
    "/files/{file_id}/shares/{share_id}",
    status_code=status.HTTP_204_NO_CONTENT
)
def revoke_share(
    file_id: int,
    share_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    _owned_file_or_404(db, file_id, current_user.id)

    try:
        revoke_file_share(db, file_id, share_id)
    except ShareNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/shares/{token}", response_model=ShareAccessInfo)
def inspect_share(token: str, db: Session = Depends(get_db)):
    share = _public_share_or_error(db, token)
    return ShareAccessInfo.model_validate(share, from_attributes=True)


@router.post("/shares/{token}/unlock", response_model=ShareUnlockResponse)
def unlock_share(
    token: str,
    data: ShareUnlockRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    share = _public_share_or_error(db, token)
    client_host = request.client.host if request.client else "unknown"

    try:
        download_token = verify_share_password(
            db,
            share,
            data.password_verifier,
            client_host
        )
    except ShareRateLimitError as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)}
        ) from exc
    except SharePasswordError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="Share throttling is not configured"
        ) from exc

    metadata = share.file.encryption_metadata

    if not metadata:
        raise HTTPException(status_code=409, detail="Shared file is unavailable")

    return ShareUnlockResponse(
        share_id=share.id,
        encrypted_filename=share.file.encrypted_filename,
        size_bytes=share.file.size_bytes,
        encryption_metadata=SharedFileEncryptionMetadata(
            version=metadata["version"],
            cipher=metadata["cipher"],
            file_id=metadata["file_id"],
            chunk_size=metadata["chunk_size"],
            plaintext_size=metadata["plaintext_size"],
            stream_header=metadata["stream_header"],
            manifest_nonce=metadata["manifest_nonce"]
        ),
        share_envelope=ShareKeyEnvelope(
            version=share.version,
            wrap_algorithm=share.wrap_algorithm,
            wrapped_file_key=share.wrapped_file_key,
            wrap_nonce=share.wrap_nonce
        ),
        download_token=download_token,
        download_expires_in_seconds=(
            settings.share_download_grant_expire_minutes * 60
        ),
        expires_at=share.expires_at
    )


@router.get("/shares/{token}/download")
def download_shared_file(
    token: str,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Share "):
        raise HTTPException(status_code=401, detail="Share authorization is missing")

    try:
        share = authorize_share_download(
            db,
            token,
            authorization.removeprefix("Share ").strip()
        )
        storage_path = get_download_path(share.file)
    except ShareNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ShareInactiveError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except SharePasswordError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="File content not found") from exc
    except FileStorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return FileResponse(
        path=storage_path,
        media_type="application/octet-stream",
        filename="encrypted-shared-file.enc"
    )
