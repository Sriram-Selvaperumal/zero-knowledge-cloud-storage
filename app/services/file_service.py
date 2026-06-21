import base64
import binascii
import json
import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import UploadFile
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.file import FileMetadata
from app.models.user import User
from app.schemas.file import EncryptionMetadataV1


logger = logging.getLogger(__name__)

UPLOAD_CHUNK_SIZE_BYTES = 1024 * 1024
MAX_ENCRYPTION_METADATA_LENGTH = 16 * 1024


class FileStorageError(Exception):
    pass


class FileTooLargeError(FileStorageError):
    pass


class EmptyFileError(FileStorageError):
    pass


class InvalidFileMetadataError(FileStorageError):
    pass


def parse_encryption_metadata(
    raw_metadata: str | None
) -> dict[str, Any]:
    if raw_metadata is None or not raw_metadata.strip():
        raise InvalidFileMetadataError(
            "encryption_metadata is required"
        )

    if len(raw_metadata) > MAX_ENCRYPTION_METADATA_LENGTH:
        raise InvalidFileMetadataError(
            "encryption_metadata is too large"
        )

    try:
        metadata = json.loads(raw_metadata)
    except json.JSONDecodeError as exc:
        raise InvalidFileMetadataError(
            "encryption_metadata must be valid JSON"
        ) from exc

    try:
        validated_metadata = EncryptionMetadataV1.model_validate(metadata)
    except ValidationError as exc:
        raise InvalidFileMetadataError(
            "encryption_metadata does not match protocol version 1"
        ) from exc

    return validated_metadata.model_dump()


def _resolve_storage_path(storage_key: str) -> Path:
    storage_root = settings.storage_root
    storage_path = (storage_root / storage_key).resolve()

    try:
        storage_path.relative_to(storage_root)
    except ValueError as exc:
        raise FileStorageError("Invalid storage path") from exc

    return storage_path


def _remove_empty_directory(directory: Path) -> None:
    if directory == settings.storage_root:
        return

    try:
        directory.rmdir()
    except OSError:
        pass


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.exception("Unable to clean up stored file content")


def save_uploaded_file(
    db: Session,
    owner: User,
    upload: UploadFile,
    encrypted_filename: str,
    encryption_metadata: dict[str, Any] | None
) -> FileMetadata:
    encrypted_filename = encrypted_filename.strip()

    if not encrypted_filename:
        raise InvalidFileMetadataError(
            "encrypted_filename cannot be empty"
        )

    if len(encrypted_filename) > 1024:
        raise InvalidFileMetadataError(
            "encrypted_filename is too long"
        )

    try:
        decoded_manifest = base64.b64decode(
            encrypted_filename,
            validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise InvalidFileMetadataError(
            "encrypted_filename must be valid standard base64"
        ) from exc

    if len(decoded_manifest) < 16:
        raise InvalidFileMetadataError(
            "encrypted_filename is too short"
        )

    content_type = upload.content_type

    if content_type and len(content_type) > 255:
        raise InvalidFileMetadataError("File content type is too long")

    storage_key = f"{owner.id}/{uuid4().hex}.enc"
    storage_path = _resolve_storage_path(storage_key)
    temporary_path = storage_path.with_suffix(".part")
    size_bytes = 0

    try:
        storage_path.parent.mkdir(parents=True, exist_ok=True)

        with temporary_path.open("xb") as destination:
            while True:
                chunk = upload.file.read(UPLOAD_CHUNK_SIZE_BYTES)

                if not chunk:
                    break

                size_bytes += len(chunk)

                if size_bytes > settings.max_upload_size_bytes:
                    raise FileTooLargeError(
                        "Uploaded file exceeds the configured size limit"
                    )

                destination.write(chunk)

        if size_bytes == 0:
            raise EmptyFileError("Uploaded file cannot be empty")

        temporary_path.replace(storage_path)
    except (EmptyFileError, FileTooLargeError):
        _safe_unlink(temporary_path)
        _remove_empty_directory(storage_path.parent)
        raise
    except OSError as exc:
        _safe_unlink(temporary_path)
        _remove_empty_directory(storage_path.parent)
        raise FileStorageError("Unable to store uploaded file") from exc

    file_metadata = FileMetadata(
        owner_id=owner.id,
        encrypted_filename=encrypted_filename,
        storage_key=storage_key,
        content_type=content_type,
        size_bytes=size_bytes,
        encryption_metadata=encryption_metadata
    )

    try:
        db.add(file_metadata)
        db.commit()
        db.refresh(file_metadata)
    except Exception:
        db.rollback()
        _safe_unlink(storage_path)
        _remove_empty_directory(storage_path.parent)
        raise

    return file_metadata


def list_owned_files(db: Session, owner_id: int) -> list[FileMetadata]:
    return (
        db.query(FileMetadata)
        .filter(FileMetadata.owner_id == owner_id)
        .order_by(FileMetadata.created_at.desc())
        .all()
    )


def get_owned_file(
    db: Session,
    file_id: int,
    owner_id: int
) -> FileMetadata | None:
    return (
        db.query(FileMetadata)
        .filter(
            FileMetadata.id == file_id,
            FileMetadata.owner_id == owner_id
        )
        .first()
    )


def get_download_path(file_metadata: FileMetadata) -> Path:
    storage_path = _resolve_storage_path(file_metadata.storage_key)

    if not storage_path.is_file():
        raise FileNotFoundError("Stored file content was not found")

    return storage_path


def delete_owned_file(db: Session, file_metadata: FileMetadata) -> None:
    storage_path = _resolve_storage_path(file_metadata.storage_key)
    staged_path: Path | None = None

    if storage_path.exists():
        staged_path = storage_path.with_name(
            f".{storage_path.name}.{uuid4().hex}.deleting"
        )

        try:
            storage_path.replace(staged_path)
        except OSError as exc:
            raise FileStorageError("Unable to remove stored file") from exc

    try:
        db.delete(file_metadata)
        db.commit()
    except Exception:
        db.rollback()

        if staged_path and staged_path.exists():
            try:
                staged_path.replace(storage_path)
            except OSError:
                logger.exception(
                    "Unable to restore file after database rollback"
                )

        raise

    if staged_path:
        try:
            staged_path.unlink(missing_ok=True)
        except OSError:
            logger.exception("Unable to clean up deleted file content")

    _remove_empty_directory(storage_path.parent)
