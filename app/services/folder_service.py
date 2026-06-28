from sqlalchemy.orm import Session

from app.models.file import FileMetadata
from app.models.folder import FolderMetadata
from app.models.user import User
from app.services.file_service import (
    FolderTargetNotFoundError,
    delete_owned_file,
    ensure_owned_folder
)


class FolderOperationError(Exception):
    pass


def create_folder(
    db: Session,
    owner: User,
    encrypted_name: str,
    encryption_metadata: dict,
    parent_id: int | None
) -> FolderMetadata:
    ensure_owned_folder(db, owner.id, parent_id)

    folder = FolderMetadata(
        owner_id=owner.id,
        parent_id=parent_id,
        encrypted_name=encrypted_name,
        encryption_metadata=encryption_metadata
    )

    try:
        db.add(folder)
        db.commit()
        db.refresh(folder)
    except Exception:
        db.rollback()
        raise

    return folder


def list_owned_folders(
    db: Session,
    owner_id: int,
    parent_id: int | None
) -> list[FolderMetadata]:
    ensure_owned_folder(db, owner_id, parent_id)

    query = db.query(FolderMetadata).filter(
        FolderMetadata.owner_id == owner_id
    )

    if parent_id is None:
        query = query.filter(FolderMetadata.parent_id.is_(None))
    else:
        query = query.filter(FolderMetadata.parent_id == parent_id)

    return query.order_by(FolderMetadata.created_at.desc()).all()


def get_owned_folder(
    db: Session,
    folder_id: int,
    owner_id: int
) -> FolderMetadata | None:
    return (
        db.query(FolderMetadata)
        .filter(
            FolderMetadata.id == folder_id,
            FolderMetadata.owner_id == owner_id
        )
        .first()
    )


def _assert_valid_parent(
    db: Session,
    folder: FolderMetadata,
    parent_id: int | None
) -> None:
    if parent_id is None:
        return

    ensure_owned_folder(db, folder.owner_id, parent_id)
    current_parent_id: int | None = parent_id

    while current_parent_id is not None:
        if current_parent_id == folder.id:
            raise FolderOperationError("A folder cannot be moved into itself")

        current_parent_id = (
            db.query(FolderMetadata.parent_id)
            .filter(
                FolderMetadata.id == current_parent_id,
                FolderMetadata.owner_id == folder.owner_id
            )
            .scalar()
        )


def move_owned_folder(
    db: Session,
    folder: FolderMetadata,
    parent_id: int | None
) -> FolderMetadata:
    _assert_valid_parent(db, folder, parent_id)
    folder.parent_id = parent_id

    try:
        db.commit()
        db.refresh(folder)
    except Exception:
        db.rollback()
        raise

    return folder


def delete_owned_folder(db: Session, folder: FolderMetadata) -> None:
    folder_id = folder.id
    owner_id = folder.owner_id

    children = (
        db.query(FolderMetadata)
        .filter(
            FolderMetadata.owner_id == owner_id,
            FolderMetadata.parent_id == folder_id
        )
        .all()
    )

    for child in children:
        delete_owned_folder(db, child)

    files = (
        db.query(FileMetadata)
        .filter(
            FileMetadata.owner_id == owner_id,
            FileMetadata.folder_id == folder_id
        )
        .all()
    )

    for file_metadata in files:
        delete_owned_file(db, file_metadata)

    folder = get_owned_folder(db, folder_id, owner_id)

    if folder is None:
        raise FolderTargetNotFoundError("Folder not found")

    try:
        db.delete(folder)
        db.commit()
    except Exception:
        db.rollback()
        raise
