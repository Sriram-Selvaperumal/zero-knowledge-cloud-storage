from fastapi import APIRouter, Depends, HTTPException, Response, Query, status
from sqlalchemy.orm import Session

from app.database.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.file import (
    FolderCreateRequest,
    FolderMetadataResponse,
    FolderMoveRequest
)
from app.services.file_service import FolderTargetNotFoundError
from app.services.folder_service import (
    FolderOperationError,
    create_folder,
    delete_owned_folder,
    get_owned_folder,
    list_owned_folders,
    move_owned_folder
)


router = APIRouter(
    prefix="/folders",
    tags=["Folders"]
)


def _parse_folder_query(value: str | None) -> int | None:
    if value is None or value.strip().lower() in {"", "root"}:
        return None

    try:
        folder_id = int(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="parent_id must be root or a folder id"
        ) from exc

    if folder_id < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="parent_id must be root or a folder id"
        )

    return folder_id


@router.post(
    "",
    response_model=FolderMetadataResponse,
    status_code=status.HTTP_201_CREATED
)
def create_vault_folder(
    data: FolderCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        return create_folder(
            db=db,
            owner=current_user,
            encrypted_name=data.encrypted_name,
            encryption_metadata=data.encryption_metadata.model_dump(),
            parent_id=data.parent_id
        )
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "",
    response_model=list[FolderMetadataResponse]
)
def list_vault_folders(
    parent_id: str | None = Query(default="root"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        return list_owned_folders(
            db,
            current_user.id,
            _parse_folder_query(parent_id)
        )
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch(
    "/{folder_id}/move",
    response_model=FolderMetadataResponse
)
def move_vault_folder(
    folder_id: int,
    data: FolderMoveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    folder = get_owned_folder(db, folder_id, current_user.id)

    if folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    try:
        return move_owned_folder(db, folder, data.parent_id)
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FolderOperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete(
    "/{folder_id}",
    status_code=status.HTTP_204_NO_CONTENT
)
def delete_vault_folder(
    folder_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    folder = get_owned_folder(db, folder_id, current_user.id)

    if folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    delete_owned_folder(db, folder)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
