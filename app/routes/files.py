from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.file import FileCopyRequest, FileMetadataResponse, FileMoveRequest
from app.services.file_service import (
    ALL_FOLDERS,
    EmptyFileError,
    FileStorageError,
    FileTooLargeError,
    FolderTargetNotFoundError,
    InvalidFileMetadataError,
    copy_owned_file,
    delete_owned_file,
    ensure_owned_folder,
    get_download_path,
    get_owned_file,
    list_owned_files,
    move_owned_file,
    parse_encryption_metadata,
    save_uploaded_file
)


router = APIRouter(
    prefix="/files",
    tags=["Files"]
)


def _parse_folder_id(value: str | None) -> int | None:
    if value is None or value.strip().lower() in {"", "root"}:
        return None

    try:
        folder_id = int(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="folder_id must be root or a folder id"
        ) from exc

    if folder_id < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="folder_id must be root or a folder id"
        )

    return folder_id


def _parse_folder_filter(value: str | None) -> int | None | object:
    if value is None:
        return ALL_FOLDERS

    return _parse_folder_id(value)


@router.post(
    "/upload",
    response_model=FileMetadataResponse,
    status_code=status.HTTP_201_CREATED
)
def upload_encrypted_file(
    file: UploadFile = File(...),
    encrypted_filename: str = Form(..., min_length=1, max_length=1024),
    encryption_metadata: str | None = Form(default=None),
    folder_id: str | None = Form(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        parsed_metadata = parse_encryption_metadata(encryption_metadata)

        return save_uploaded_file(
            db=db,
            owner=current_user,
            upload=file,
            encrypted_filename=encrypted_filename,
            encryption_metadata=parsed_metadata,
            folder_id=_parse_folder_id(folder_id)
        )
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidFileMetadataError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc)
        ) from exc
    except EmptyFileError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        ) from exc
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"{exc}. Maximum size is "
                f"{settings.max_upload_size_bytes} bytes"
            )
        ) from exc
    except FileStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc)
        ) from exc


@router.get(
    "",
    response_model=list[FileMetadataResponse]
)
def list_files(
    folder_id: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    parsed_folder_id = _parse_folder_filter(folder_id)

    try:
        if parsed_folder_id is not ALL_FOLDERS:
            ensure_owned_folder(db, current_user.id, parsed_folder_id)

        return list_owned_files(db, current_user.id, parsed_folder_id)
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{file_id}/download")
def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_metadata = get_owned_file(db, file_id, current_user.id)

    if file_metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    try:
        storage_path = get_download_path(file_metadata)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File content not found"
        ) from exc
    except FileStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc)
        ) from exc

    return FileResponse(
        path=storage_path,
        media_type=file_metadata.content_type or "application/octet-stream",
        filename=f"encrypted-file-{file_metadata.id}.enc"
    )


@router.patch(
    "/{file_id}/move",
    response_model=FileMetadataResponse
)
def move_file(
    file_id: int,
    data: FileMoveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_metadata = get_owned_file(db, file_id, current_user.id)

    if file_metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    try:
        return move_owned_file(
            db,
            file_metadata,
            current_user.id,
            data.folder_id
        )
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{file_id}/copy",
    response_model=FileMetadataResponse,
    status_code=status.HTTP_201_CREATED
)
def copy_file(
    file_id: int,
    data: FileCopyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_metadata = get_owned_file(db, file_id, current_user.id)

    if file_metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    try:
        return copy_owned_file(
            db,
            file_metadata,
            current_user,
            data.folder_id
        )
    except FolderTargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File content not found"
        ) from exc
    except FileStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc)
        ) from exc


@router.delete(
    "/{file_id}",
    status_code=status.HTTP_204_NO_CONTENT
)
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_metadata = get_owned_file(db, file_id, current_user.id)

    if file_metadata is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    try:
        delete_owned_file(db, file_metadata)
    except FileStorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc)
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)
