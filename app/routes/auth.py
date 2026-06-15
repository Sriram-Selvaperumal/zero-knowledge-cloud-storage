from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.user import (
    ProtectedRouteResponse,
    TokenResponse,
    UserRegister,
    UserResponse
)
from app.services.auth_service import (
    authenticate_user,
    create_user,
    create_user_access_token,
    get_user_by_email,
    get_user_by_username
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post(
    "/register",
    response_model=UserResponse
)
def register_user(
    user: UserRegister,
    db: Session = Depends(get_db)
):

    if get_user_by_username(db, user.username):
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    if get_user_by_email(db, str(user.email)):
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    return create_user(db, user)


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
