from typing import Annotated
from datetime import timedelta

from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from src.config import ACCESS_TOKEN_EXPIRE_MINUTES

from .models import User, UserVerification
from .schemas import Token, UserRegister, User as UserSchema
from .service import (
    get_db,
    authenticate_user,
    create_access_token,
    create_verify_user,
    create_user,
    get_current_active_user
    )


auth_router = APIRouter(
    prefix='/auth',
    tags=['auth']
)


@auth_router.post("/signup")
async def signup_user(user_schema: UserRegister, db: Session = Depends(get_db)):
    user_exists = db.query(User).filter(User.email == user_schema.email).first()
    if user_exists:
        raise HTTPException(
            detail="User already exists.", 
            status_code=status.HTTP_400_BAD_REQUEST
            )
    user = create_user(user_schema, db)
    create_verify_user(user, db)
    return {"detail": "user was created successfully. proceed with verification."}


@auth_router.post("/verify")
def verify_user_for_token(email: str, code:str, db: Session = Depends(get_db)):
    verification_exists = db.query(UserVerification) \
        .join(User) \
        .filter(User.email == email, UserVerification.code == code) \
        .first()
    if verification_exists:
        token = create_access_token(email)
        return {"token": token}
    else:
        return {"detail": "invalid code"}


@auth_router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db) 
):  
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.username, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@auth_router.get("/users/me/", response_model=UserSchema)
async def read_users_me(current_user: Annotated[UserSchema, Depends(get_current_active_user)]):
    return current_user
