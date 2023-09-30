from random import randint
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

from src.service import get_db

from .schemas import (
    User as UserSchema, 
    TokenData, 
    UserRegister,
    UserVerify
    )
from .models import User, UserVerification


SECRET_KEY = "00d8db5a8ba0926e0f476839b3e898e56e851718a6fe29a5f4c8c73a430a5e02"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def generate_code():
    return randint(100_000, 999_999)


def get_user(username: str, db: Session):
    return db.query(User).filter(User.username == username).first()


def create_user(user_schema: UserRegister, db: Session):
    password = get_password_hash(user_schema.password)
    user = User(**user_schema.model_dump(exclude=['password']), password=password)
    db.add(user)
    db.commit()
    return user


def create_verify_user(user: UserSchema, db: Session):
    user_verification = UserVerification(
        user=user, 
        code=generate_code(), 
        verified=False
        )
    db.add(user_verification)
    db.commit()
    return user_verification


def authenticate_user(username: str, password: str, db: Session):
    user = get_user(username, db)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(sub: str, expires_delta: timedelta | None = None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encoded_jwt = jwt.encode({"sub": sub, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username, db=db)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[UserSchema, Depends(get_current_user)]
):
    if current_user.is_active == False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
