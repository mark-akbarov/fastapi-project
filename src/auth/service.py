from random import randint
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

from src.service import get_db
from src.config import SECRET_KEY, HASH_ALGORITHM

from .schemas import (
    User as UserSchema, 
    TokenData, 
    UserRegister,
    )
from .models import User, UserVerification


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def generate_code():
    return randint(100_000, 999_999)


def get_user(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).one_or_none()
    return UserRegister(**user.to_dict())


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[HASH_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username, db=db)
    print(user)
    if user is None:
        return {"error": "user not authorized"}
    return user


async def get_current_active_user(
    current_user: Annotated[UserSchema, Depends(get_current_user)]
):
    # if current_user.is_active == False:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


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
    encoded_jwt = jwt.encode({"sub": sub, "exp": expire}, SECRET_KEY, algorithm=HASH_ALGORITHM)
    return encoded_jwt

