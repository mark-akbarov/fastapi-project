from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    phone_number: str | None = None
    first_name: str | None = None
    last_name: str | None = None


class UserBase(User):
    is_active: bool | None = None


class UserInDB(UserBase):
    id: int
    password: str


class UserRegister(UserBase):
    username: str
    email: str | None = None
    password: str
    phone_number: str | None = None
    first_name: str | None = None
    last_name: str | None = None


class UserLogin(BaseModel):
    username: str
    password: str


class UserVerify(BaseModel):
    code: str
    verified: bool
    user: User
    
    class Config:
        from_attributes = True
