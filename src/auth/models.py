import sqlalchemy as db
from sqlalchemy import Column
from sqlalchemy.orm import relationship

from src.models import BaseModel
from src.auth.mixins import ToDictMixin


class User(BaseModel, ToDictMixin):
    __tablename__ = 'users'

    id = Column(db.Integer, primary_key=True, index=True)
    first_name = Column(db.String, index=True)
    last_name = Column(db.String, index=True)
    username = Column(db.String, unique=True, index=True)
    phone_number = Column(db.String, unique=True, index=True)
    email = Column(db.String, unique=True, index=True)
    password = Column(db.String)
    is_active = Column(db.Boolean, default=False)


class UserVerification(BaseModel):
    __tablename__ = 'user_verification'

    id = Column(db.Integer, primary_key=True)
    user_id = Column(db.Integer, db.ForeignKey('users.id'))
    code = Column(db.String(255))
    verified = Column(db.Boolean, default=False)

    user = relationship('User', backref='verifications')
