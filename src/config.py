import os
from dotenv import load_dotenv


load_dotenv()


SECRET_KEY=os.getenv('SECRET_KEY')
HASH_ALGORITHM=os.getenv('HASH_ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES=int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))

SQLALCHEMY_DATABASE_URL=os.getenv('SQLALCHEMY_DATABASE_URL')
