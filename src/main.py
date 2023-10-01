from fastapi import FastAPI

from src.auth.views import auth_router


app = FastAPI()


app.include_router(auth_router)
