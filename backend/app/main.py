"""
app/main.py

Entrypoint for the multi-tenant CSPM SaaS backend.

Run:
    uvicorn app.main:app --reload --port 8000

First run creates the SQLite tables automatically. For Postgres in
production, use Alembic migrations instead of create_all (not included
here - this is dev-friendly by default).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.database import engine, Base
from app.routers import auth, accounts, scans, chat

# Import models so their tables are registered on Base before create_all.
from app import models  # noqa: F401

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CSPM SaaS API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(accounts.router)
app.include_router(scans.router)
app.include_router(chat.router)


@app.get("/health")
def health():
    return {"status": "ok"}
