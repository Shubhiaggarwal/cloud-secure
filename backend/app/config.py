"""
app/config.py

Central configuration for the multi-tenant CSPM SaaS backend.
Everything is loaded from environment variables (via .env in development).
"""

import os
from dotenv import load_dotenv

load_dotenv()

# --- Database ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cspm.db")
# Production: postgresql+psycopg2://user:password@host:5432/cspm

# --- Auth ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24h

# --- AWS scanning ---
# The AWS account ID *this backend* runs in. Companies' IAM roles must trust
# this account ID in their role's trust policy so we can sts:AssumeRole into
# their account securely (no long-lived keys ever stored).
SCANNER_AWS_ACCOUNT_ID = os.getenv("SCANNER_AWS_ACCOUNT_ID", "")
DEFAULT_SCAN_REGION = os.getenv("DEFAULT_SCAN_REGION", "us-east-1")

# --- Gemini / AI Assistant ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
GEMINI_EMBEDDING_MODEL = os.getenv("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")

# --- RAG / Chroma ---
CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "chroma_db")
CHROMA_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "security_knowledge")
KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge")

# --- CORS ---
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")


def has_gemini_key() -> bool:
    return bool(GEMINI_API_KEY)
