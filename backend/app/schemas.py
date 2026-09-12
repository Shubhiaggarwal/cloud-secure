"""app/schemas.py - Pydantic request/response models."""

import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr


# --- Auth ---

class SignupRequest(BaseModel):
    company_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- AWS Accounts ---

class AWSAccountCreate(BaseModel):
    name: str
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    region: str = "us-east-1"
    demo_mode: bool = True


class AWSAccountOut(BaseModel):
    id: int
    name: str
    region: str
    demo_mode: bool
    role_arn: Optional[str] = None

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_bool(cls, obj):
        return cls(
            id=obj.id,
            name=obj.name,
            region=obj.region,
            demo_mode=(obj.demo_mode == "true"),
            role_arn=obj.role_arn,
        )


# --- Scans / Findings ---

class FindingOut(BaseModel):
    id: int
    service: Optional[str]
    rule_id: Optional[str]
    severity: Optional[str]
    resource: Optional[str]
    issue: Optional[str]
    impact: Optional[str]
    recommendation: Optional[str]
    mitre: Optional[str]

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    aws_account_id: int
    status: str
    security_score: Optional[int]
    error_message: Optional[str]
    started_at: datetime.datetime
    finished_at: Optional[datetime.datetime]
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True


class ScanSummaryOut(BaseModel):
    id: int
    aws_account_id: int
    status: str
    security_score: Optional[int]
    started_at: datetime.datetime
    finished_at: Optional[datetime.datetime]

    class Config:
        from_attributes = True


# --- Chat ---

class ChatRequest(BaseModel):
    scan_id: int
    message: str
    session_id: Optional[str] = None  # groups multi-turn history; defaults to str(scan_id)


class ChatResponse(BaseModel):
    reply: str
    session_id: str
