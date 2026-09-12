"""
app/models.py

Multi-tenant schema:
    Company -> Users            (who can log in)
    Company -> AWSAccount(s)    (what gets scanned; role ARN, never raw keys)
    AWSAccount -> Scan(s)       (one scan run)
    Scan -> Finding(s)          (structured findings, same shape as CLI tool)

Every table that isn't Company carries company_id (directly or via a parent
FK) so every query can be scoped to "only this tenant's data" - the most
important rule in a multi-tenant app.
"""

import datetime
import enum

from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, ForeignKey, Enum
)
from sqlalchemy.orm import relationship

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
    aws_accounts = relationship("AWSAccount", back_populates="company", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    company = relationship("Company", back_populates="users")


class AWSAccount(Base):
    """
    A single AWS account a company wants scanned. In production, `role_arn`
    is the IAM role the company created in their account, trusting our
    scanner's AWS account id, with a read-only security-audit policy
    attached. `external_id` is the standard extra secret used to prevent
    the "confused deputy" problem when assuming cross-account roles.

    `demo_mode=True` skips AssumeRole entirely and scans the seeded moto
    mock account instead - useful for onboarding/testing without needing
    real AWS access configured yet.
    """
    __tablename__ = "aws_accounts"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    name = Column(String, nullable=False)  # friendly label, e.g. "Production"
    role_arn = Column(String, nullable=True)
    external_id = Column(String, nullable=True)
    region = Column(String, default="us-east-1")
    demo_mode = Column(String, default="true")  # "true"/"false" as string for SQLite simplicity
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    company = relationship("Company", back_populates="aws_accounts")
    scans = relationship("Scan", back_populates="aws_account", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    security_score = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    aws_account = relationship("AWSAccount", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    service = Column(String)
    rule_id = Column(String)
    severity = Column(String)
    resource = Column(String)
    issue = Column(Text)
    impact = Column(Text)
    recommendation = Column(Text)
    mitre = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")
