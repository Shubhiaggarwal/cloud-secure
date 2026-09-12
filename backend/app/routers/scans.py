"""
app/routers/scans.py

Trigger an on-demand scan of one of the company's AWS accounts, and fetch
results. Scans run in a FastAPI BackgroundTask so the "Scan Now" button
returns immediately with a scan id in PENDING/RUNNING state, and the
frontend polls GET /scans/{id} until status is COMPLETE or FAILED.

(For real production scale with many concurrent scans, swap BackgroundTasks
for a proper task queue - Celery + Redis, or RQ - the run_scan_job function
below wouldn't need to change, just how it's invoked.)
"""

import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import AWSAccount, Scan, Finding, ScanStatus, User
from app.schemas import ScanOut, ScanSummaryOut
from app.security import get_current_user
from app.services.scanner_service import run_scan_for_account, ScanError
from app.engine.risk_engine import calculate_security_score

router = APIRouter(prefix="/scans", tags=["scans"])


def run_scan_job(scan_id: int):
    """Runs in the background. Opens its own DB session since it executes
    outside the request/response cycle."""
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = ScanStatus.RUNNING
        db.commit()

        account = db.query(AWSAccount).filter(AWSAccount.id == scan.aws_account_id).first()

        try:
            findings = run_scan_for_account(account)
        except ScanError as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.finished_at = datetime.datetime.utcnow()
            db.commit()
            return

        for f in findings:
            db.add(Finding(
                scan_id=scan.id,
                service=f.get("service"),
                rule_id=f.get("rule_id"),
                severity=f.get("severity"),
                resource=f.get("resource"),
                issue=f.get("issue"),
                impact=f.get("impact"),
                recommendation=f.get("recommendation"),
                mitre=f.get("mitre"),
            ))

        scan.security_score = calculate_security_score(findings)
        scan.status = ScanStatus.COMPLETE
        scan.finished_at = datetime.datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _get_owned_account(db, account_id, company_id) -> AWSAccount:
    account = (
        db.query(AWSAccount)
        .filter(AWSAccount.id == account_id, AWSAccount.company_id == company_id)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")
    return account


@router.post("/trigger/{account_id}", response_model=ScanSummaryOut)
def trigger_scan(
    account_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    account = _get_owned_account(db, account_id, current_user.company_id)

    scan = Scan(aws_account_id=account.id, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_scan_job, scan.id)
    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    scan = (
        db.query(Scan)
        .join(AWSAccount)
        .filter(Scan.id == scan_id, AWSAccount.company_id == current_user.company_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/account/{account_id}", response_model=List[ScanSummaryOut])
def list_scans_for_account(
    account_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    _get_owned_account(db, account_id, current_user.company_id)
    scans = (
        db.query(Scan)
        .filter(Scan.aws_account_id == account_id)
        .order_by(Scan.started_at.desc())
        .all()
    )
    return scans
