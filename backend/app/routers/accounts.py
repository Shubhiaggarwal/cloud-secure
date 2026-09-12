"""
app/routers/accounts.py

Manage the AWS accounts a company wants scanned. Every query/mutation is
scoped to `current_user.company_id` - a company can only ever see or touch
its own AWS accounts, never another tenant's.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AWSAccount, User
from app.schemas import AWSAccountCreate, AWSAccountOut
from app.security import get_current_user

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.post("", response_model=AWSAccountOut)
def create_account(
    payload: AWSAccountCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    account = AWSAccount(
        company_id=current_user.company_id,
        name=payload.name,
        role_arn=payload.role_arn,
        external_id=payload.external_id,
        region=payload.region,
        demo_mode="true" if payload.demo_mode else "false",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return AWSAccountOut.from_orm_bool(account)


@router.get("", response_model=List[AWSAccountOut])
def list_accounts(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    accounts = db.query(AWSAccount).filter(AWSAccount.company_id == current_user.company_id).all()
    return [AWSAccountOut.from_orm_bool(a) for a in accounts]


@router.delete("/{account_id}")
def delete_account(
    account_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    account = (
        db.query(AWSAccount)
        .filter(AWSAccount.id == account_id, AWSAccount.company_id == current_user.company_id)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")
    db.delete(account)
    db.commit()
    return {"ok": True}
