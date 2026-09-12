"""
app/routers/chat.py

The always-available chatbot endpoint. Every message is scoped to a
scan_id, and that scan must belong to the caller's company - so the AI
can only ever see and discuss findings the requesting company owns.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan, AWSAccount, Finding, User
from app.schemas import ChatRequest, ChatResponse
from app.security import get_current_user
from app.services.chat_service import get_reply

router = APIRouter(prefix="/chat", tags=["chat"])


@router.post("", response_model=ChatResponse)
def chat(
    payload: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = (
        db.query(Scan)
        .join(AWSAccount)
        .filter(Scan.id == payload.scan_id, AWSAccount.company_id == current_user.company_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "service": f.service, "rule_id": f.rule_id, "severity": f.severity,
            "resource": f.resource, "issue": f.issue, "impact": f.impact,
            "recommendation": f.recommendation, "mitre": f.mitre,
        }
        for f in db.query(Finding).filter(Finding.scan_id == scan.id).all()
    ]

    session_id = payload.session_id or f"scan-{scan.id}-{uuid.uuid4().hex[:8]}"
    reply = get_reply(session_id=session_id, user_message=payload.message, findings=findings)
    return ChatResponse(reply=reply, session_id=session_id)
