from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
import uuid
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role
from app.core.config import settings
from app.db.database import get_db
from app.models.ai import AIConversation, AIMessage
from app.models.user import User
from app.services.audit import AuditService
from app.services.ai_service import query_ai, explain_finding, investigate_asset

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])

def _require_ai_enabled():
    if not settings.AI_ENABLED:
        raise HTTPException(status_code=503, detail="AI is disabled — set AI_ENABLED=true")

def _check_project_access(project_id: str, db: Session, user: User):
    require_project_access(project_id, db, current_user=user)

@router.get("/status")
def ai_status(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return {"enabled": settings.AI_ENABLED, "provider": settings.AI_PROVIDER, "model": settings.AI_MODEL, "mock": settings.AI_PROVIDER == "mock"}

@router.get("/usage")
def ai_usage(project_id: str = Query(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    require_project_access(project_id, db, current_user)
    from app.models.ai import AIUsage
    rows = db.query(AIUsage).filter(AIUsage.project_id == project_id).order_by(AIUsage.created_at.desc()).limit(20).all()
    return {"items": [{"id": r.id, "provider": r.provider, "model": r.model, "input_tokens": r.input_tokens, "output_tokens": r.output_tokens, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}

@router.post("/conversations", status_code=201)
def create_conversation(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    project_id = str(payload.get("project_id", "")).strip()
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id required")
    require_project_access(project_id, db, current_user)
    title = str(payload.get("title", "New Conversation")).strip()[:255] or "New Conversation"
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    conv = AIConversation(id=str(uuid.uuid4()), organization_id=proj.organization_id, project_id=project_id, user_id=current_user.id, title=title)
    db.add(conv)
    db.commit()
    try:
        AuditService.record(db, event_type="AI_CONVERSATION_CREATED", action="AI_CONVERSATION_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="ai_conversation", resource_id=conv.id, metadata={"title": title[:100]})
        db.commit()
    except Exception:
        pass
    return {"id": conv.id, "title": conv.title, "project_id": conv.project_id, "created_at": conv.created_at.isoformat() if conv.created_at else None}

@router.get("/conversations")
def list_conversations(project_id: str = Query(...), page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=50), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    require_project_access(project_id, db, current_user)
    q = db.query(AIConversation).filter(AIConversation.project_id == project_id, AIConversation.user_id == current_user.id).order_by(AIConversation.updated_at.desc())
    total = q.count()
    rows = q.offset((page-1)*page_size).limit(page_size).all()
    return {"items": [{"id": r.id, "title": r.title, "project_id": r.project_id, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows], "total": total, "page": page, "page_size": page_size}

@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    conv = db.query(AIConversation).filter(AIConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    require_project_access(conv.project_id, db, current_user)
    if conv.user_id != current_user.id and not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="Not your conversation")
    msgs = db.query(AIMessage).filter(AIMessage.conversation_id == conversation_id).order_by(AIMessage.created_at.asc()).limit(50).all()
    return {"id": conv.id, "title": conv.title, "project_id": conv.project_id, "messages": [{"id": m.id, "role": m.role, "content": m.content, "provider": m.provider, "model": m.model, "evidence_refs": m.evidence_refs, "created_at": m.created_at.isoformat() if m.created_at else None} for m in msgs]}

@router.post("/conversations/{conversation_id}/messages", status_code=201)
def post_message(conversation_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    conv = db.query(AIConversation).filter(AIConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    require_project_access(conv.project_id, db, current_user)
    if conv.user_id != current_user.id and not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="Not your conversation")
    content = str(payload.get("content", "")).strip()
    if not content or len(content) > 2000:
        raise HTTPException(status_code=400, detail="Invalid content")
    # Save user message
    user_msg = AIMessage(id=str(uuid.uuid4()), conversation_id=conversation_id, role="user", content=content, sanitized_content=content[:2000])
    db.add(user_msg)
    db.commit()
    # Query AI
    try:
        result = query_ai(db, current_user, conv.organization_id, conv.project_id, content)
        assistant_content = result["answer"]
        # Save assistant message
        assistant_msg = AIMessage(id=str(uuid.uuid4()), conversation_id=conversation_id, role="assistant", content=assistant_content, sanitized_content=assistant_content[:2000], provider=result.get("provider"), model=result.get("model"), evidence_refs=result.get("evidence"), token_usage={"input_tokens": 0, "output_tokens": len(assistant_content)//4})
        db.add(assistant_msg)
        conv.updated_at = datetime.now(timezone.utc)
        db.commit()
        try:
            AuditService.record(db, event_type="AI_RESPONSE_GENERATED", action="AI_RESPONSE_GENERATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=conv.organization_id, project_id=conv.project_id, resource_type="ai_conversation", resource_id=conv.id, metadata={"provider": result.get("provider")})
            db.commit()
        except Exception:
            pass
        return {"id": assistant_msg.id, "role": "assistant", "content": assistant_content, "confidence": result.get("confidence"), "evidence": result.get("evidence"), "recommendations": result.get("recommendations"), "limitations": result.get("limitations")}
    except Exception as e:
        try:
            AuditService.record(db, event_type="AI_RESPONSE_FAILED", action="AI_RESPONSE_FAILED", result="FAILURE", actor_user_id=current_user.id, organization_id=conv.organization_id, project_id=conv.project_id, resource_type="ai_conversation", resource_id=conv.id, metadata={"error": str(e)[:200]})
            db.commit()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e)[:500])

@router.delete("/conversations/{conversation_id}", status_code=204)
def delete_conversation(conversation_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    conv = db.query(AIConversation).filter(AIConversation.id == conversation_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    require_project_access(conv.project_id, db, current_user)
    if conv.user_id != current_user.id and not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="Not your conversation")
    db.delete(conv)
    db.commit()
    return None

@router.post("/query")
def ai_query(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    project_id = str(payload.get("project_id", "")).strip()
    prompt = str(payload.get("prompt", "")).strip()
    if not project_id or not prompt:
        raise HTTPException(status_code=400, detail="project_id and prompt required")
    require_project_access(project_id, db, current_user)
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    result = query_ai(db, current_user, proj.organization_id, project_id, prompt, filters=payload.get("filters"))
    return result

@router.post("/findings/{finding_id}/explain")
def explain_finding_route(finding_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    project_id = str(payload.get("project_id", "")).strip()
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id required")
    require_project_access(project_id, db, current_user)
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    result = explain_finding(db, current_user, proj.organization_id, project_id, finding_id)
    return result

@router.post("/assets/{asset_id}/investigate")
def investigate_asset_route(asset_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_ai_enabled()
    project_id = str(payload.get("project_id", "")).strip()
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id required")
    require_project_access(project_id, db, current_user)
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    result = investigate_asset(db, current_user, proj.organization_id, project_id, asset_id)
    return result
