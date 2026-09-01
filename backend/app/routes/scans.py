import json
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import get_current_user, require_roles
from app.db import get_db
from app.models import Scan, User
from app.schemas import ScanReport, ScanSummary, UserOut
from app.services.static_analyzer import analyze_file, store_uploaded_bytes

router = APIRouter(prefix="/api/scans", tags=["Static Analysis"])
ANALYST_ROLES = ("security_analyst", "administrator", "researcher")

@router.post("/analyze", response_model=ScanReport)
async def analyze_upload(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(require_roles(*ANALYST_ROLES))):
    if not file.filename: raise HTTPException(status_code=400, detail="A filename is required")
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes: raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb} MB limit")
    stored_name = store_uploaded_bytes(settings.upload_dir, file.filename, data)
    try: result = analyze_file(str(__import__('pathlib').Path(settings.upload_dir) / stored_name))
    except Exception as exc: raise HTTPException(status_code=422, detail=f"Static analysis failed: {type(exc).__name__}")
    scan = Scan(user_id=current_user.id, original_filename=file.filename[:255], stored_filename=stored_name, size_bytes=len(data), md5=result["hashes"]["md5"], sha256=result["hashes"]["sha256"], file_type=result["metadata"]["file_description"][:120], mime_type=result["metadata"]["mime_type"], risk_score=result["risk"]["score"], classification=result["risk"]["classification"], result_json=json.dumps(result))
    db.add(scan); db.commit(); db.refresh(scan)
    return _report(scan, current_user)

@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Scan).order_by(Scan.created_at.desc())
    if current_user.role not in ("administrator", "soc_member"): query = query.filter(Scan.user_id == current_user.id)
    rows = query.limit(100).all()
    return [_summary(x) for x in rows]

@router.get("/{scan_id}", response_model=ScanReport)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.role not in ("administrator", "soc_member") and scan.user_id != current_user.id: raise HTTPException(status_code=403, detail="You cannot access this scan")
    return _report(scan, scan.user)

def _summary(scan):
    return ScanSummary(id=scan.id, original_filename=scan.original_filename, size_bytes=scan.size_bytes, sha256=scan.sha256, file_type=scan.file_type, risk_score=scan.risk_score, classification=scan.classification, status=scan.status, created_at=scan.created_at, analyst_name=scan.user.full_name)

def _report(scan, analyst):
    return ScanReport(id=scan.id, original_filename=scan.original_filename, size_bytes=scan.size_bytes, sha256=scan.sha256, file_type=scan.file_type, risk_score=scan.risk_score, classification=scan.classification, status=scan.status, created_at=scan.created_at, analyst_name=analyst.full_name, md5=scan.md5, mime_type=scan.mime_type, result=json.loads(scan.result_json), analyst=UserOut.model_validate(analyst))
