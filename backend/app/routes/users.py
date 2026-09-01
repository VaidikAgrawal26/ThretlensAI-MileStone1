from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Scan, User
from app.schemas import DashboardStats, RoleUpdate, UserCreate, UserOut, UserStatusUpdate, YaraRuleOut
from app.core.security import hash_password, require_roles
from app.services.static_analyzer import list_yara_rules

router = APIRouter(prefix="/api/users", tags=["User Management"])
ROLES = {"security_analyst", "soc_member", "administrator", "researcher"}

@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles("administrator"))):
    return db.query(User).order_by(User.id.asc()).all()

@router.post("", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_roles("administrator"))):
    email = str(payload.email).strip().lower()
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {sorted(ROLES)}")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=email, password_hash=hash_password(payload.password), full_name=payload.full_name.strip(), role=payload.role, active=True)
    db.add(user); db.commit(); db.refresh(user); return user

# Static paths must be declared before /{user_id} so FastAPI does not parse them as integers.
@router.get("/stats/summary", response_model=DashboardStats)
def stats(db: Session = Depends(get_db), _: User = Depends(require_roles("administrator"))):
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.active.is_(True)).count()
    total_scans = db.query(Scan).count()
    suspicious = db.query(Scan).filter(Scan.classification == "Suspicious").count()
    malware = db.query(Scan).filter(Scan.classification == "Potential Malware").count()
    clean = db.query(Scan).filter(Scan.classification == "No Strong Indicators").count()
    return DashboardStats(total_users=total_users, active_users=active_users, total_scans=total_scans, suspicious_scans=suspicious, potential_malware_scans=malware, clean_scans=clean)

@router.get("/yara/rules", response_model=list[YaraRuleOut])
def yara_rules(_: User = Depends(require_roles("administrator", "security_analyst", "soc_member", "researcher"))):
    return list_yara_rules()

@router.patch("/{user_id}/role", response_model=UserOut)
def update_role(user_id: int, payload: RoleUpdate, db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {sorted(ROLES)}")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and payload.role != "administrator":
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
    user.role = payload.role; db.commit(); db.refresh(user); return user

@router.patch("/{user_id}/status", response_model=UserOut)
def update_status(user_id: int, payload: UserStatusUpdate, db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and not payload.active:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    user.active = payload.active; db.commit(); db.refresh(user); return user

@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    user.active = False; db.commit()
    return {"message":"User deactivated", "user_id":user_id}
