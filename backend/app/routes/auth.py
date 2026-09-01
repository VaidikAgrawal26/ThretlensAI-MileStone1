from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User
from app.schemas import LoginRequest, PasswordUpdate, ProfileUpdate, RegisterRequest, TokenResponse, UserOut
from app.core.security import create_access_token, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication & Profile"])

@router.post("/register", response_model=UserOut)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    allowed_roles = {"administrator", "security_analyst", "soc_member", "researcher"}
    role = payload.role.strip().lower()
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {sorted(allowed_roles)}")
    user = User(email=email, password_hash=hash_password(payload.password), full_name=payload.full_name.strip(), role=role, active=True)
    db.add(user); db.commit(); db.refresh(user); return user

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.strip().lower()).first()
    if not user or not verify_password(payload.password, user.password_hash) or not user.active:
        raise HTTPException(status_code=401, detail="Incorrect email/password or inactive account")
    user.last_login_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(user)
    return {"access_token": create_access_token(user), "token_type":"bearer", "user":user}

@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)): return current_user

@router.patch("/profile", response_model=UserOut)
def update_profile(payload: ProfileUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    email = str(payload.email).strip().lower()
    existing = db.query(User).filter(User.email == email, User.id != current_user.id).first()
    if existing: raise HTTPException(status_code=409, detail="Email already registered")
    current_user.email = email; current_user.full_name = payload.full_name.strip()
    db.commit(); db.refresh(current_user); return current_user

@router.post("/change-password")
def change_password(payload: PasswordUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"message":"Password changed successfully"}
