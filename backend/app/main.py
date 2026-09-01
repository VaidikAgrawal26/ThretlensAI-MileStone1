from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import hash_password
from app.db import Base, SessionLocal, engine
from app.models import User
from app.routes import auth, scans, users

app=FastAPI(title="ThreatLens AI — Milestone 1 API",version="2.0.0",description="Functional static-only malware analysis platform for Milestone 1.")
origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
app.include_router(auth.router); app.include_router(scans.router); app.include_router(users.router)

@app.on_event('startup')
def startup():
    Path(settings.upload_dir).mkdir(parents=True,exist_ok=True)
    Base.metadata.create_all(bind=engine)
    ensure_compatible_schema()
    seed_demo_users()

@app.get('/health')
def health(): return {'status':'ok','service':'threatlens-backend','milestone':1}


def ensure_compatible_schema():
    """Small compatibility migration for databases created by the earlier starter ZIP."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("users")}
    with engine.begin() as conn:
        if "active" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE"))
        if "last_login_at" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMPTZ NULL"))

def seed_demo_users():
    db:Session=SessionLocal()
    defaults=[
        ('admin@threatlens.local','Admin@123','Platform Administrator','administrator'),
        ('analyst@threatlens.local','Analyst@123','Security Analyst','security_analyst'),
        ('soc@threatlens.local','Soc@123','SOC Team Member','soc_member'),
        ('researcher@threatlens.local','Researcher@123','Malware Researcher','researcher'),
    ]
    try:
        for email,password,name,role in defaults:
            user=db.query(User).filter(User.email==email).first()
            if not user: db.add(User(email=email,password_hash=hash_password(password),full_name=name,role=role,active=True))
        db.commit()
    finally: db.close()
