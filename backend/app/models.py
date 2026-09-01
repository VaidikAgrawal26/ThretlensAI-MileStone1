from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.db import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    role = Column(String(40), nullable=False, default="researcher", index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    md5 = Column(String(32), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    file_type = Column(String(120), nullable=False)
    mime_type = Column(String(120), nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    classification = Column(String(80), nullable=False)
    status = Column(String(40), nullable=False, default="completed")
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    user = relationship("User", back_populates="scans")
