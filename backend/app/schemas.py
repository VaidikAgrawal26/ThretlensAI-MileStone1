from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    full_name: str
    role: str
    active: bool
    created_at: datetime
    last_login_at: datetime | None = None

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2, max_length=120)
    role: str = 'researcher'

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class RoleUpdate(BaseModel):
    role: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2, max_length=120)
    role: str

class UserStatusUpdate(BaseModel):
    active: bool

class ProfileUpdate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr

class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)

class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    original_filename: str
    size_bytes: int
    sha256: str
    file_type: str
    risk_score: int
    classification: str
    status: str
    created_at: datetime
    analyst_name: str

class ScanReport(ScanSummary):
    md5: str
    mime_type: str | None
    result: dict
    analyst: UserOut

class DashboardStats(BaseModel):
    total_users: int
    active_users: int
    total_scans: int
    suspicious_scans: int
    potential_malware_scans: int
    clean_scans: int

class YaraRuleOut(BaseModel):
    name: str
    description: str
    severity: str
    category: str
    file: str
