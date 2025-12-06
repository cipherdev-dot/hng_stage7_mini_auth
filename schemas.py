from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class SignupRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CreateKeyResponse(BaseModel):
    id: int
    key: str  # The actual API key (shown once)
    expires_at: datetime


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: datetime


class ServiceResponse(BaseModel):
    user_id: int
    auth_type: str  # "user" or "service"
    message: str
