"""
Authentication utilities for JWT and API key handling.
"""

import datetime
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from sqlalchemy import select

from config import settings as config
import models
import schemas

# Argon2id hasher - current best practice (2025)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

logger = logging.getLogger(__name__)

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)


class AuthService:
    """Handles authentication, password hashing, and token creation."""

    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        Hash a password using Argon2id.
        """
        return ph.hash(password)

    @staticmethod
    async def get_password_hash_async(password: str) -> str:
        """
        Async version of get_password_hash - safe to call from async contexts.
        """
        def _hash_sync():
            return ph.hash(password)

        return await anyio.to_thread.run_sync(_hash_sync)

    @staticmethod
    async def verify_password(plain_password: str, stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        Uses Argon2id with backwards compatibility for any old hashes.
        """
        try:
            # Main Argon2id hashes
            def _verify_sync():
                ph.verify(stored_hash, plain_password)

            await anyio.to_thread.run_sync(_verify_sync)
            return True

        except (VerifyMismatchError, ValueError):
            return False

        except Exception as e:
            logger.error(f"Unexpected error during password verification: {e}")
            return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_api_key() -> str:
    """Generate a new random API key."""
    return secrets.token_urlsafe(32)  # 32 bytes = 43 char string


def hash_api_key(key: str) -> str:
    """Hash an API key with salt."""
    salted_key = key + config.API_KEY_SALT
    return hashlib.sha256(salted_key.encode()).hexdigest()


async def get_user_by_api_key(db: Session, key: str) -> Optional[models.User]:
    """Verify API key and return associated user if valid."""
    key_hash = hash_api_key(key)
    result = await db.execute(
        select(models.APIKey).where(
            models.APIKey.key_hash == key_hash,
            models.APIKey.revoked == False,
            models.APIKey.expires_at > datetime.utcnow()
        )
    )
    api_key = result.scalars().first()
    if api_key:
        return api_key.user
    return None


async def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    """Authenticate user with email and password."""
    result = await db.execute(
        select(models.User).where(models.User.email == email)
    )
    user = result.scalars().first()
    if not user:
        return None
    if not await AuthService.verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user_or_service(
    request: Request,
    db: Session
) -> Tuple[models.User, str]:
    """
    Unified authentication dependency function acting as middleware.

    Detects authentication type by checking headers in order:
    1. Authorization header with Bearer token (for user authentication)
    2. X-API-Key header (for service authentication)

    Args:
        request (Request): The FastAPI request object to access headers.
        db (Session): The database session for user lookups.

    Returns:
        Tuple[models.User, str]: A tuple containing the authenticated user and auth type ("user" or "service").

    Raises:
        HTTPException: 401 if no valid authentication is found or token/key is invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check Bearer token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer "
        payload = verify_token(token)
        if payload:
            email: str = payload.get("sub")
            if email:
                result = await db.execute(
                    select(models.User).where(models.User.email == email)
                )
                user = result.scalars().first()
                if user:
                    return user, "user"

    # Check X-API-Key header
    api_key = request.headers.get("x-api-key")
    if api_key:
        user = await get_user_by_api_key(db, api_key)
        if user:
            return user, "service"

    raise credentials_exception
