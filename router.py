

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.requests import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import auth
import src.db.database as database
import config
import src.db.database as database
import models
import schemas

router = APIRouter()


@router.post("/auth/signup", response_model=schemas.UserResponse)
async def signup(
    user_data: schemas.SignupRequest, db: AsyncSession = Depends(database.get_db)
):
    """
    Create a new user account.

    Args:
        user_data (SignupRequest): The signup data containing email and password.
        db (AsyncSession): The database session dependency.

    Returns:
        UserResponse: The created user details.

    Raises:
        HTTPException: 400 if the email is already registered.
    """
    # Check if user already exists
    result = await db.execute(
        select(models.User).where(models.User.email == user_data.email)
    )
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create new user
    hashed_password = await auth.AuthService.get_password_hash_async(user_data.password)
    new_user = models.User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return schemas.UserResponse(
        id=str(new_user.id), email=new_user.email, created_at=new_user.created_at
    )


@router.post("/auth/login", response_model=schemas.TokenResponse)
async def login(
    user_data: schemas.LoginRequest, db: AsyncSession = Depends(database.get_db)
):
    """
    Authenticate user and return JWT token.

    Args:
        user_data (LoginRequest): The login data containing email and password.
        db (AsyncSession): The database session dependency.

    Returns:
        TokenResponse: The JWT access token.

    Raises:
        HTTPException: 401 if email or password is incorrect.
    """
    user = await auth.authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(data={"sub": user.email})
    return schemas.TokenResponse(access_token=access_token)


@router.post("/keys/create", response_model=schemas.CreateKeyResponse)
async def create_api_key(request: Request, db: AsyncSession = Depends(database.get_db)):
    """
    Create a new API key for the authenticated user (user or service).

    Args:
        request (Request): The request object for authentication header access.
        db (AsyncSession): The database session dependency.

    Returns:
        CreateKeyResponse: The created API key details (key shown once).

    Raises:
        HTTPException: 401 if user is not authenticated.
    """
    user, _ = await auth.get_current_user_or_service(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Generate API key
    api_key = auth.generate_api_key()
    key_hash = auth.hash_api_key(api_key)
    expires_at = datetime.utcnow() + timedelta(days=365)  # 1 year expiry

    # Save to database
    new_key = models.APIKey(user_id=user.id, key_hash=key_hash, expires_at=expires_at)
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)

    return schemas.CreateKeyResponse(
        id=str(new_key.id),
        key=api_key,
        expires_at=new_key.expires_at,
    )


@router.delete("/keys/{key_id}", response_model=schemas.RevokeKeyResponse)
async def revoke_api_key(
    key_id: str, request: Request, db: AsyncSession = Depends(database.get_db)
):
    """
    Revoke an existing API key owned by the authenticated user.

    Args:
        key_id (str): The ID of the API key to revoke.
        request (Request): The request object for authentication.
        db (AsyncSession): The database session dependency.

    Returns:
        RevokeKeyResponse: Confirmation message.

    Raises:
        HTTPException: 401 if not authenticated, 404 if key not found or not owned by user.
    """
    user, _ = await auth.get_current_user_or_service(request, db)

    # Find the key owned by this user
    result = await db.execute(
        select(models.APIKey).where(
            models.APIKey.id == key_id, models.APIKey.user_id == user.id
        )
    )
    api_key = result.scalars().first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Revoke the key
    api_key.revoked = True
    await db.commit()

    return schemas.RevokeKeyResponse(message="API key revoked successfully")


# Protected routes demonstrating middleware detection
@router.get("/protected/user", response_model=schemas.UserResponse)
async def protected_user_endpoint(
    request: Request, db: AsyncSession = Depends(database.get_db)
):
    """
    Protected endpoint accessible only with user authentication (JWT).

    Args:
        request (Request): The request object for authentication header access.
        db (AsyncSession): The database session dependency.

    Returns:
        UserResponse: The user details.

    Raises:
        HTTPException: 401 if not authenticated, 403 if not user auth type.
    """
    user, auth_type = await auth.get_current_user_or_service(request, db)
    if auth_type != "user":
        raise HTTPException(status_code=403, detail="User authentication required")
    return schemas.UserResponse(
        id=str(user.id), email=user.email, created_at=user.created_at
    )


@router.get("/protected/service", response_model=schemas.ServiceResponse)
async def protected_service_endpoint(
    request: Request, db: AsyncSession = Depends(database.get_db)
):
    """
    Protected endpoint accessible with user or service authentication.

    Args:
        request (Request): The request object for authentication header access.
        db (AsyncSession): The database session dependency.

    Returns:
        ServiceResponse: Response indicating the auth type and user ID.

    Raises:
        HTTPException: 401 if not authenticated.
    """
    user, auth_type = await auth.get_current_user_or_service(request, db)
    return schemas.ServiceResponse(
        user_id=str(user.id),
        auth_type=auth_type,
        message=f"Accessed by {auth_type} authentication",
    )
