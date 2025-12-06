
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """
    User model representing a registered user in the system.

    Attributes:
        id (UUID): Primary key, unique identifier.
        email (str): Unique email address, used for authentication.
        hashed_password (str): BCrypt hash of the user's password.
        created_at (datetime): Timestamp of when the user was created.
        api_keys (relationship): One-to-many relationship with APIKey.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("APIKey", back_populates="user")


class APIKey(Base):
    """
    API Key model for service-to-service authentication.

    Attributes:
        id (UUID): Primary key, unique identifier.
        user_id (UUID): Foreign key to the owning User.
        key_hash (str): SHA256 hash of the API key + salt.
        expires_at (datetime): When the key expires.
        revoked (bool): Whether the key has been revoked.
        created_at (datetime): Timestamp of creation.
        user (relationship): Many-to-one relationship with User.
    """
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    key_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="api_keys")
