from datetime import datetime
from typing import Optional, Dict, Any
from sqlmodel import SQLModel, Field
from sqlalchemy import JSON, Column
from uuid import UUID, uuid4

class DriftScan(SQLModel, table=True):
    """Model representing a drift scan record in the database."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provider: str
    iac_type: str  # e.g., "terraform", "pulumi"
    environment: str
    total_resources: int = 0
    drift_detected: bool = False
    scan_status: str = "pending"
    error_message: Optional[str] = None

class ResourceDrift(SQLModel, table=True):
    """Model representing individual resource drift records."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(foreign_key="driftscan.id")
    resource_id: str
    resource_type: str
    drift_type: str  # "MISSING", "CHANGED", "EXTRA"
    expected_state: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    actual_state: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    changes: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class NotificationConfig(SQLModel, table=True):
    """Model for storing notification configurations."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    channel_type: str  # e.g., "slack", "email"
    channel_config: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class User(SQLModel, table=True):
    """Model representing a user in the system."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

class RefreshToken(SQLModel, table=True):
    """Model for storing refresh tokens."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    token: str = Field(unique=True, index=True)
    user_id: UUID = Field(foreign_key="user.id")
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_revoked: bool = False