from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
from typing import Optional, Tuple, TYPE_CHECKING
import os
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

if TYPE_CHECKING:
    from cloud_drift_analyzer.db.models import User

from cloud_drift_analyzer.core.logging import get_logger

logger = get_logger(__name__)

# Configure JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)

def create_access_token(
    username: str,
    is_superuser: bool = False,
    expires_delta: Optional[timedelta] = None
) -> Tuple[str, int]:
    """
    Create a JWT access token.
    
    Returns:
        Tuple of (token string, expiration timestamp)
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    
    claims = {
        "sub": username,
        "exp": int(expires_at.timestamp()),
        "iat": int(now.timestamp()),
        "is_superuser": is_superuser,
        "type": "access"
    }
    
    encoded_jwt = jwt.encode(claims, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, int(expires_at.timestamp())

def create_refresh_token() -> Tuple[str, datetime]:
    """
    Create a refresh token.
    
    Returns:
        Tuple of (token string, expiration datetime)
    """
    token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return token, expires_at

def verify_token(token: str, token_type: str = "access") -> dict:
    """
    Verify and decode a JWT token.
    
    Args:
        token: The token to verify
        token_type: Either "access" or "refresh"
    
    Raises:
        jwt.InvalidTokenError if token is invalid
    """
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    
    # Verify token type
    if payload.get("type") != token_type:
        raise jwt.InvalidTokenError(f"Invalid token type. Expected {token_type}")
        
    return payload


async def get_current_user_from_token(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(lambda: __import__('cloud_drift_analyzer.db.database', fromlist=['get_session']).get_session())
) -> "User":
    """Dependency to get current authenticated user."""
    from cloud_drift_analyzer.db.models import User
    
    try:
        # Verify token
        payload = verify_token(token)
        username = payload.get("sub")
        
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user details
        stmt = select(User).where(User.username == username)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        return user
        
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_from_token(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = None
) -> "User":
    """Dependency to get current authenticated user."""
    from cloud_drift_analyzer.db.database import get_session
    from cloud_drift_analyzer.db.models import User
    
    if session is None:
        # This will be handled by FastAPI dependency injection
        raise ValueError("Session dependency required")
    
    try:
        # Verify token
        payload = verify_token(token)
        username = payload.get("sub")
        
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user details
        stmt = select(User).where(User.username == username)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        return user
        
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )