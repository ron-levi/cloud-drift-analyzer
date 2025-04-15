from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import jwt

from cloud_drift_analyzer.api.schemas.auth import UserCreate, UserResponse, Token, UserLogin, UserUpdate, PasswordChange, RefreshToken
from cloud_drift_analyzer.api.security.auth import verify_password, get_password_hash, create_access_token, create_refresh_token, verify_token
from cloud_drift_analyzer.db.database import get_session
from cloud_drift_analyzer.db.models import User, RefreshToken as RefreshTokenModel
from cloud_drift_analyzer.core.logging import get_logger, log_duration, LogContext
from cloud_drift_analyzer.api.routes.auth import get_current_user_from_token


router = APIRouter(
    prefix="/auth",
    tags=["authentication"]
)

logger = get_logger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_session)
):
    """Register a new user."""
    with LogContext(username=user_data.username):
        try:
            # Check if user exists
            stmt = select(User).where(
                (User.username == user_data.username) | 
                (User.email == user_data.email)
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username or email already registered"
                )
            
            # Create new user
            user = User(
                username=user_data.username,
                email=user_data.email,
                hashed_password=get_password_hash(user_data.password)
            )
            
            session.add(user)
            await session.commit()
            await session.refresh(user)
            
            logger.info("user_registered")
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("registration_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Registration failed"
            )

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session)
):
    """Get an access token using username and password."""
    with LogContext(username=form_data.username):
        try:
            # Find user
            stmt = select(User).where(User.username == form_data.username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            
            if not user or not verify_password(form_data.password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Update last login
            user.last_login = datetime.now(timezone.utc)
            
            # Create access token and refresh token
            access_token, expires_at = create_access_token(
                username=user.username,
                is_superuser=user.is_superuser
            )
            
            refresh_token, refresh_expires = create_refresh_token()
            
            # Store refresh token
            db_refresh_token = RefreshTokenModel(
                token=refresh_token,
                user_id=user.id,
                expires_at=refresh_expires
            )
            session.add(db_refresh_token)
            await session.commit()
            
            logger.info("login_successful")
            return Token(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_at
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("login_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Login failed"
            )

@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    refresh_token: RefreshToken,
    session: AsyncSession = Depends(get_session)
):
    """Refresh access token using a refresh token."""
    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_token.refresh_token,
        RefreshTokenModel.is_revoked == False,
        RefreshTokenModel.expires_at > datetime.now(timezone.utc)
    )
    result = await session.execute(stmt)
    db_refresh_token = result.scalar_one_or_none()
    
    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Get user
    stmt = select(User).where(User.id == db_refresh_token.user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Create new access token
    access_token, expires_at = create_access_token(
        username=user.username,
        is_superuser=user.is_superuser
    )
    
    logger.info("token_refreshed", username=user.username)
    return Token(
        access_token=access_token,
        refresh_token=refresh_token.refresh_token,
        expires_in=expires_at
    )

@router.put("/me", response_model=UserResponse)
async def update_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user_from_token),
    session: AsyncSession = Depends(get_session)
):
    """Update current user's profile."""
    with LogContext(user_id=str(current_user.id)):
        try:
            if user_update.email:
                # Check if email is already taken
                stmt = select(User).where(
                    User.email == user_update.email,
                    User.id != current_user.id
                )
                result = await session.execute(stmt)
                if result.scalar_one_or_none():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already registered"
                    )
                current_user.email = user_update.email
            
            if user_update.password:
                current_user.hashed_password = get_password_hash(user_update.password)
            
            await session.commit()
            await session.refresh(current_user)
            
            logger.info("user_updated")
            return current_user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("user_update_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )

@router.post("/me/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user_from_token),
    session: AsyncSession = Depends(get_session)
):
    """Change user's password."""
    with LogContext(user_id=str(current_user.id)):
        try:
            # Verify current password
            if not verify_password(password_change.current_password, current_user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Current password is incorrect"
                )
            
            # Update password
            current_user.hashed_password = get_password_hash(password_change.new_password)
            await session.commit()
            
            # Revoke all refresh tokens
            stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == current_user.id)
            result = await session.execute(stmt)
            refresh_tokens = result.scalars().all()
            
            for token in refresh_tokens:
                token.is_revoked = True
            
            await session.commit()
            
            logger.info("password_changed")
            return {"message": "Password changed successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("password_change_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to change password"
            )

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user_from_token),
    session: AsyncSession = Depends(get_session)
):
    """Logout user by revoking all refresh tokens."""
    with LogContext(user_id=str(current_user.id)):
        try:
            # Revoke all refresh tokens
            stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == current_user.id)
            result = await session.execute(stmt)
            refresh_tokens = result.scalars().all()
            
            for token in refresh_tokens:
                token.is_revoked = True
            
            await session.commit()
            
            logger.info("user_logged_out")
            return {"message": "Successfully logged out"}
            
        except Exception as e:
            logger.error("logout_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to logout"
            )

async def get_current_user_from_token(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session)
) -> User:
    """Dependency to get current authenticated user."""
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

@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_current_user_from_token)
):
    """Get current authenticated user details."""
    return current_user