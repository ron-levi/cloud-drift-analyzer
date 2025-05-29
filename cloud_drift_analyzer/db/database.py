from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel import SQLModel
from ..core.logging import get_logger, log_duration, LogContext

# Import all models to register them with SQLModel
from .models import (
    DriftScan, 
    ResourceDrift, 
    NotificationConfig, 
    User, 
    RefreshToken, 
    ChatConversation, 
    ChatMessage, 
    ToolExecution
)

logger = get_logger(__name__)

# Get this from environment variable in production
DATABASE_URL = "sqlite+aiosqlite:///./drift.db"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_db() -> None:
    """Initialize the database, creating all tables."""
    logger.info("initializing_database")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        logger.info("database_initialized")
    except Exception as e:
        logger.error("database_initialization_failed", error=str(e))
        raise

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI to get database sessions."""
    async with async_session() as session:
        try:
            with LogContext(session_id=id(session)):
                logger.debug("database_session_created")
                yield session
        finally:
            logger.debug("database_session_closed")
            await session.close()

async def get_db() -> AsyncSession:
    """Get a database session for use outside of FastAPI dependencies."""
    async with async_session() as session:
        logger.debug("database_session_created", session_id=id(session))
        return session