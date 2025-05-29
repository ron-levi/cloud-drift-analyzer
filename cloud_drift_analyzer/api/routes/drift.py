from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List
from datetime import datetime

from cloud_drift_analyzer.core.logging import get_logger, log_duration, LogContext
from cloud_drift_analyzer.db.database import get_session
from cloud_drift_analyzer.db import crud
from cloud_drift_analyzer.core.models import DriftResult
from cloud_drift_analyzer.db.models import User
from cloud_drift_analyzer.api.dependencies import get_current_user

logger = get_logger(__name__)

router = APIRouter(
    prefix="/drift",
    tags=["drift"],
    responses={404: {"description": "Not found"}}
)

@router.get("/")
async def get_drift_analysis(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),  # Add auth
    environment: str = "production",
    since: datetime | None = None
):
    """
    Get drift analysis results
    """
    try:
        with log_duration(logger, "get_drift_analysis") as log:
            with LogContext(
                environment=environment,
                user_id=str(current_user.id)
            ):
                logger.info("fetching_drift_results", 
                          since=since.isoformat() if since else None)
                
                # Get recent drift results
                results = await crud.get_recent_drifts(
                    session=session,
                    environment=environment,
                    since=since or datetime.min
                )
                
                logger.info("drift_results_fetched", 
                          count=len(results))
                
                return {
                    "message": "Drift analysis results retrieved",
                    "environment": environment,
                    "count": len(results),
                    "results": results
                }
                
    except Exception as e:
        logger.error("drift_analysis_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/scan")
async def start_drift_scan(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),  # Add auth
    environment: str = "production"
):
    """
    Start a new drift analysis scan
    """
    try:
        with log_duration(logger, "start_drift_scan") as log:
            with LogContext(
                environment=environment,
                user_id=str(current_user.id)
            ):
                logger.info("creating_drift_scan")
                
                # Create new scan record
                scan = await crud.create_drift_scan(
                    session=session,
                    provider="aws",  # TODO: Make configurable
                    iac_type="terraform",  # TODO: Make configurable
                    environment=environment
                )
                
                logger.info("drift_scan_created", scan_id=str(scan.id))
                
                return {
                    "message": "Drift scan started",
                    "scan_id": str(scan.id),
                    "status": scan.scan_status
                }
                
    except Exception as e:
        logger.error("drift_scan_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )