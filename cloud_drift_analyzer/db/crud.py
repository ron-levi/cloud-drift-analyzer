from typing import List, Optional
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .models import DriftScan, ResourceDrift, NotificationConfig
from ..core.models import DriftResult
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

async def create_drift_scan(
    session: AsyncSession,
    provider: str,
    iac_type: str,
    environment: str
) -> DriftScan:
    """Create a new drift scan record."""
    with LogContext(provider=provider, iac_type=iac_type, environment=environment):
        try:
            logger.info("creating_drift_scan")
            drift_scan = DriftScan(
                provider=provider,
                iac_type=iac_type,
                environment=environment
            )
            session.add(drift_scan)
            await session.commit()
            await session.refresh(drift_scan)
            logger.info("drift_scan_created", scan_id=str(drift_scan.id))
            return drift_scan
        except Exception as e:
            logger.error("drift_scan_creation_failed", error=str(e))
            raise

async def update_drift_scan(
    session: AsyncSession,
    scan_id: str,
    total_resources: int,
    drift_detected: bool,
    status: str,
    error_message: Optional[str] = None
) -> DriftScan:
    """Update an existing drift scan record."""
    with LogContext(scan_id=scan_id):
        try:
            logger.info("updating_drift_scan",
                       total_resources=total_resources,
                       drift_detected=drift_detected,
                       status=status)
            
            stmt = select(DriftScan).where(DriftScan.id == scan_id)
            result = await session.execute(stmt)
            drift_scan = result.scalar_one()
            
            drift_scan.total_resources = total_resources
            drift_scan.drift_detected = drift_detected
            drift_scan.scan_status = status
            drift_scan.error_message = error_message
            
            await session.commit()
            await session.refresh(drift_scan)
            
            logger.info("drift_scan_updated")
            return drift_scan
            
        except Exception as e:
            logger.error("drift_scan_update_failed", error=str(e))
            raise

async def create_resource_drift(
    session: AsyncSession,
    scan_id: str,
    drift_result: DriftResult
) -> ResourceDrift:
    """Create a new resource drift record."""
    with LogContext(
        scan_id=scan_id,
        resource_id=drift_result.resource.resource_id,
        resource_type=drift_result.resource.resource_type
    ):
        try:
            logger.info("creating_resource_drift",
                       drift_type=drift_result.drift_type.value)
            
            resource_drift = ResourceDrift(
                scan_id=scan_id,
                resource_id=drift_result.resource.resource_id,
                resource_type=drift_result.resource.resource_type,
                drift_type=drift_result.drift_type.value,
                expected_state=drift_result.expected_state.properties if drift_result.expected_state else {},
                actual_state=drift_result.actual_state.properties if drift_result.actual_state else {},
                changes=drift_result.changes or {},
                timestamp=drift_result.timestamp or datetime.utcnow()
            )
            
            session.add(resource_drift)
            await session.commit()
            await session.refresh(resource_drift)
            
            logger.info("resource_drift_created",
                       drift_id=str(resource_drift.id))
            return resource_drift
            
        except Exception as e:
            logger.error("resource_drift_creation_failed", error=str(e))
            raise

async def get_scan_results(
    session: AsyncSession,
    scan_id: str
) -> tuple[DriftScan, List[ResourceDrift]]:
    """Get a drift scan and all its resource drift records."""
    with LogContext(scan_id=scan_id):
        try:
            with log_duration(logger, "fetch_scan_results"):
                # Get the scan
                stmt = select(DriftScan).where(DriftScan.id == scan_id)
                result = await session.execute(stmt)
                drift_scan = result.scalar_one()
                
                # Get all resource drifts for this scan
                stmt = select(ResourceDrift).where(ResourceDrift.scan_id == scan_id)
                result = await session.execute(stmt)
                resource_drifts = result.scalars().all()
                
                logger.info("scan_results_fetched",
                           total_drifts=len(resource_drifts))
                
                return drift_scan, resource_drifts
                
        except Exception as e:
            logger.error("scan_results_fetch_failed", error=str(e))
            raise

async def create_notification_config(
    session: AsyncSession,
    channel_type: str,
    channel_config: dict
) -> NotificationConfig:
    """Create a new notification configuration."""
    with LogContext(channel_type=channel_type):
        try:
            logger.info("creating_notification_config")
            
            config = NotificationConfig(
                channel_type=channel_type,
                channel_config=channel_config
            )
            session.add(config)
            await session.commit()
            await session.refresh(config)
            
            logger.info("notification_config_created",
                       config_id=str(config.id))
            return config
            
        except Exception as e:
            logger.error("notification_config_creation_failed", error=str(e))
            raise

async def get_active_notification_configs(
    session: AsyncSession
) -> List[NotificationConfig]:
    """Get all active notification configurations."""
    try:
        with log_duration(logger, "fetch_notification_configs"):
            stmt = select(NotificationConfig).where(NotificationConfig.enabled == True)
            result = await session.execute(stmt)
            configs = result.scalars().all()
            
            logger.info("notification_configs_fetched",
                       count=len(configs))
            return configs
            
    except Exception as e:
        logger.error("notification_configs_fetch_failed", error=str(e))
        raise

async def get_recent_drifts(
    session: AsyncSession,
    environment: str,
    since: datetime
) -> List[ResourceDrift]:
    """Get all resource drifts detected since the specified time."""
    with LogContext(environment=environment):
        try:
            with log_duration(logger, "fetch_recent_drifts"):
                stmt = (
                    select(ResourceDrift)
                    .join(DriftScan)
                    .where(
                        DriftScan.environment == environment,
                        ResourceDrift.timestamp >= since
                    )
                )
                result = await session.execute(stmt)
                drifts = result.scalars().all()
                
                logger.info("recent_drifts_fetched",
                           count=len(drifts),
                           since=since.isoformat())
                return drifts
                
        except Exception as e:
            logger.error("recent_drifts_fetch_failed", error=str(e))
            raise