from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from .models import DriftResult, ResourceState, DriftType
from ..providers.base import CloudProvider
from ..state_adapters.base import BaseStateAdapter
from .logging import get_logger, log_duration, LogContext
from ..db import crud

logger = get_logger(__name__)

class DriftEngine:
    """Main engine for analyzing infrastructure drift."""
    
    def __init__(
        self,
        provider: CloudProvider,
        state_adapter: BaseStateAdapter,
        environment: str,
        session: AsyncSession
    ):
        self.provider = provider
        self.state_adapter = state_adapter
        self.environment = environment
        self.session = session
        logger.info("drift_engine_initialized",
                   environment=environment,
                   provider_type=type(provider).__name__,
                   adapter_type=type(state_adapter).__name__)
        
    async def analyze_drift(self) -> List[DriftResult]:
        """
        Analyze drift between IaC state and actual cloud resources.
        Returns a list of DriftResult objects.
        """
        results: List[DriftResult] = []
        
        with log_duration(logger, "drift_analysis") as log:
            try:
                # Create initial drift scan record
                drift_scan = await crud.create_drift_scan(
                    session=self.session,
                    provider=self.provider.__class__.__name__,
                    iac_type=self.state_adapter.__class__.__name__,
                    environment=self.environment
                )
                
                # Get expected state from IaC
                logger.info("fetching_expected_state")
                expected_resources = await self.state_adapter.get_resources()
                logger.info("expected_state_fetched", count=len(expected_resources))
                
                # Get actual state from cloud provider
                logger.info("fetching_actual_state")
                actual_resources = await self.provider.get_resources()
                logger.info("actual_state_fetched", count=len(actual_resources))

                # Create maps for efficient lookup
                actual_resources_map = {
                    (r.resource_id, r.resource_type): r for r in actual_resources
                }
                expected_resources_map = {
                    (r.resource_id, r.resource_type): r for r in expected_resources
                }
                
                # Check for missing and changed resources
                for expected in expected_resources:
                    with LogContext(resource_id=expected.resource_id, 
                                  resource_type=expected.resource_type):
                        actual = actual_resources_map.get((expected.resource_id, expected.resource_type))
                        if not actual:
                            logger.warning("resource_missing")
                            drift_result = self._create_missing_result(expected)
                            results.append(drift_result)
                            await crud.create_resource_drift(
                                session=self.session,
                                scan_id=str(drift_scan.id),
                                drift_result=drift_result
                            )
                        elif not self._states_match(expected, actual):
                            logger.warning("resource_changed")
                            drift_result = self._create_changed_result(expected, actual)
                            results.append(drift_result)
                            await crud.create_resource_drift(
                                session=self.session,
                                scan_id=str(drift_scan.id),
                                drift_result=drift_result
                            )
                            
                # Check for extra resources
                for actual in actual_resources:
                    with LogContext(resource_id=actual.resource_id,
                                  resource_type=actual.resource_type):
                        if (actual.resource_id, actual.resource_type) not in expected_resources_map:
                            logger.warning("unexpected_resource")
                            drift_result = self._create_extra_result(actual)
                            results.append(drift_result)
                            await crud.create_resource_drift(
                                session=self.session,
                                scan_id=str(drift_scan.id),
                                drift_result=drift_result
                            )
                
                # Update drift scan with final results
                await crud.update_drift_scan(
                    session=self.session,
                    scan_id=str(drift_scan.id),
                    total_resources=len(expected_resources),
                    drift_detected=len(results) > 0,
                    status="completed"
                )
                
                logger.info("drift_analysis_complete",
                           total_resources=len(expected_resources),
                           drift_count=len(results),
                           drift_types={
                               DriftType.MISSING: sum(1 for r in results if r.drift_type == DriftType.MISSING),
                               DriftType.CHANGED: sum(1 for r in results if r.drift_type == DriftType.CHANGED),
                               DriftType.EXTRA: sum(1 for r in results if r.drift_type == DriftType.EXTRA)
                           })
                            
            except Exception as e:
                # Update drift scan with error status if something went wrong
                if 'drift_scan' in locals():
                    await crud.update_drift_scan(
                        session=self.session,
                        scan_id=str(drift_scan.id),
                        total_resources=0,
                        drift_detected=False,
                        status="failed",
                        error_message=str(e)
                    )
                logger.error("drift_analysis_failed", error=str(e))
                raise
                
        return results

    def _states_match(
        self,
        expected: ResourceState,
        actual: ResourceState
    ) -> bool:
        """Compare two resource states to determine if they match."""
        # Compare relevant properties while ignoring metadata
        result = expected.properties == actual.properties
        if not result:
            logger.debug("states_mismatch",
                        resource_id=expected.resource_id,
                        differences=self._compute_changes(expected, actual))
        return result

    def _create_missing_result(self, expected: ResourceState) -> DriftResult:
        """Create a DriftResult for a missing resource."""
        return DriftResult(
            drift_type=DriftType.MISSING,
            resource=expected,
            expected_state=expected,
            actual_state=None,
            changes=None,
            timestamp=datetime.now(timezone.utc)
        )
    
    def _create_changed_result(
        self,
        expected: ResourceState,
        actual: ResourceState
    ) -> DriftResult:
        """Create a DriftResult for a changed resource."""
        return DriftResult(
            drift_type=DriftType.CHANGED,
            resource=expected,
            expected_state=expected,
            actual_state=actual,
            changes=self._compute_changes(expected, actual),
            timestamp=datetime.now(timezone.utc)
        )
    
    def _create_extra_result(self, actual: ResourceState) -> DriftResult:
        """Create a DriftResult for an extra resource."""
        return DriftResult(
            drift_type=DriftType.EXTRA,
            resource=actual,
            expected_state=None,
            actual_state=actual,
            changes=None,
            timestamp=datetime.now(timezone.utc)
        )
    
    def _compute_changes(
        self,
        expected: ResourceState,
        actual: ResourceState
    ) -> dict:
        """Compute the differences between expected and actual states."""
        changes = {}
        
        # Track changes for logging
        added = []
        removed = []
        modified = []
        
        for key, expected_value in expected.properties.items():
            if key not in actual.properties:
                changes[key] = {"action": "removed", "value": expected_value}
                removed.append(key)
            elif actual.properties[key] != expected_value:
                changes[key] = {
                    "action": "modified",
                    "old": expected_value,
                    "new": actual.properties[key]
                }
                modified.append(key)
        
        for key, actual_value in actual.properties.items():
            if key not in expected.properties:
                changes[key] = {"action": "added", "value": actual_value}
                added.append(key)
        
        if changes:
            logger.debug("computed_changes",
                        resource_id=expected.resource_id,
                        added=added,
                        removed=removed,
                        modified=modified)
                
        return changes