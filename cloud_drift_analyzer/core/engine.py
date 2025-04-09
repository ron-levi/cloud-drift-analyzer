from typing import List, Optional
from datetime import datetime
from .models import DriftResult, ResourceState, DriftType
from ..providers.base import BaseProvider
from ..state_adapters.base import BaseStateAdapter
from .logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class DriftEngine:
    """Main engine for analyzing infrastructure drift."""
    
    def __init__(
        self,
        provider: BaseProvider,
        state_adapter: BaseStateAdapter,
        environment: str
    ):
        self.provider = provider
        self.state_adapter = state_adapter
        self.environment = environment
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
                # Get expected state from IaC
                logger.info("fetching_expected_state")
                expected_resources = await self.state_adapter.get_resources()
                logger.info("expected_state_fetched", count=len(expected_resources))
                
                # Get actual state from cloud provider
                logger.info("fetching_actual_state")
                actual_resources = await self.provider.get_resources()
                logger.info("actual_state_fetched", count=len(actual_resources))
                
                # Check for missing and changed resources
                for expected in expected_resources:
                    with LogContext(resource_id=expected.resource_id, 
                                  resource_type=expected.resource_type):
                        actual = self._find_matching_resource(expected, actual_resources)
                        if not actual:
                            logger.warning("resource_missing")
                            results.append(self._create_missing_result(expected))
                        elif not self._states_match(expected, actual):
                            logger.warning("resource_changed")
                            results.append(self._create_changed_result(expected, actual))
                            
                # Check for extra resources
                for actual in actual_resources:
                    with LogContext(resource_id=actual.resource_id,
                                  resource_type=actual.resource_type):
                        if not self._find_matching_resource(actual, expected_resources):
                            logger.warning("unexpected_resource")
                            results.append(self._create_extra_result(actual))
                
                logger.info("drift_analysis_complete",
                           total_resources=len(expected_resources),
                           drift_count=len(results),
                           drift_types={
                               DriftType.MISSING: sum(1 for r in results if r.drift_type == DriftType.MISSING),
                               DriftType.CHANGED: sum(1 for r in results if r.drift_type == DriftType.CHANGED),
                               DriftType.EXTRA: sum(1 for r in results if r.drift_type == DriftType.EXTRA)
                           })
                            
            except Exception as e:
                logger.error("drift_analysis_failed", error=str(e))
                raise
                
        return results

    def _find_matching_resource(
        self,
        resource: ResourceState,
        resource_list: List[ResourceState]
    ) -> Optional[ResourceState]:
        """Find a matching resource in the list based on ID and type."""
        logger.debug("finding_matching_resource",
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type)
        return next(
            (r for r in resource_list 
             if r.resource_id == resource.resource_id 
             and r.resource_type == resource.resource_type),
            None
        )

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
            timestamp=datetime.now(datetime.timezone.utc)
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
            timestamp=datetime.now(datetime.timezone.utc)
        )
    
    def _create_extra_result(self, actual: ResourceState) -> DriftResult:
        """Create a DriftResult for an extra resource."""
        return DriftResult(
            drift_type=DriftType.EXTRA,
            resource=actual,
            expected_state=None,
            actual_state=actual,
            changes=None,
            timestamp=datetime.now(datetime.timezone.utc)
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