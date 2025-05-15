"""
Core drift analysis engine for Cloud Drift Analyzer.

This module implements the main drift detection engine that compares
infrastructure-as-code state with actual cloud resources.
"""

from typing import List, Dict, Any, Optional
import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from ..providers.base import CloudProvider
from ..state_adapters.base import StateAdapter
from ..core.models import Resource, DriftResult, DriftType
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class DriftEngine:
    """
    Core engine for detecting and analyzing drift between IaC and cloud resources.
    
    This engine compares resources defined in infrastructure code with
    actual deployed resources to identify differences.
    """
    
    def __init__(
        self,
        provider: CloudProvider,
        state_adapter: StateAdapter,
        environment: str,
        session: AsyncSession,
        max_concurrent_scans: int = 10
    ):
        """
        Initialize the drift analysis engine.
        
        Args:
            provider: Cloud provider instance
            state_adapter: Infrastructure-as-code state adapter
            environment: Environment name (e.g., 'production', 'staging')
            session: Database session for persisting results
            max_concurrent_scans: Maximum number of concurrent resource scans
        """
        self.provider = provider
        self.state_adapter = state_adapter
        self.environment = environment
        self.session = session
        self.max_concurrent_scans = max_concurrent_scans
        
    async def analyze_drift(self) -> List[DriftResult]:
        """
        Analyze drift between IaC state and cloud resources.
        
        Returns:
            List of drift results
        """
        with LogContext(engine="drift", environment=self.environment):
            logger.info("drift_analysis_started")
            
            with log_duration(logger, "get_expected_resources"):
                # Get expected resources from IaC state
                expected_resources = await self.state_adapter.get_resources()
                logger.info("expected_resources_fetched", count=len(expected_resources))
                
            with log_duration(logger, "get_actual_resources"):
                # Get actual resources from cloud provider
                # Group by resource type for efficient scanning
                resource_types = {r.resource_type for r in expected_resources}
                
                # Scan cloud resources with concurrency limits
                semaphore = asyncio.Semaphore(self.max_concurrent_scans)
                scan_tasks = []
                
                async def scan_resource_type(resource_type):
                    async with semaphore:
                        return await self.provider.get_resources(resource_type)
                
                for resource_type in resource_types:
                    scan_tasks.append(scan_resource_type(resource_type))
                
                scan_results = await asyncio.gather(*scan_tasks)
                
                # Combine results
                actual_resources = []
                for resources in scan_results:
                    actual_resources.extend(resources)
                
                logger.info("actual_resources_fetched", count=len(actual_resources))
            
            # Analyze drift
            with log_duration(logger, "analyze_resource_drift"):
                drift_results = await self._compare_resources(expected_resources, actual_resources)
                
            # Save results to database
            with log_duration(logger, "save_drift_results"):
                await self._save_results(drift_results)
                
            logger.info("drift_analysis_completed", 
                       total_resources=len(expected_resources),
                       drift_count=len(drift_results))
            
            return drift_results
    
    async def _compare_resources(
        self, expected: List[Resource], actual: List[Resource]
    ) -> List[DriftResult]:
        """
        Compare expected resources with actual resources to detect drift.
        
        Args:
            expected: List of expected resources from IaC
            actual: List of actual resources from cloud provider
            
        Returns:
            List of drift results
        """
        results: List[DriftResult] = []
        
        # Create dictionary of actual resources for easy lookup
        actual_dict = {f"{r.resource_type}:{r.resource_id}": r for r in actual}
        
        # Check for missing and modified resources
        for expected_resource in expected:
            key = f"{expected_resource.resource_type}:{expected_resource.resource_id}"
            
            if key not in actual_dict:
                # Resource exists in IaC but not in cloud (missing)
                results.append(DriftResult(
                    resource=expected_resource,
                    drift_type=DriftType.MISSING,
                    detected_at=datetime.now(),
                    details={
                        "message": f"Resource defined in IaC but not found in cloud",
                        "expected": expected_resource.model_dump()
                    }
                ))
                continue
                
            # Resource exists in both, check for differences
            actual_resource = actual_dict[key]
            differences = self.provider.compare_resources(expected_resource, actual_resource)
            
            if differences:
                results.append(DriftResult(
                    resource=expected_resource,
                    drift_type=DriftType.MODIFIED,
                    detected_at=datetime.now(),
                    details={
                        "message": f"Resource properties differ from IaC definition",
                        "differences": differences,
                        "expected": expected_resource.model_dump(),
                        "actual": actual_resource.model_dump()
                    }
                ))
        
        # Check for unexpected resources (exist in cloud but not in IaC)
        expected_keys = {f"{r.resource_type}:{r.resource_id}" for r in expected}
        
        for key, actual_resource in actual_dict.items():
            if key not in expected_keys:
                results.append(DriftResult(
                    resource=actual_resource,
                    drift_type=DriftType.UNEXPECTED,
                    detected_at=datetime.now(),
                    details={
                        "message": f"Resource exists in cloud but not defined in IaC",
                        "actual": actual_resource.model_dump()
                    }
                ))
        
        return results
    
    async def _save_results(self, results: List[DriftResult]) -> None:
        """
        Save drift results to the database.
        
        Args:
            results: List of drift results to save
        """
        # Implementation depends on your ORM models
        # This is a placeholder for the actual implementation
        if not results:
            logger.info("no_drift_results_to_save")
            return
            
        try:
            # Add results to the database session
            for result in results:
                self.session.add(result)
                
            # Commit the session
            await self.session.commit()
            logger.info("drift_results_saved", count=len(results))
            
        except Exception as e:
            # Rollback on error
            await self.session.rollback()
            logger.error("failed_to_save_drift_results", error=str(e))
            raise