from typing import List
import json
from pathlib import Path
from datetime import datetime
from ..core.models import DriftResult, DriftType # Ensure DriftType is imported
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class JSONReporter:
    """Generate JSON reports for drift analysis results."""
    
    def __init__(self, pretty_print: bool = True):
        """
        Initialize JSON reporter.
        
        Args:
            pretty_print: Whether to format JSON with indentation
        """
        self.pretty_print = pretty_print
        logger.info("json_reporter_initialized",
                   pretty_print=pretty_print)
    
    async def generate_report(
        self,
        drift_results: List[DriftResult],
        output_path: str,
        environment: str = "production"
    ) -> bool:
        """
        Generate a JSON report from drift results.
        
        Args:
            drift_results: List of drift detection results
            output_path: Path where the JSON report will be saved
            environment: Environment name for the report
            
        Returns:
            bool: True if report generation was successful
        """
        with LogContext(environment=environment):
            try:
                with log_duration(logger, "generate_json_report"):
                    logger.info("starting_report_generation",
                              output_path=output_path)
                    
                    # Prepare report data
                    report_data = self._prepare_report_data(drift_results, environment)
                    # logger.debug("report_data_prepared") # This log is implicitly covered by log_duration context exit
                    
                    # Write JSON to file
                    output_file = Path(output_path)
                    indent = 2 if self.pretty_print else None
                    
                    with output_file.open('w') as f:
                        json.dump(report_data, f, indent=indent, default=self._json_serializer)
                    
                    logger.info("report_generated",
                              file=str(output_file),
                              size_bytes=output_file.stat().st_size)
                    return True
                    
            except Exception as e:
                logger.error("report_generation_failed",
                           error=str(e))
                return False
    
    def _prepare_report_data(
        self,
        drift_results: List[DriftResult], # Corrected: List[DriftResult] instead of List<DriftResult]
        environment: str
    ) -> dict:
        """Prepare data structure for JSON report."""
        try:
            with log_duration(logger, "prepare_report_data"):
                # Calculate statistics assuming drift_results contains only drifted items
                total_drifts = len(drift_results)
                missing_count = sum(1 for r in drift_results if r.drift_type == DriftType.MISSING)
                changed_count = sum(1 for r in drift_results if r.drift_type == DriftType.CHANGED)
                extra_count = sum(1 for r in drift_results if r.drift_type == DriftType.EXTRA)
                
                report_data = {
                    "metadata": {
                        "environment": environment,
                        "timestamp": datetime.utcnow().isoformat(),
                        "drift_summary": {
                            "total_drifts": total_drifts,
                            "missing": missing_count,
                            "changed": changed_count,
                            "extra": extra_count
                        }
                    },
                    "results": [self._format_drift_result(result) for result in drift_results]
                }
                
                logger.debug("report_data_prepared",
                           total_drifts=total_drifts)
                
                return report_data
                
        except Exception as e:
            logger.error("report_data_preparation_failed",
                        error=str(e))
            raise # Re-raise to be caught by generate_report if necessary or calling context
    
    def _format_drift_result(self, result: DriftResult) -> dict:
        """Format a drift result for JSON output."""
        try:
            formatted = {
                "resource": {
                    "id": result.resource.resource_id,
                    "type": result.resource.resource_type,
                    "provider": result.resource.provider
                },
                "drift_type": result.drift_type.value, # .value is correct as DriftType is an Enum
                "timestamp": result.timestamp.isoformat() if result.timestamp else None
            }
            
            if result.expected_state:
                formatted["expected_state"] = result.expected_state.properties
                
            if result.actual_state:
                formatted["actual_state"] = result.actual_state.properties
                
            if result.changes:
                formatted["changes"] = result.changes
                
            return formatted
            
        except Exception as e:
            logger.error("drift_result_formatting_failed",
                        resource_id=result.resource.resource_id if result and result.resource else "unknown",
                        error=str(e))
            raise
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for handling special types."""
        try:
            if isinstance(obj, datetime):
                return obj.isoformat()
            # Add other type handlers if needed, e.g., for Pydantic models if not pre-converted
            raise TypeError(f"Type {type(obj)} not serializable")
        except Exception as e:
            logger.error("json_serialization_failed",
                        type=str(type(obj)),
                        error=str(e))
            raise