from typing import List
import json
from pathlib import Path
from datetime import datetime
from ..core.models import DriftResult
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
                    logger.debug("report_data_prepared")
                    
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
        drift_results: List[DriftResult],
        environment: str
    ) -> dict:
        """Prepare data structure for JSON report."""
        try:
            with log_duration(logger, "prepare_report_data"):
                # Calculate statistics
                total_resources = len(drift_results)
                missing_count = sum(1 for r in drift_results if r.drift_type == "MISSING")
                changed_count = sum(1 for r in drift_results if r.drift_type == "CHANGED")
                extra_count = sum(1 for r in drift_results if r.drift_type == "EXTRA")
                
                report_data = {
                    "metadata": {
                        "environment": environment,
                        "timestamp": datetime.utcnow().isoformat(),
                        "total_resources": total_resources,
                        "drift_summary": {
                            "total_drifts": len(drift_results),
                            "missing": missing_count,
                            "changed": changed_count,
                            "extra": extra_count
                        }
                    },
                    "results": []
                }
                
                # Format each result
                for result in drift_results:
                    with LogContext(
                        resource_id=result.resource.resource_id,
                        drift_type=result.drift_type
                    ):
                        try:
                            report_data["results"].append(
                                self._format_drift_result(result)
                            )
                        except Exception as e:
                            logger.error("result_formatting_failed",
                                       error=str(e))
                
                logger.debug("report_data_prepared",
                           total_resources=total_resources,
                           total_drifts=len(drift_results))
                
                return report_data
                
        except Exception as e:
            logger.error("report_data_preparation_failed",
                        error=str(e))
            raise
    
    def _format_drift_result(self, result: DriftResult) -> dict:
        """Format a drift result for JSON output."""
        try:
            formatted = {
                "resource": {
                    "id": result.resource.resource_id,
                    "type": result.resource.resource_type,
                    "provider": result.resource.provider
                },
                "drift_type": result.drift_type.value,
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
                        error=str(e))
            raise
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for handling special types."""
        try:
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        except Exception as e:
            logger.error("json_serialization_failed",
                        type=str(type(obj)),
                        error=str(e))
            raise