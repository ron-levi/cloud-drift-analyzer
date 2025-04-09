from typing import List
from pathlib import Path
from jinja2 import Environment, PackageLoader, select_autoescape
from ..core.models import DriftResult
from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class HTMLReporter:
    """Generate HTML reports for drift analysis results."""
    
    def __init__(self, template_dir: str = "templates"):
        """Initialize HTML reporter with template directory."""
        try:
            self.env = Environment(
                loader=PackageLoader("cloud_drift_analyzer.reporters", template_dir),
                autoescape=select_autoescape(["html", "xml"])
            )
            logger.info("html_reporter_initialized",
                       template_dir=template_dir)
        except Exception as e:
            logger.error("reporter_initialization_failed",
                        error=str(e))
            raise
    
    async def generate_report(
        self,
        drift_results: List[DriftResult],
        output_path: str,
        environment: str = "production"
    ) -> bool:
        """
        Generate an HTML report from drift results.
        
        Args:
            drift_results: List of drift detection results
            output_path: Path where the HTML report will be saved
            environment: Environment name for the report
            
        Returns:
            bool: True if report generation was successful
        """
        with LogContext(environment=environment):
            try:
                with log_duration(logger, "generate_html_report"):
                    logger.info("starting_report_generation",
                              output_path=output_path)
                    
                    # Load template
                    template = self.env.get_template("drift_report.html")
                    logger.debug("template_loaded")
                    
                    # Prepare report data
                    report_data = self._prepare_report_data(drift_results)
                    logger.debug("report_data_prepared")
                    
                    # Render HTML
                    html_content = template.render(
                        environment=environment,
                        **report_data
                    )
                    logger.debug("template_rendered")
                    
                    # Write to file
                    output_file = Path(output_path)
                    output_file.write_text(html_content)
                    
                    logger.info("report_generated",
                              file=str(output_file))
                    return True
                    
            except Exception as e:
                logger.error("report_generation_failed",
                           error=str(e))
                return False
    
    def _prepare_report_data(self, drift_results: List[DriftResult]) -> dict:
        """Prepare data for the HTML report template."""
        try:
            with log_duration(logger, "prepare_report_data"):
                # Calculate statistics
                total_resources = len(drift_results)
                missing_count = sum(1 for r in drift_results if r.drift_type == "MISSING")
                changed_count = sum(1 for r in drift_results if r.drift_type == "CHANGED")
                extra_count = sum(1 for r in drift_results if r.drift_type == "EXTRA")
                
                # Group results by type
                grouped_results = {
                    "missing": [],
                    "changed": [],
                    "extra": []
                }
                
                for result in drift_results:
                    with LogContext(
                        resource_id=result.resource.resource_id,
                        drift_type=result.drift_type
                    ):
                        try:
                            group = result.drift_type.value.lower()
                            grouped_results[group].append(
                                self._format_drift_result(result)
                            )
                        except Exception as e:
                            logger.error("result_formatting_failed",
                                       error=str(e))
                
                report_data = {
                    "summary": {
                        "total": total_resources,
                        "missing": missing_count,
                        "changed": changed_count,
                        "extra": extra_count
                    },
                    "results": grouped_results,
                    "timestamp": drift_results[0].timestamp if drift_results else None
                }
                
                logger.debug("report_data_prepared",
                           total_resources=total_resources,
                           drift_counts=report_data["summary"])
                
                return report_data
                
        except Exception as e:
            logger.error("report_data_preparation_failed",
                        error=str(e))
            raise
    
    def _format_drift_result(self, result: DriftResult) -> dict:
        """Format a drift result for HTML display."""
        try:
            formatted = {
                "resource_type": result.resource.resource_type,
                "resource_id": result.resource.resource_id,
                "drift_type": result.drift_type.value,
                "timestamp": result.timestamp
            }
            
            if result.changes:
                formatted["changes"] = []
                for key, change in result.changes.items():
                    formatted["changes"].append({
                        "property": key,
                        "action": change["action"],
                        "old_value": change.get("old"),
                        "new_value": change.get("new"),
                        "value": change.get("value")
                    })
            
            return formatted
            
        except Exception as e:
            logger.error("drift_result_formatting_failed",
                        error=str(e))
            raise