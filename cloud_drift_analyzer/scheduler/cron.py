from typing import Optional
from datetime import datetime
from crontab import CronTab
import os
from pathlib import Path

from ..core.logging import get_logger, log_duration, LogContext

logger = get_logger(__name__)

class DriftScheduler:
    """Handles scheduling of periodic drift analysis jobs."""
    
    def __init__(self, user: Optional[str] = None):
        """Initialize the scheduler for a specific user or current user."""
        self.user = user
        self.cron = CronTab(user=user)
        logger.info("scheduler_initialized",
                   user=user or "current")
    
    def schedule_drift_analysis(
        self,
        schedule: str,
        environment: str,
        comment: Optional[str] = None
    ) -> bool:
        """
        Schedule a new drift analysis job.
        
        Args:
            schedule: Cron schedule expression (e.g., "0 * * * *" for hourly)
            environment: Environment to analyze
            comment: Optional comment for the cron job
            
        Returns:
            bool: True if job was scheduled successfully
        """
        try:
            with log_duration(logger, "schedule_drift_analysis"):
                with LogContext(environment=environment, schedule=schedule):
                    logger.info("creating_cron_job")
                    
                    # Get path to CLI script
                    cli_path = Path(__file__).parent.parent / "cli" / "main.py"
                    if not cli_path.exists():
                        logger.error("cli_script_not_found",
                                   path=str(cli_path))
                        return False
                    
                    # Create the cron command
                    command = (
                        f"cd {cli_path.parent.parent} && "
                        f"poetry run python -m cloud_drift_analyzer.cli.main "
                        f"analyze-drift --env {environment}"
                    )
                    
                    # Create new cron job
                    job = self.cron.new(
                        command=command,
                        comment=comment or f"Drift analysis for {environment}"
                    )
                    
                    # Set schedule
                    if job.setall(schedule):
                        self.cron.write()
                        logger.info("cron_job_created",
                                  command=command,
                                  schedule=job.slices)
                        return True
                    else:
                        logger.error("invalid_cron_schedule",
                                   schedule=schedule)
                        return False
                        
        except Exception as e:
            logger.error("job_scheduling_failed",
                        error=str(e))
            return False
    
    def list_scheduled_jobs(self) -> list[dict]:
        """List all scheduled drift analysis jobs."""
        try:
            with log_duration(logger, "list_scheduled_jobs"):
                jobs = []
                
                for job in self.cron:
                    if "analyze-drift" in job.command:
                        job_info = {
                            "command": job.command,
                            "schedule": str(job.slices),
                            "comment": job.comment,
                            "enabled": job.enabled
                        }
                        jobs.append(job_info)
                
                logger.info("jobs_listed",
                          count=len(jobs))
                return jobs
                
        except Exception as e:
            logger.error("job_listing_failed",
                        error=str(e))
            return []
    
    def remove_job(self, comment: str) -> bool:
        """Remove a scheduled job by its comment."""
        try:
            with LogContext(job_comment=comment):
                logger.info("removing_job")
                
                removed = False
                for job in self.cron:
                    if job.comment == comment:
                        self.cron.remove(job)
                        removed = True
                        
                if removed:
                    self.cron.write()
                    logger.info("job_removed")
                else:
                    logger.warning("job_not_found")
                    
                return removed
                
        except Exception as e:
            logger.error("job_removal_failed",
                        error=str(e))
            return False
    
    def disable_job(self, comment: str) -> bool:
        """Disable a scheduled job by its comment."""
        try:
            with LogContext(job_comment=comment):
                logger.info("disabling_job")
                
                disabled = False
                for job in self.cron:
                    if job.comment == comment:
                        job.enable(False)
                        disabled = True
                        
                if disabled:
                    self.cron.write()
                    logger.info("job_disabled")
                else:
                    logger.warning("job_not_found")
                    
                return disabled
                
        except Exception as e:
            logger.error("job_disable_failed",
                        error=str(e))
            return False
    
    def enable_job(self, comment: str) -> bool:
        """Enable a scheduled job by its comment."""
        try:
            with LogContext(job_comment=comment):
                logger.info("enabling_job")
                
                enabled = False
                for job in self.cron:
                    if job.comment == comment:
                        job.enable()
                        enabled = True
                        
                if enabled:
                    self.cron.write()
                    logger.info("job_enabled")
                else:
                    logger.warning("job_not_found")
                    
                return enabled
                
        except Exception as e:
            logger.error("job_enable_failed",
                        error=str(e))
            return False