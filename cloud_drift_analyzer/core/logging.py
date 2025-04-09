import sys
import structlog
from typing import Optional, Dict, Any
from datetime import datetime
import logging.config
import json
import os
from pathlib import Path

# Global logger cache
_loggers = {}

def configure_logging(
    log_level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[str] = None
) -> None:
    """
    Configure structured logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Whether to output logs in JSON format
        log_file: Optional path to log file. If None, logs to stdout
    """
    # Configure standard logging
    logging.basicConfig(level=log_level)
    
    # Ensure log directory exists if log_file specified
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
    
    # Common processors
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if json_format:
        # JSON formatting
        processors.extend([
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(serializer=_json_serializer)
        ])
    else:
        # Console formatting
        processors.extend([
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.DefaultExceptionFormatter()
            )
        ])
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(log_level)),
        logger_factory=_create_logger_factory(log_file) if log_file else structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True
    )

def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a logger instance with the given name.
    
    Args:
        name: Name for the logger, typically __name__ of the module
        
    Returns:
        A structured logger instance
    """
    if name not in _loggers:
        _loggers[name] = structlog.get_logger(name)
    return _loggers[name]

def _create_logger_factory(log_file: str) -> structlog.stdlib.LoggerFactory:
    """Create a logger factory that writes to both file and stdout."""
    handler = logging.FileHandler(log_file)
    console_handler = logging.StreamHandler(sys.stdout)
    
    def create_stdlib_logger(name: str) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        logger.addHandler(console_handler)
        logger.setLevel(logging.DEBUG)  # Let structlog handle actual filtering
        return logger
        
    return structlog.stdlib.LoggerFactory(create_stdlib_logger)

def _json_serializer(obj: Any) -> str:
    """Custom JSON serializer that handles datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

class LogContext:
    """Context manager for adding temporary context to logs."""
    
    def __init__(self, **kwargs):
        self.context = kwargs
        self.token = None
        
    def __enter__(self):
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        structlog.contextvars.unbind_contextvars(*self.context.keys())
        
def log_duration(logger: structlog.BoundLogger, action: str) -> "DurationLogger":
    """
    Context manager for logging duration of operations.
    
    Args:
        logger: Logger instance to use
        action: Description of the action being timed
        
    Returns:
        Context manager that logs duration
    """
    return DurationLogger(logger, action)

class DurationLogger:
    """Context manager for logging operation duration."""
    
    def __init__(self, logger: structlog.BoundLogger, action: str):
        self.logger = logger
        self.action = action
        self.start_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"{self.action}.start")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = datetime.now() - self.start_time
        duration_ms = duration.total_seconds() * 1000
        
        if exc_type:
            self.logger.error(
                f"{self.action}.error",
                error=str(exc_val),
                duration_ms=duration_ms,
                exception_type=exc_type.__name__
            )
        else:
            self.logger.info(
                f"{self.action}.complete",
                duration_ms=duration_ms
            )