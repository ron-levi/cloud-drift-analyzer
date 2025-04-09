from fastapi import FastAPI, Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from datetime import datetime
from typing import Callable
import uuid
import json

from .routes import drift, health
from ..core.logging import get_logger, LogContext, configure_logging

logger = get_logger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging all API requests and responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        # Create logging context for this request
        with LogContext(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None
        ):
            try:
                # Log request
                logger.info("api_request_started")
                
                # Process request
                response = await call_next(request)
                
                # Calculate duration
                duration = (datetime.now() - start_time).total_seconds() * 1000
                
                # Log response
                logger.info("api_request_completed",
                           status_code=response.status_code,
                           duration_ms=duration)
                
                # Add request ID to response headers
                response.headers["X-Request-ID"] = request_id
                return response
                
            except Exception as e:
                logger.error("api_request_failed",
                           error=str(e),
                           duration_ms=(datetime.now() - start_time).total_seconds() * 1000)
                raise

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    # Configure logging
    configure_logging(
        log_level="INFO",
        json_format=True  # Use JSON format for structured logging
    )
    
    app = FastAPI(
        title="Cloud Drift Analyzer API",
        description="API for analyzing infrastructure drift between IaC and cloud resources",
        version="1.0.0"
    )
    
    # Add logging middleware
    app.add_middleware(LoggingMiddleware)
    
    # Include routers
    app.include_router(health.router, tags=["health"])
    app.include_router(drift.router, prefix="/api/v1")
    
    logger.info("api_application_initialized")
    return app

app = create_app()