from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime
from typing import Callable
import uuid
import json
import os

from cloud_drift_analyzer.api.routes import drift, health, auth, chat
from cloud_drift_analyzer.mcp.api import router as mcp_router
from cloud_drift_analyzer.core.logging import get_logger, LogContext, configure_logging
from cloud_drift_analyzer.db.database import init_db

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
    
    @app.on_event("startup")
    async def startup_event():
        """Initialize database on application startup."""
        await init_db()
    
    # Add logging middleware
    app.add_middleware(LoggingMiddleware)
    
    # Mount static files for frontend
    # Calculate frontend path relative to project root
    current_dir = os.path.dirname(os.path.abspath(__file__))  # api directory
    project_root = os.path.dirname(os.path.dirname(current_dir))  # project root
    frontend_path = os.path.join(project_root, "frontend")
    
    if os.path.exists(frontend_path):
        app.mount("/static", StaticFiles(directory=frontend_path), name="static")
        logger.info("frontend_mounted", path=frontend_path)
    else:
        logger.warning("frontend_directory_not_found", path=frontend_path)
    
    # Root endpoint to serve frontend
    @app.get("/")
    async def serve_frontend():
        frontend_file = os.path.join(frontend_path, "index.html")
        if os.path.exists(frontend_file):
            return FileResponse(frontend_file)
        return {"message": "Frontend not found"}
    
    # Include routers
    app.include_router(health.router, tags=["health"])
    app.include_router(auth.router, prefix="/api/v1")  # Added auth router
    app.include_router(chat.router, prefix="/api/v1")  # Added chat router
    app.include_router(mcp_router, prefix="/api/v1")  # Added MCP router
    app.include_router(drift.router, prefix="/api/v1")
    
    logger.info("api_application_initialized")
    return app

app = create_app()