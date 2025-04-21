"""
FastAPI endpoints for exposing MCP server functionality.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Body, Depends
from pydantic import BaseModel, Field

from . import server

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/mcp", tags=["mcp"])


class ToolExecutionRequest(BaseModel):
    """Request model for tool execution."""
    tool_name: str = Field(..., description="Name of the tool to execute")
    input_data: Dict[str, Any] = Field(..., description="Input data for the tool")


class ToolExecutionResponse(BaseModel):
    """Response model for tool execution."""
    result: Dict[str, Any] = Field(..., description="Result of the tool execution")


class ToolSchemaResponse(BaseModel):
    """Response model for tool schema."""
    schemas: Dict[str, Dict[str, Any]] = Field(..., description="Schemas for available tools")


class ServerInfoResponse(BaseModel):
    """Response model for server info."""
    server_name: str = Field(..., description="Name of the MCP server")
    description: str = Field(..., description="Description of the MCP server")
    tools: Dict[str, Dict[str, Any]] = Field(..., description="Available tools")


@router.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(request: ToolExecutionRequest):
    """Execute a tool with the provided input data."""
    try:
        result = await server.execute_tool(request.tool_name, request.input_data)
        return ToolExecutionResponse(result=result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error executing tool {request.tool_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error executing tool: {str(e)}")


@router.get("/schemas", response_model=ToolSchemaResponse)
def get_tool_schemas():
    """Get schemas for all available tools."""
    try:
        schemas = server.get_tool_schemas()
        return ToolSchemaResponse(schemas=schemas)
    except Exception as e:
        logger.exception(f"Error getting tool schemas: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting tool schemas: {str(e)}")


@router.get("/info", response_model=ServerInfoResponse)
def get_server_info():
    """Get information about the MCP server."""
    try:
        info = server.get_server_info()
        return ServerInfoResponse(
            server_name=info["server_name"],
            description=info["description"],
            tools=info["tools"]
        )
    except Exception as e:
        logger.exception(f"Error getting server info: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting server info: {str(e)}")
