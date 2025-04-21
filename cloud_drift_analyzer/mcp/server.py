"""
MCP Server implementation for Cloud Drift Analyzer.
This module implements a Model Context Protocol server that makes our tools available to AI agents.
"""

import os
import logging
from typing import Dict, Any, List, Optional

from .base import MCPServer, Tool
from .tools import (
    AnalyzeDriftTool,
    OptimizeCostsTool,
    IAMReviewTool,
    S3PermissionScanTool,
    K8sComplianceTool
)

logger = logging.getLogger(__name__)


class CloudConsultantMCPServer(MCPServer):
    """MCP Server implementation that provides cloud consulting tools for AI agents."""
    
    def __init__(self):
        """Initialize the Cloud Consultant MCP Server with all available tools."""
        super().__init__(
            server_name="cloud-consultant-mcp-server",
            description="Cloud Consultant MCP Server providing tools for cloud infrastructure analysis and optimization"
        )
        
        # Register all available tools
        self._register_all_tools()
    
    def _register_all_tools(self) -> None:
        """Register all available tools with the server."""
        # Drift analysis tool
        self.register_tool(AnalyzeDriftTool())
        
        # Cost optimization tool
        self.register_tool(OptimizeCostsTool())
        
        # IAM review tool
        self.register_tool(IAMReviewTool())
        
        # S3 permission scan tool
        self.register_tool(S3PermissionScanTool())
        
        # Kubernetes compliance tool
        self.register_tool(K8sComplianceTool())


# Global server instance
_server_instance: Optional[CloudConsultantMCPServer] = None


def get_server() -> CloudConsultantMCPServer:
    """Get the global MCP server instance, creating it if it doesn't exist."""
    global _server_instance
    if _server_instance is None:
        _server_instance = CloudConsultantMCPServer()
    return _server_instance


async def execute_tool(tool_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool with the given input data."""
    server = get_server()
    return await server.execute_tool(tool_name, input_data)


def get_tool_schemas() -> Dict[str, Dict[str, Any]]:
    """Get schemas for all registered tools."""
    server = get_server()
    return server.registry.list_tools()


def get_server_info() -> Dict[str, Any]:
    """Get information about the server."""
    server = get_server()
    return server.get_server_info()
