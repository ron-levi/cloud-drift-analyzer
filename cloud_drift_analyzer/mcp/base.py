"""
Base classes for MCP (Model Context Protocol) implementations.
"""

import abc
import json
from enum import Enum
from typing import Dict, Any, List, Generic, TypeVar, Type, Optional
from pydantic import BaseModel, create_model, Field


# Severity enum for findings
class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Base class for findings
class FindingBase(BaseModel):
    """Base class for findings."""
    type: str = Field(..., description="Type of finding")
    description: str = Field(..., description="Description of the finding")
    severity: str = Field(..., description="Severity of the finding")


# Base class for recommendations
class RecommendationBase(BaseModel):
    """Base class for recommendations."""
    description: str = Field(..., description="Description of the recommendation")
    priority: int = Field(default=1, description="Priority of the recommendation (1-5)")


# Type variables for tool input and output
I = TypeVar('I', bound=BaseModel)
O = TypeVar('O', bound=BaseModel)


class Tool(Generic[I, O], abc.ABC):
    """Base class for MCP tools."""
    
    input_schema: Type[I]
    output_schema: Type[O]
    
    def __init__(self, name: str, description: str):
        """Initialize a tool.
        
        Args:
            name: Name of the tool
            description: Description of the tool
        """
        self.name = name
        self.description = description
    
    @abc.abstractmethod
    async def execute(self, input_data: I) -> O:
        """Execute the tool with the given input data.
        
        Args:
            input_data: Input data for the tool
            
        Returns:
            Output data from the tool
        """
        pass
    
    def get_input_schema(self) -> Dict[str, Any]:
        """Get the JSON schema for the input model."""
        schema = self.input_schema.model_json_schema()
        return schema
    
    def get_output_schema(self) -> Dict[str, Any]:
        """Get the JSON schema for the output model."""
        schema = self.output_schema.model_json_schema()
        return schema
    
    def validate_input(self, input_data: Dict[str, Any]) -> I:
        """Validate and convert input data to the input model."""
        return self.input_schema(**input_data)


class ToolRegistry:
    """Registry for MCP tools."""
    
    def __init__(self):
        """Initialize an empty tool registry."""
        self._tools: Dict[str, Tool] = {}
    
    def register_tool(self, tool: Tool) -> None:
        """Register a tool in the registry.
        
        Args:
            tool: Tool to register
        """
        self._tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Tool:
        """Get a tool by name.
        
        Args:
            name: Name of the tool
            
        Returns:
            The tool
            
        Raises:
            ValueError: If the tool does not exist
        """
        if name not in self._tools:
            raise ValueError(f"Tool {name} not found")
        
        return self._tools[name]
    
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """List all registered tools with their schemas.
        
        Returns:
            Dictionary of tool names to their schema information
        """
        return {
            tool.name: {
                "description": tool.description,
                "input_schema": tool.get_input_schema(),
                "output_schema": tool.get_output_schema()
            }
            for tool in self._tools.values()
        }


class MCPServer:
    """Base class for MCP servers."""
    
    def __init__(self, server_name: str, description: str):
        """Initialize an MCP server.
        
        Args:
            server_name: Name of the server
            description: Description of the server
        """
        self.server_name = server_name
        self.description = description
        self.registry = ToolRegistry()
    
    def register_tool(self, tool: Tool) -> None:
        """Register a tool with the server.
        
        Args:
            tool: Tool to register
        """
        self.registry.register_tool(tool)
    
    async def execute_tool(self, tool_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given input data.
        
        Args:
            tool_name: Name of the tool to execute
            input_data: Input data for the tool
            
        Returns:
            Output data from the tool
            
        Raises:
            ValueError: If the tool does not exist or the input data is invalid
        """
        tool = self.registry.get_tool(tool_name)
        
        try:
            validated_input = tool.validate_input(input_data)
            result = await tool.execute(validated_input)
            return result.model_dump()
        except Exception as e:
            # Re-raise any validation errors
            raise ValueError(f"Error executing tool: {str(e)}")
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get information about the server.
        
        Returns:
            Dictionary with server information
        """
        return {
            "server_name": self.server_name,
            "description": self.description,
            "tools": self.registry.list_tools()
        }
