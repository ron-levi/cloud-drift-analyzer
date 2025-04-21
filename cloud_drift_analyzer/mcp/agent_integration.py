"""
Integration layer between Cloud Drift Analyzer MCP and AI agents.
Provides the necessary interface for LangGraph-based agents to discover and use MCP tools.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from pydantic import BaseModel, Field

from .base import Tool, ToolRegistry, MCPServer
from .server import get_server

logger = logging.getLogger(__name__)


class ToolDescription(BaseModel):
    """Tool description for AI agent consumption."""
    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    input_schema: Dict[str, Any] = Field(..., description="JSON schema for input")
    output_schema: Dict[str, Any] = Field(..., description="JSON schema for output")


class AgentToolRegistry(BaseModel):
    """Registry of tools that can be used by an AI agent."""
    tools: List[ToolDescription] = Field(..., description="Available tools")


class AgentAction(BaseModel):
    """Represents an action the agent wants to take."""
    tool: str = Field(..., description="Tool to use")
    tool_input: Dict[str, Any] = Field(..., description="Input to the tool")


class AgentActionResult(BaseModel):
    """Represents the result of an agent action."""
    tool: str = Field(..., description="Tool that was used")
    tool_output: Dict[str, Any] = Field(..., description="Output from the tool")
    error: Optional[str] = Field(None, description="Error if the action failed")


class AgentMCPInterface:
    """
    Interface between AI agents and MCP server.
    
    This class provides methods for:
    1. Getting available tools with their schemas for agent reasoning
    2. Executing tools based on agent decisions
    3. Converting results into agent-friendly format
    """
    
    def __init__(self, mcp_server: Optional[MCPServer] = None):
        """Initialize the agent interface.
        
        Args:
            mcp_server: MCP server to use, or None to use the global server
        """
        self.mcp_server = mcp_server or get_server()
        logger.info("agent_mcp_interface_initialized")
    
    def get_available_tools(self) -> AgentToolRegistry:
        """Get a list of available tools for agent consumption.
        
        Returns:
            AgentToolRegistry with all available tools
        """
        server_info = self.mcp_server.get_server_info()
        tools = []
        
        for tool_name, tool_info in server_info["tools"].items():
            tools.append(ToolDescription(
                name=tool_name,
                description=tool_info["description"],
                input_schema=tool_info["input_schema"],
                output_schema=tool_info["output_schema"]
            ))
        
        logger.info("agent_retrieved_tools", count=len(tools))
        return AgentToolRegistry(tools=tools)
    
    async def execute_agent_action(self, action: AgentAction) -> AgentActionResult:
        """Execute an action from the agent.
        
        Args:
            action: The action to execute
            
        Returns:
            Result of the action
        """
        try:
            logger.info("agent_executing_action", 
                       tool=action.tool, 
                       inputs=json.dumps(action.tool_input))
            
            result = await self.mcp_server.execute_tool(
                action.tool,
                action.tool_input
            )
            
            logger.info("agent_action_succeeded", 
                       tool=action.tool)
            
            return AgentActionResult(
                tool=action.tool,
                tool_output=result,
                error=None
            )
        except Exception as e:
            logger.error("agent_action_failed", 
                        tool=action.tool, 
                        error=str(e))
            
            return AgentActionResult(
                tool=action.tool,
                tool_output={},
                error=str(e)
            )


class LangGraphExecutor:
    """
    Executor for integrating MCP tools with LangGraph workflows.
    
    This class provides the necessary hooks to use MCP tools within a LangGraph
    execution flow, enabling AI agents to reason about and use cloud consulting tools.
    """
    
    def __init__(self):
        """Initialize the LangGraph executor."""
        self.interface = AgentMCPInterface()
        logger.info("langgraph_executor_initialized")
    
    def get_tool_nodes(self) -> Dict[str, Callable]:
        """
        Get tool nodes for LangGraph.
        
        Returns a dictionary mapping tool names to functions that execute those tools.
        These can be used directly in a LangGraph workflow.
        
        Returns:
            Dictionary of tool names to executor functions
        """
        tools = self.interface.get_available_tools().tools
        
        # Create a function for each tool
        tool_nodes = {}
        for tool in tools:
            tool_nodes[tool.name] = self._create_tool_executor(tool.name)
            
        logger.info("created_langgraph_tool_nodes", count=len(tool_nodes))
        return tool_nodes
        
    def _create_tool_executor(self, tool_name: str) -> Callable:
        """
        Create a function that executes a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Function that executes the tool
        """
        async def execute_tool(state: Dict[str, Any]) -> Dict[str, Any]:
            """Execute the tool with the current state."""
            # Extract tool input from state
            tool_input = state.get("tool_input", {})
            
            # Execute the tool
            action = AgentAction(tool=tool_name, tool_input=tool_input)
            result = await self.interface.execute_agent_action(action)
            
            # Update state with tool result
            new_state = state.copy()
            new_state["tool_output"] = result.tool_output
            
            if result.error:
                new_state["error"] = result.error
            
            return new_state
            
        return execute_tool


# Helper functions to simplify agent integration

async def get_available_tools_for_agent() -> List[Dict[str, Any]]:
    """
    Get available tools in a format suitable for agent reasoning.
    
    Returns:
        List of tool descriptions with name, description, and schemas
    """
    interface = AgentMCPInterface()
    registry = interface.get_available_tools()
    
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema
        }
        for tool in registry.tools
    ]


async def execute_tool_for_agent(
    tool_name: str,
    tool_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a tool for an agent.
    
    Args:
        tool_name: Name of the tool to execute
        tool_input: Input for the tool
        
    Returns:
        Output from the tool or error information
    """
    interface = AgentMCPInterface()
    action = AgentAction(tool=tool_name, tool_input=tool_input)
    result = await interface.execute_agent_action(action)
    
    if result.error:
        return {"error": result.error}
    
    return result.tool_output
