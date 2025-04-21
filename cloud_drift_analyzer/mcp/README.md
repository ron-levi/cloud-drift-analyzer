# Model Context Protocol (MCP) Implementation

This module implements the Model Context Protocol (MCP) for Cloud Drift Analyzer, enabling AI agents to interact with cloud infrastructure through a standardized interface.

## Overview

The MCP implementation consists of several components:

1. **Tool Definition**: Base classes for defining tools with input/output schemas.
2. **Tool Registry**: A registry that allows tools to be discovered and queried.
3. **MCP Server**: A server that manages tools and handles tool execution.
4. **Agent Integration**: Components for integrating with AI agents and LangGraph workflows.

## Components

### Base Classes (`base.py`)

- `Tool`: Abstract base class for MCP tools
- `ToolRegistry`: Registry for MCP tools
- `MCPServer`: Base class for MCP servers
- Support classes for findings and recommendations

### Tool Implementations (`tools.py`)

The following tools are implemented:

1. `AnalyzeDriftTool`: Detects infrastructure drift between IaC and cloud resources
2. `OptimizeCostsTool`: Analyzes cloud costs and provides optimization recommendations
3. `IAMReviewTool`: Reviews IAM permissions and identifies security issues
4. `S3PermissionScanTool`: Scans S3 bucket permissions for security issues
5. `K8sComplianceTool`: Checks Kubernetes configurations against compliance standards

### Server Implementation (`server.py`)

- `CloudConsultantMCPServer`: Implements an MCP server for cloud consulting tools
- Global functions for accessing the server and executing tools

### API Layer (`api.py`)

- FastAPI endpoints for exposing MCP functionality via HTTP

### Agent Integration (`agent_integration.py`)

- `AgentMCPInterface`: Interface between AI agents and MCP server
- `LangGraphExecutor`: Executor for integrating MCP tools with LangGraph workflows
- Helper functions for agent integration

## Usage

### Direct Tool Execution

```python
from cloud_drift_analyzer.mcp import execute_tool

# Execute a tool
result = await execute_tool("analyze_drift", {
    "resource_type": "aws_s3_bucket",
    "resource_id": "my-bucket",
    "state_backend": "terraform",
    "state_location": "./terraform.tfstate"
})
```

### Agent Integration

```python
from cloud_drift_analyzer.mcp import (
    get_available_tools_for_agent,
    execute_tool_for_agent
)

# Get available tools for agent reasoning
tools = await get_available_tools_for_agent()

# Execute a tool based on agent decision
result = await execute_tool_for_agent("analyze_drift", {
    "resource_type": "aws_s3_bucket",
    "resource_id": "my-bucket",
    "state_backend": "terraform",
    "state_location": "./terraform.tfstate"
})
```

### LangGraph Integration

```python
from cloud_drift_analyzer.mcp import LangGraphExecutor

# Create LangGraph executor
executor = LangGraphExecutor()

# Get tool nodes for LangGraph
tool_nodes = executor.get_tool_nodes()

# Use in LangGraph workflow
tool_executor = ToolExecutor(tool_nodes)
workflow = StateGraph(AgentState)
workflow.add_node("tool", tool_executor)
# ...
```

## Adding New Tools

To add a new tool:

1. Define input and output schemas as Pydantic models
2. Implement the tool by extending the `Tool` class
3. Register the tool with the MCP server in `server.py`

Example:

```python
class NewToolInput(BaseModel):
    param1: str = Field(..., description="Parameter 1")
    param2: int = Field(..., description="Parameter 2")

class NewToolOutput(BaseModel):
    result: str = Field(..., description="Result")

class NewTool(Tool[NewToolInput, NewToolOutput]):
    input_schema = NewToolInput
    output_schema = NewToolOutput
    
    def __init__(self):
        super().__init__(
            name="new_tool",
            description="Description of the new tool"
        )
    
    async def execute(self, input_data: NewToolInput) -> NewToolOutput:
        # Implement tool logic
        return NewToolOutput(result="Done")
