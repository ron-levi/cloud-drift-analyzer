"""
Example of integrating Cloud Drift Analyzer's MCP with LangGraph for AI agent usage.

This script demonstrates how to:
1. Register MCP tools with a LangGraph workflow
2. Have an agent reason about and select tools
3. Execute the selected tools through the MCP layer
"""

import asyncio
import json
from typing import Dict, Any, List, Tuple, Optional, TypedDict, Literal

# Import LangGraph (would need to be installed)
# from langgraph.graph import StateGraph
# from langgraph.prebuilt import ToolNode, ToolExecutor

# Import our MCP agent integration
from cloud_drift_analyzer.mcp import (
    get_available_tools_for_agent,
    execute_tool_for_agent,
    LangGraphExecutor
)

# NOTE: This is a simplified example to demonstrate the concepts
# In a real implementation, you would use an actual LLM and LangGraph


class AgentState(TypedDict):
    """Type definition for agent state in LangGraph."""
    messages: List[Dict[str, Any]]
    tools: List[Dict[str, Any]]
    tool_output: Optional[Dict[str, Any]]
    current_tool: Optional[str]
    tool_input: Optional[Dict[str, Any]]
    next_step: Literal["agent", "tool", "complete"]


async def main():
    """Run the example script."""
    print("==== Cloud Drift Analyzer MCP + LangGraph Example ====")
    
    # 1. Get available tools for agent reasoning
    tools = await get_available_tools_for_agent()
    print(f"Found {len(tools)} available tools:")
    for tool in tools:
        print(f"  - {tool['name']}: {tool['description']}")
    print()
    
    # 2. Create a LangGraph executor
    executor = LangGraphExecutor()
    tool_nodes = executor.get_tool_nodes()
    print(f"Created {len(tool_nodes)} tool nodes for LangGraph")
    print()
    
    # 3. Example of how to use in a LangGraph workflow (pseudocode)
    print("== LangGraph Integration Example (pseudocode) ==")
    print("""
    # Create tool executor
    tool_executor = ToolExecutor(tool_nodes)
    
    # Define agent that selects tools
    async def agent(state: AgentState) -> AgentState:
        # Use LLM to decide what tool to use based on state
        # For this example, we'll just choose a tool
        selected_tool = "analyze_drift"
        tool_input = {
            "resource_type": "aws_s3_bucket",
            "resource_id": "my-bucket",
            "state_backend": "terraform",
            "state_location": "./terraform.tfstate"
        }
        
        return {
            **state,
            "current_tool": selected_tool,
            "tool_input": tool_input,
            "next_step": "tool"
        }
    
    # Define workflow
    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent)
    workflow.add_node("tool", tool_executor)
    
    # Define transitions
    workflow.add_edge("agent", "tool")
    workflow.add_edge("tool", "agent")
    
    # Compile workflow
    app = workflow.compile()
    
    # Run workflow
    result = await app.invoke({
        "messages": [...],
        "tools": tools,
        "next_step": "agent"
    })
    """)
    print()
    
    # 4. Direct execution example (what happens under the hood)
    print("== Direct Tool Execution Example ==")
    
    # Example of executing the drift analysis tool
    try:
        tool_input = {
            "resource_type": "aws_s3_bucket",
            "resource_id": "my-bucket",
            "state_backend": "terraform",
            "state_location": "./terraform.tfstate"
        }
        
        print(f"Executing analyze_drift tool with input: {json.dumps(tool_input, indent=2)}")
        
        # This would normally be executed within the LangGraph workflow
        result = await execute_tool_for_agent("analyze_drift", tool_input)
        
        # In a real application, this result would be sent back to the agent
        # for reasoning and deciding the next step
        print(f"Result: {json.dumps(result, indent=2)}")
    
    except Exception as e:
        print(f"Error executing tool: {str(e)}")
    
    print("\n==== Example Complete ====")


# Run the example
if __name__ == "__main__":
    asyncio.run(main())
