"""
Chat API routes for real-time LLM interaction with MCP tools.
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from cloud_drift_analyzer.api.schemas.chat import (
    ChatRequest, ChatResponse, ChatMessageResponse, ConversationCreate,
    ConversationResponse, ConversationWithMessages, ConversationListResponse
)
from cloud_drift_analyzer.api.dependencies import get_current_user
from cloud_drift_analyzer.db.database import get_session
from cloud_drift_analyzer.db.models import User, ChatConversation, ChatMessage, ToolExecution
from cloud_drift_analyzer.mcp.agent_integration import AgentMCPInterface, AgentAction
from cloud_drift_analyzer.core.logging import get_logger, LogContext

logger = get_logger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])


class ConnectionManager:
    """Manages WebSocket connections for real-time chat."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        """Connect a new WebSocket."""
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info("websocket_connected", user_id=user_id)
    
    def disconnect(self, user_id: str):
        """Disconnect a WebSocket."""
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info("websocket_disconnected", user_id=user_id)
    
    async def send_personal_message(self, message: dict, user_id: str):
        """Send a message to a specific user."""
        if user_id in self.active_connections:
            websocket = self.active_connections[user_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error("websocket_send_failed", user_id=user_id, error=str(e))
                self.disconnect(user_id)


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    session: AsyncSession = Depends(get_session)
):
    """WebSocket endpoint for real-time chat."""
    try:
        # Verify token and get user
        from cloud_drift_analyzer.api.security.auth import verify_token
        payload = verify_token(token)
        username = payload["sub"]
        
        # Get user from database
        stmt = select(User).where(User.username == username)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            await websocket.close(code=4001, reason="User not found")
            return
        
        # Connect user
        await manager.connect(websocket, str(user.id))
        
        # Initialize MCP interface
        mcp_interface = AgentMCPInterface()
        
        try:
            while True:
                # Receive message from client
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                with LogContext(user_id=str(user.id), conversation_id=message_data.get("conversation_id")):
                    await handle_chat_message(
                        message_data, user, session, mcp_interface, manager
                    )
                    
        except WebSocketDisconnect:
            manager.disconnect(str(user.id))
    
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        await websocket.close(code=4000, reason=str(e))


async def handle_chat_message(
    message_data: dict,
    user: User,
    session: AsyncSession,
    mcp_interface: AgentMCPInterface,
    manager: ConnectionManager
):
    """Handle incoming chat message and generate response."""
    try:
        # Extract message details
        content = message_data.get("message", "")
        conversation_id = message_data.get("conversation_id")
        use_tools = message_data.get("use_tools", True)
        
        # Get or create conversation
        if conversation_id:
            stmt = select(ChatConversation).where(
                ChatConversation.id == conversation_id,
                ChatConversation.user_id == user.id
            )
            result = await session.execute(stmt)
            conversation = result.scalar_one_or_none()
            
            if not conversation:
                raise ValueError("Conversation not found")
        else:
            # Create new conversation
            conversation = ChatConversation(
                user_id=user.id,
                title=content[:50] + "..." if len(content) > 50 else content
            )
            session.add(conversation)
            await session.commit()
            await session.refresh(conversation)
        
        # Save user message
        user_message = ChatMessage(
            conversation_id=conversation.id,
            role="user",
            content=content
        )
        session.add(user_message)
        await session.commit()
        await session.refresh(user_message)
        
        # Send user message confirmation
        await manager.send_personal_message({
            "type": "user_message",
            "message": {
                "id": str(user_message.id),
                "content": content,
                "role": "user",
                "timestamp": user_message.timestamp.isoformat()
            },
            "conversation_id": str(conversation.id)
        }, str(user.id))
        
        # Generate AI response
        assistant_response = await generate_ai_response(
            content, conversation.id, use_tools, mcp_interface, session
        )
        
        # Save assistant message
        assistant_message = ChatMessage(
            conversation_id=conversation.id,
            role="assistant",
            content=assistant_response["content"],
            tool_calls=assistant_response.get("tool_calls"),
            tool_results=assistant_response.get("tool_results")
        )
        session.add(assistant_message)
        await session.commit()
        await session.refresh(assistant_message)
        
        # Send assistant response
        await manager.send_personal_message({
            "type": "assistant_message",
            "message": {
                "id": str(assistant_message.id),
                "content": assistant_response["content"],
                "role": "assistant",
                "tool_calls": assistant_response.get("tool_calls"),
                "tool_results": assistant_response.get("tool_results"),
                "timestamp": assistant_message.timestamp.isoformat()
            },
            "conversation_id": str(conversation.id)
        }, str(user.id))
        
    except Exception as e:
        logger.error("chat_message_handling_failed", error=str(e))
        await manager.send_personal_message({
            "type": "error",
            "message": f"Error processing message: {str(e)}"
        }, str(user.id))


async def generate_ai_response(
    user_message: str,
    conversation_id: UUID,
    use_tools: bool,
    mcp_interface: AgentMCPInterface,
    session: AsyncSession
) -> Dict[str, Any]:
    """Generate AI response, potentially using MCP tools."""
    
    # Simple logic for determining if tools should be used
    # In a real implementation, this would be more sophisticated
    tool_keywords = ["analyze", "drift", "cost", "iam", "security", "compliance", "s3", "bucket"]
    should_use_tools = use_tools and any(keyword in user_message.lower() for keyword in tool_keywords)
    
    if should_use_tools:
        # Determine which tool to use based on message content
        tool_name = determine_tool_from_message(user_message)
        
        if tool_name:
            try:
                # Execute tool
                tool_input = extract_tool_input_from_message(user_message, tool_name)
                action = AgentAction(tool=tool_name, tool_input=tool_input)
                tool_result = await mcp_interface.execute_agent_action(action)
                
                if tool_result.error:
                    return {
                        "content": f"I encountered an error while using the {tool_name} tool: {tool_result.error}",
                        "tool_calls": {tool_name: tool_input},
                        "tool_results": {"error": tool_result.error}
                    }
                else:
                    # Format tool result into human-readable response
                    formatted_response = format_tool_result(tool_name, tool_result.tool_output)
                    
                    return {
                        "content": formatted_response,
                        "tool_calls": {tool_name: tool_input},
                        "tool_results": tool_result.tool_output
                    }
                    
            except Exception as e:
                logger.error("tool_execution_failed", tool=tool_name, error=str(e))
                return {
                    "content": f"I encountered an error while trying to help: {str(e)}",
                    "tool_calls": None,
                    "tool_results": None
                }
    
    # Default response without tools
    return {
        "content": generate_default_response(user_message),
        "tool_calls": None,
        "tool_results": None
    }


def determine_tool_from_message(message: str) -> Optional[str]:
    """Determine which tool to use based on message content."""
    message_lower = message.lower()
    
    if any(word in message_lower for word in ["drift", "differ", "compare", "change"]):
        return "analyze_drift"
    elif any(word in message_lower for word in ["cost", "expense", "money", "optimize"]):
        return "optimize_costs"
    elif any(word in message_lower for word in ["iam", "permission", "role", "policy"]):
        return "iam_review"
    elif any(word in message_lower for word in ["s3", "bucket", "storage"]):
        return "s3_permission_scan"
    elif any(word in message_lower for word in ["kubernetes", "k8s", "compliance"]):
        return "k8s_compliance"
    
    return None


def extract_tool_input_from_message(message: str, tool_name: str) -> Dict[str, Any]:
    """Extract tool input parameters from user message."""
    # This is a simplified implementation
    # In a real application, you'd use NLP or more sophisticated parsing
    
    if tool_name == "analyze_drift":
        return {
            "resource_type": "aws_s3_bucket",  # Default
            "resource_id": "example-bucket",
            "state_backend": "terraform",
            "state_location": "./terraform.tfstate"
        }
    elif tool_name == "optimize_costs":
        return {
            "provider": "aws",
            "region": "us-east-1",
            "time_period_days": 30
        }
    elif tool_name == "iam_review":
        return {
            "provider": "aws",
            "resource_type": "user",
            "resource_name": "*"
        }
    elif tool_name == "s3_permission_scan":
        return {
            "bucket_name": "*",
            "check_public_access": True
        }
    elif tool_name == "k8s_compliance":
        return {
            "namespace": "default",
            "compliance_framework": "CIS"
        }
    
    return {}


def format_tool_result(tool_name: str, result: Dict[str, Any]) -> str:
    """Format tool execution result into human-readable response."""
    if tool_name == "analyze_drift":
        drift_detected = result.get("drift_detected", False)
        if drift_detected:
            changes = result.get("changes", [])
            return f"I found {len(changes)} drift issues in your infrastructure. Here's a summary: {json.dumps(changes, indent=2)}"
        else:
            return "Great news! No infrastructure drift was detected."
    
    elif tool_name == "optimize_costs":
        recommendations = result.get("recommendations", [])
        potential_savings = result.get("potential_monthly_savings", 0)
        return f"I found {len(recommendations)} cost optimization opportunities with potential monthly savings of ${potential_savings}. Details: {json.dumps(recommendations, indent=2)}"
    
    elif tool_name == "iam_review":
        findings = result.get("findings", [])
        return f"IAM security review completed. Found {len(findings)} security findings: {json.dumps(findings, indent=2)}"
    
    elif tool_name == "s3_permission_scan":
        buckets = result.get("buckets_scanned", [])
        issues = result.get("permission_issues", [])
        return f"Scanned {len(buckets)} S3 buckets and found {len(issues)} permission issues: {json.dumps(issues, indent=2)}"
    
    elif tool_name == "k8s_compliance":
        compliance_score = result.get("compliance_score", 0)
        violations = result.get("violations", [])
        return f"Kubernetes compliance check completed. Compliance score: {compliance_score}%. Found {len(violations)} violations: {json.dumps(violations, indent=2)}"
    
    return f"Tool execution completed: {json.dumps(result, indent=2)}"


def generate_default_response(message: str) -> str:
    """Generate a default response when no tools are used."""
    responses = [
        "I'm here to help you with cloud infrastructure analysis. You can ask me to analyze drift, optimize costs, review IAM permissions, scan S3 buckets, or check Kubernetes compliance.",
        "Hello! I can help you with various cloud infrastructure tasks. Try asking me to analyze drift or optimize costs in your cloud environment.",
        "I'm your cloud infrastructure assistant. I can help with drift detection, cost optimization, security reviews, and compliance checks.",
    ]
    
    # Simple keyword-based responses
    message_lower = message.lower()
    if "hello" in message_lower or "hi" in message_lower:
        return "Hello! I'm your cloud infrastructure assistant. I can help you analyze drift, optimize costs, and review security configurations. What would you like me to help you with?"
    elif "help" in message_lower:
        return "I can help you with:\n- Analyzing infrastructure drift\n- Optimizing cloud costs\n- Reviewing IAM permissions\n- Scanning S3 bucket permissions\n- Checking Kubernetes compliance\n\nJust ask me about any of these topics!"
    
    return responses[0]


# REST API endpoints for chat management

@router.post("/conversations", response_model=ConversationResponse)
async def create_conversation(
    conversation_data: ConversationCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """Create a new conversation."""
    conversation = ChatConversation(
        user_id=current_user.id,
        title=conversation_data.title
    )
    
    session.add(conversation)
    await session.commit()
    await session.refresh(conversation)
    
    return conversation


@router.get("/conversations", response_model=ConversationListResponse)
async def list_conversations(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """List user's conversations."""
    # Get total count
    count_stmt = select(func.count(ChatConversation.id)).where(
        ChatConversation.user_id == current_user.id,
        ChatConversation.is_active == True
    )
    total_result = await session.execute(count_stmt)
    total = total_result.scalar()
    
    # Get conversations
    offset = (page - 1) * per_page
    stmt = select(ChatConversation).where(
        ChatConversation.user_id == current_user.id,
        ChatConversation.is_active == True
    ).order_by(desc(ChatConversation.updated_at)).offset(offset).limit(per_page)
    
    result = await session.execute(stmt)
    conversations = result.scalars().all()
    
    return ConversationListResponse(
        conversations=conversations,
        total=total,
        page=page,
        per_page=per_page
    )


@router.get("/conversations/{conversation_id}", response_model=ConversationWithMessages)
async def get_conversation(
    conversation_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """Get a conversation with its messages."""
    # Get conversation
    stmt = select(ChatConversation).where(
        ChatConversation.id == conversation_id,
        ChatConversation.user_id == current_user.id
    )
    result = await session.execute(stmt)
    conversation = result.scalar_one_or_none()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    # Get messages
    msg_stmt = select(ChatMessage).where(
        ChatMessage.conversation_id == conversation_id
    ).order_by(ChatMessage.timestamp)
    
    msg_result = await session.execute(msg_stmt)
    messages = msg_result.scalars().all()
    
    return ConversationWithMessages(
        id=conversation.id,
        user_id=conversation.user_id,
        title=conversation.title,
        created_at=conversation.created_at,
        updated_at=conversation.updated_at,
        is_active=conversation.is_active,
        messages=[
            ChatMessageResponse(
                id=msg.id,
                conversation_id=msg.conversation_id,
                role=msg.role,
                content=msg.content,
                message_metadata=msg.message_metadata,
                tool_calls=msg.tool_calls,
                tool_results=msg.tool_results,
                timestamp=msg.timestamp
            ) for msg in messages
        ]
    )


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    """Delete a conversation."""
    stmt = select(ChatConversation).where(
        ChatConversation.id == conversation_id,
        ChatConversation.user_id == current_user.id
    )
    result = await session.execute(stmt)
    conversation = result.scalar_one_or_none()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    conversation.is_active = False
    await session.commit()
    
    return {"message": "Conversation deleted successfully"}
