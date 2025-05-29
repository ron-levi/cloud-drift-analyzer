"""
Pydantic schemas for chat API endpoints.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, Field
from uuid import UUID


class ChatMessageBase(BaseModel):
    """Base schema for chat messages."""
    content: str = Field(..., description="Message content")
    role: Literal["user", "assistant", "system"] = Field(..., description="Message role")
    message_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ChatMessageCreate(ChatMessageBase):
    """Schema for creating a chat message."""
    conversation_id: Optional[UUID] = Field(None, description="Conversation ID, if None creates new conversation")


class ChatMessageResponse(ChatMessageBase):
    """Schema for chat message response."""
    id: UUID
    conversation_id: UUID
    tool_calls: Optional[Dict[str, Any]] = None
    tool_results: Optional[Dict[str, Any]] = None
    timestamp: datetime

    class Config:
        from_attributes = True


class ConversationBase(BaseModel):
    """Base schema for conversations."""
    title: str = Field(..., max_length=255, description="Conversation title")


class ConversationCreate(ConversationBase):
    """Schema for creating a conversation."""
    pass


class ConversationResponse(ConversationBase):
    """Schema for conversation response."""
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime
    is_active: bool
    message_count: Optional[int] = None

    class Config:
        from_attributes = True


class ConversationWithMessages(ConversationResponse):
    """Schema for conversation with messages."""
    messages: List[ChatMessageResponse] = Field(default_factory=list)


class ChatRequest(BaseModel):
    """Schema for chat request."""
    message: str = Field(..., description="User message")
    conversation_id: Optional[UUID] = Field(None, description="Conversation ID, if None creates new conversation")
    use_tools: bool = Field(True, description="Whether to use MCP tools for this request")
    tool_preference: Optional[str] = Field(None, description="Preferred tool to use")


class ChatResponse(BaseModel):
    """Schema for chat response."""
    message: ChatMessageResponse
    conversation: ConversationResponse
    tool_executions: List[Dict[str, Any]] = Field(default_factory=list)


class ToolExecutionResponse(BaseModel):
    """Schema for tool execution response."""
    id: UUID
    tool_name: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    execution_status: str
    error_message: Optional[str] = None
    execution_time_ms: Optional[int] = None
    timestamp: datetime

    class Config:
        from_attributes = True


class ConversationListResponse(BaseModel):
    """Schema for listing conversations."""
    conversations: List[ConversationResponse]
    total: int
    page: int
    per_page: int
