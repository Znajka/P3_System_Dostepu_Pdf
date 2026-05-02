"""
Pydantic models for streaming requests/responses.
"""

from pydantic import BaseModel, Field
from typing import Optional


class StreamingRequest(BaseModel):
    """Request metadata for streaming (implicit from JWT)."""
    ticket: str = Field(..., description="Open-ticket JWT")
    user_id: str = Field(..., description="User ID from ticket")
    document_id: str = Field(..., description="Document ID from ticket")
    nonce: str = Field(..., description="Ticket nonce for replay prevention")


class StreamingAuditLog(BaseModel):
    """Audit event for streaming operations."""
    document_id: str
    user_id: str
    action: str  # "stream_start", "stream_end"
    status: str  # "success", "failure"
    bytes_streamed: int = 0
    reason: Optional[str] = None