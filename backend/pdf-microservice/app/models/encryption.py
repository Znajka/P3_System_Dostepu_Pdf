"""
Pydantic models for encryption metadata and requests/responses.
"""

from typing import Optional
from pydantic import BaseModel, Field
import base64


class DekMetadata(BaseModel):
    """DEK metadata from Spring Boot (wrapped DEK, IV, tag, KMS info)."""
    wrapped_dek: str = Field(..., description="Base64-encoded wrapped DEK")
    iv: str = Field(..., description="Base64-encoded IV")
    tag: str = Field(..., description="Base64-encoded authentication tag")
    algorithm: str = Field(default="AES-KW", description="Key wrap algorithm")
    kms_key_id: str = Field(..., description="KMS key identifier")
    kms_metadata: Optional[dict] = Field(None, description="KMS metadata JSON")


class EncryptionRequest(BaseModel):
    """Request to encrypt a PDF."""
    document_id: str = Field(..., description="Document UUID")
    dek_base64: str = Field(..., description="Base64-encoded 256-bit DEK")


class EncryptionResponse(BaseModel):
    """Response after encrypting a PDF."""
    document_id: str
    status: str = "encrypted"
    ciphertext_size: int
    nonce: str = Field(..., description="Base64-encoded nonce")
    tag: str = Field(..., description="Base64-encoded authentication tag")


class DecryptionRequest(BaseModel):
    """Request to decrypt a PDF (from FastAPI internal)."""
    document_id: str
    nonce: str = Field(..., description="Base64-encoded nonce")
    tag: str = Field(..., description="Base64-encoded authentication tag")
    dek_base64: str = Field(..., description="Base64-encoded DEK")


class DecryptionResponse(BaseModel):
    """Response after decrypting a PDF."""
    document_id: str
    status: str = "decrypted"
    plaintext_size: int