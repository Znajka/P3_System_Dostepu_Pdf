"""
FastAPI application entry point for PDF encryption/decryption microservice.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

# Configure logging
logging.basicConfig(level=os.getenv("FASTAPI_LOGGING_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Import routers
from app.routers import encrypt, decrypt, internal, streaming, stream_ticket

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("FastAPI PDF Microservice starting")
    yield
    logger.info("FastAPI PDF Microservice shutting down")

# Create app
app = FastAPI(
    title="P3 Dostepu PDF Microservice",
    description="AES-256-GCM encryption/decryption and streaming for PDF documents",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware (restrict to Spring Boot backend and frontend)
allowed_origins = os.getenv(
    "CORS_ORIGINS", "http://localhost:8080,http://localhost:3000"
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"]
)

# Include routers
app.include_router(encrypt.router)
app.include_router(decrypt.router)
app.include_router(internal.router)
app.include_router(streaming.router)
app.include_router(stream_ticket.router)  # ADD THIS

# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "pdf-microservice",
        "encryption": "AES-256-GCM",
        "streaming": "enabled"
    }

# Root endpoint
@app.get("/", tags=["root"])
async def root():
    return {
        "message": "P3 Dostepu PDF Microservice",
        "docs": "/docs",
        "endpoints": {
            "streaming": "/stream/{ticket}",
            "health": "/health"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443)