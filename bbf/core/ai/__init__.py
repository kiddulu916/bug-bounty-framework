"""
AI Service Integration Module

This module provides AI-powered analysis capabilities for security findings,
including finding analysis, validation, and confidence scoring.
"""

__version__ = "0.1.0"

from .service import AIService, AIServiceError
from .openai import OpenAIService
from .config import AIServiceConfig
from .monitoring import AIServiceMonitor

__all__ = [
    "AIService",
    "AIServiceError",
    "OpenAIService",
    "AIServiceConfig",
    "AIServiceMonitor",
] 