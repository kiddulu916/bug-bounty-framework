"""
Base AI Service Interface

This module defines the base interface for AI services that provide
finding analysis, validation, and confidence scoring capabilities.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from ..exceptions import FrameworkError


class AIServiceError(FrameworkError):
    """Base exception for AI service errors."""
    pass


class AIServiceConfigError(AIServiceError):
    """Configuration error in AI service."""
    pass


class AIServiceConnectionError(AIServiceError):
    """Connection error in AI service."""
    pass


class AIServiceRateLimitError(AIServiceError):
    """Rate limit error in AI service."""
    pass


class ConfidenceLevel(Enum):
    """Confidence levels for AI analysis results."""
    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 1.0


@dataclass
class AnalysisResult:
    """Result of AI analysis of a finding."""
    finding_id: str
    confidence_score: float
    confidence_level: ConfidenceLevel
    analysis_summary: str
    false_positive_probability: float
    remediation_suggestions: List[str]
    impact_assessment: str
    metadata: Dict[str, Any]
    timestamp: datetime
    model_version: str


@dataclass
class ValidationResult:
    """Result of AI validation of a finding."""
    finding_id: str
    is_valid: bool
    validation_reason: str
    confidence_score: float
    metadata: Dict[str, Any]
    timestamp: datetime
    model_version: str


@dataclass
class ConfidenceScore:
    """Confidence score for a finding."""
    finding_id: str
    score: float
    level: ConfidenceLevel
    factors: List[str]
    metadata: Dict[str, Any]
    timestamp: datetime
    model_version: str


class AIService(ABC):
    """Base class for AI service integration."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the AI service with configuration.
        
        Args:
            config: Service configuration dictionary
        """
        self.config = self._validate_config(config)
        self._initialize_service()

    @abstractmethod
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and process service configuration.
        
        Args:
            config: Raw configuration dictionary
            
        Returns:
            Processed configuration dictionary
            
        Raises:
            AIServiceConfigError: If configuration is invalid
        """
        pass

    @abstractmethod
    def _initialize_service(self) -> None:
        """Initialize the AI service connection and resources.
        
        Raises:
            AIServiceConnectionError: If service initialization fails
        """
        pass

    @abstractmethod
    async def analyze_finding(self, finding: Dict[str, Any]) -> AnalysisResult:
        """Analyze a security finding using AI.
        
        Args:
            finding: Finding data to analyze
            
        Returns:
            Analysis result with confidence score and details
            
        Raises:
            AIServiceError: If analysis fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        pass

    @abstractmethod
    async def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate a security finding using AI.
        
        Args:
            finding: Finding data to validate
            
        Returns:
            Validation result with confidence score and details
            
        Raises:
            AIServiceError: If validation fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        pass

    @abstractmethod
    async def score_confidence(self, finding: Dict[str, Any]) -> ConfidenceScore:
        """Score the confidence of a finding using AI.
        
        Args:
            finding: Finding data to score
            
        Returns:
            Confidence score with factors and details
            
        Raises:
            AIServiceError: If scoring fails
            AIServiceRateLimitError: If rate limit is exceeded
        """
        pass

    @abstractmethod
    async def get_service_health(self) -> Dict[str, Any]:
        """Get the health status of the AI service.
        
        Returns:
            Dictionary containing service health metrics
        """
        pass

    @abstractmethod
    async def get_service_metrics(self) -> Dict[str, Any]:
        """Get usage metrics for the AI service.
        
        Returns:
            Dictionary containing service usage metrics
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the AI service connection and cleanup resources."""
        pass 