"""
Unit tests for AI service base interface and common functionality.
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from bbf.core.ai.service import (
    AIService,
    AIServiceError,
    AIServiceConfigError,
    AIServiceConnectionError,
    AIServiceRateLimitError,
    ConfidenceLevel,
    AnalysisResult,
    ValidationResult,
    ConfidenceScore
)


class MockAIService(AIService):
    """Mock implementation of AIService for testing."""
    
    def __init__(self, config=None):
        super().__init__(config or {})
        self._initialized = False
        self._closed = False
        self._mock_analysis = MagicMock()
        self._mock_validation = MagicMock()
        self._mock_scoring = MagicMock()
        self._mock_health = MagicMock()
        self._mock_metrics = MagicMock()

    async def _validate_config(self):
        if not self.config.get("api_key"):
            raise AIServiceConfigError("Missing API key")
        return True

    async def _initialize_service(self):
        self._initialized = True
        return True

    async def analyze_finding(self, finding_id: str, finding_data: dict) -> AnalysisResult:
        return await self._mock_analysis(finding_id, finding_data)

    async def validate_finding(self, finding_id: str, finding_data: dict) -> ValidationResult:
        return await self._mock_validation(finding_id, finding_data)

    async def score_confidence(self, finding_id: str, finding_data: dict) -> ConfidenceScore:
        return await self._mock_scoring(finding_id, finding_data)

    async def get_service_health(self) -> dict:
        return await self._mock_health()

    async def get_service_metrics(self) -> dict:
        return await self._mock_metrics()

    async def close(self):
        self._closed = True


@pytest.fixture
def valid_config():
    """Provide a valid configuration for testing."""
    return {
        "service_name": "test-service",
        "service_version": "1.0.0",
        "api_key": "test-api-key",
        "model_name": "test-model",
        "max_tokens": 1000,
        "temperature": 0.7,
        "requests_per_minute": 60,
        "tokens_per_minute": 1000
    }


@pytest.fixture
async def mock_service(valid_config):
    """Create a mock AI service instance."""
    service = MockAIService(valid_config)
    await service.initialize()
    yield service
    await service.close()


@pytest.mark.asyncio
async def test_service_initialization(valid_config):
    """Test service initialization with valid and invalid configurations."""
    # Test successful initialization
    service = MockAIService(valid_config)
    assert not service._initialized
    await service.initialize()
    assert service._initialized

    # Test initialization with invalid config
    service = MockAIService({})
    with pytest.raises(AIServiceConfigError):
        await service.initialize()


@pytest.mark.asyncio
async def test_analyze_finding(mock_service):
    """Test finding analysis functionality."""
    finding_id = "test-finding-1"
    finding_data = {"title": "Test Finding", "description": "Test Description"}
    expected_result = AnalysisResult(
        finding_id=finding_id,
        analysis="Test analysis",
        confidence_score=0.8,
        confidence_level=ConfidenceLevel.HIGH,
        timestamp=datetime.now()
    )
    
    mock_service._mock_analysis.return_value = expected_result
    result = await mock_service.analyze_finding(finding_id, finding_data)
    
    assert result == expected_result
    mock_service._mock_analysis.assert_called_once_with(finding_id, finding_data)


@pytest.mark.asyncio
async def test_validate_finding(mock_service):
    """Test finding validation functionality."""
    finding_id = "test-finding-1"
    finding_data = {"title": "Test Finding", "description": "Test Description"}
    expected_result = ValidationResult(
        finding_id=finding_id,
        is_valid=True,
        validation_notes="Test validation",
        confidence_score=0.9,
        confidence_level=ConfidenceLevel.VERY_HIGH,
        timestamp=datetime.now()
    )
    
    mock_service._mock_validation.return_value = expected_result
    result = await mock_service.validate_finding(finding_id, finding_data)
    
    assert result == expected_result
    mock_service._mock_validation.assert_called_once_with(finding_id, finding_data)


@pytest.mark.asyncio
async def test_score_confidence(mock_service):
    """Test confidence scoring functionality."""
    finding_id = "test-finding-1"
    finding_data = {"title": "Test Finding", "description": "Test Description"}
    expected_result = ConfidenceScore(
        finding_id=finding_id,
        confidence_score=0.85,
        confidence_level=ConfidenceLevel.HIGH,
        scoring_notes="Test scoring",
        timestamp=datetime.now()
    )
    
    mock_service._mock_scoring.return_value = expected_result
    result = await mock_service.score_confidence(finding_id, finding_data)
    
    assert result == expected_result
    mock_service._mock_scoring.assert_called_once_with(finding_id, finding_data)


@pytest.mark.asyncio
async def test_service_health(mock_service):
    """Test service health check functionality."""
    expected_health = {
        "status": "healthy",
        "metrics": {
            "requests_per_minute": 10,
            "tokens_per_minute": 100
        }
    }
    
    mock_service._mock_health.return_value = expected_health
    health = await mock_service.get_service_health()
    
    assert health == expected_health
    mock_service._mock_health.assert_called_once()


@pytest.mark.asyncio
async def test_service_metrics(mock_service):
    """Test service metrics retrieval."""
    expected_metrics = {
        "total_requests": 100,
        "successful_requests": 95,
        "failed_requests": 5,
        "total_tokens": 1000
    }
    
    mock_service._mock_metrics.return_value = expected_metrics
    metrics = await mock_service.get_service_metrics()
    
    assert metrics == expected_metrics
    mock_service._mock_metrics.assert_called_once()


@pytest.mark.asyncio
async def test_error_handling(mock_service):
    """Test error handling for various service errors."""
    finding_id = "test-finding-1"
    finding_data = {"title": "Test Finding", "description": "Test Description"}
    
    # Test connection error
    mock_service._mock_analysis.side_effect = AIServiceConnectionError("Connection failed")
    with pytest.raises(AIServiceConnectionError):
        await mock_service.analyze_finding(finding_id, finding_data)
    
    # Test rate limit error
    mock_service._mock_analysis.side_effect = AIServiceRateLimitError("Rate limit exceeded")
    with pytest.raises(AIServiceRateLimitError):
        await mock_service.analyze_finding(finding_id, finding_data)
    
    # Test general service error
    mock_service._mock_analysis.side_effect = AIServiceError("General error")
    with pytest.raises(AIServiceError):
        await mock_service.analyze_finding(finding_id, finding_data)


@pytest.mark.asyncio
async def test_confidence_level_conversion():
    """Test confidence level conversion between score and level."""
    # Test score to level conversion
    assert ConfidenceLevel.from_score(0.95) == ConfidenceLevel.VERY_HIGH
    assert ConfidenceLevel.from_score(0.8) == ConfidenceLevel.HIGH
    assert ConfidenceLevel.from_score(0.6) == ConfidenceLevel.MEDIUM
    assert ConfidenceLevel.from_score(0.4) == ConfidenceLevel.LOW
    assert ConfidenceLevel.from_score(0.2) == ConfidenceLevel.VERY_LOW
    
    # Test level to score conversion
    assert ConfidenceLevel.VERY_HIGH.value == 1.0
    assert ConfidenceLevel.HIGH.value == 0.8
    assert ConfidenceLevel.MEDIUM.value == 0.6
    assert ConfidenceLevel.LOW.value == 0.4
    assert ConfidenceLevel.VERY_LOW.value == 0.2


@pytest.mark.asyncio
async def test_result_timestamps(mock_service):
    """Test that results include timestamps."""
    finding_id = "test-finding-1"
    finding_data = {"title": "Test Finding", "description": "Test Description"}
    
    # Test analysis result timestamp
    analysis_result = await mock_service.analyze_finding(finding_id, finding_data)
    assert isinstance(analysis_result.timestamp, datetime)
    
    # Test validation result timestamp
    validation_result = await mock_service.validate_finding(finding_id, finding_data)
    assert isinstance(validation_result.timestamp, datetime)
    
    # Test confidence score timestamp
    confidence_result = await mock_service.score_confidence(finding_id, finding_data)
    assert isinstance(confidence_result.timestamp, datetime)


@pytest.mark.asyncio
async def test_service_cleanup(mock_service):
    """Test service cleanup on close."""
    assert not mock_service._closed
    await mock_service.close()
    assert mock_service._closed 