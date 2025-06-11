"""
Unit tests for OpenAI service implementation.
"""

import asyncio
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import ClientResponse, ClientSession

from bbf.core.ai.openai import OpenAIService
from bbf.core.ai.service import (
    AIServiceError,
    AIServiceConfigError,
    AIServiceConnectionError,
    AIServiceRateLimitError,
    AnalysisResult,
    ValidationResult,
    ConfidenceScore,
    ConfidenceLevel
)


@pytest.fixture
def valid_config():
    """Provide a valid configuration for testing."""
    return {
        "service_name": "openai",
        "service_version": "1.0.0",
        "api_key": "test-api-key",
        "api_base": "https://api.openai.com/v1",
        "model_name": "gpt-4",
        "max_tokens": 1000,
        "temperature": 0.7,
        "requests_per_minute": 60,
        "tokens_per_minute": 1000,
        "enable_metrics": True,
        "enable_logging": True,
        "log_level": "INFO",
        "cost_per_token": 0.00002,
        "cost_per_request": 0.0001
    }


@pytest.fixture
def mock_response():
    """Provide a mock OpenAI API response."""
    return {
        "id": "test-response-id",
        "object": "chat.completion",
        "created": int(datetime.now().timestamp()),
        "model": "gpt-4",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "analysis": {
                        "severity": "high",
                        "confidence": 0.9,
                        "explanation": "Test explanation"
                    }
                })
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 50,
            "completion_tokens": 50,
            "total_tokens": 100
        }
    }


@pytest.fixture
async def mock_session(mock_response):
    """Create a mock aiohttp session."""
    session = AsyncMock()
    session.post.return_value.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
    session.post.return_value.__aenter__.return_value.status = 200
    return session


@pytest.fixture
async def service(valid_config, mock_session):
    """Create an OpenAI service instance for testing."""
    with patch("aiohttp.ClientSession", return_value=mock_session):
        service = OpenAIService(valid_config)
        await service.initialize()
        yield service
        await service.close()


@pytest.mark.asyncio
async def test_openai_initialization(valid_config):
    """Test OpenAI service initialization."""
    # Test successful initialization
    with patch("aiohttp.ClientSession") as mock_session:
        service = OpenAIService(valid_config)
        await service.initialize()
        assert service.is_initialized
        assert service.session is not None
        assert service.monitor is not None
        await service.close()
    
    # Test initialization with invalid config
    invalid_config = valid_config.copy()
    invalid_config["api_key"] = None
    
    with pytest.raises(AIServiceError) as exc_info:
        service = OpenAIService(invalid_config)
        await service.initialize()
    assert "Invalid configuration" in str(exc_info.value)


@pytest.mark.asyncio
async def test_analyze_finding(service, mock_response):
    """Test finding analysis functionality."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Test successful analysis
    result = await service.analyze_finding(finding)
    assert result["analysis"]["severity"] == "high"
    assert result["analysis"]["confidence"] == 0.9
    assert result["analysis"]["explanation"] == "Test explanation"
    assert "timestamp" in result
    assert "request_id" in result
    
    # Test rate limit handling
    service.session.post.return_value.__aenter__.return_value.status = 429
    service.session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"error": {"message": "Rate limit exceeded"}}
    )
    
    with pytest.raises(AIServiceRateLimitError) as exc_info:
        await service.analyze_finding(finding)
    assert "Rate limit exceeded" in str(exc_info.value)
    
    # Test connection error handling
    service.session.post.side_effect = Exception("Connection error")
    
    with pytest.raises(AIServiceError) as exc_info:
        await service.analyze_finding(finding)
    assert "Connection error" in str(exc_info.value)


@pytest.mark.asyncio
async def test_validate_finding(service, mock_response):
    """Test finding validation functionality."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Test successful validation
    mock_response["choices"][0]["message"]["content"] = json.dumps({
        "validation": {
            "is_valid": True,
            "confidence": 0.9,
            "explanation": "Valid finding"
        }
    })
    
    result = await service.validate_finding(finding)
    assert result["validation"]["is_valid"] is True
    assert result["validation"]["confidence"] == 0.9
    assert result["validation"]["explanation"] == "Valid finding"
    assert "timestamp" in result
    assert "request_id" in result
    
    # Test invalid finding
    mock_response["choices"][0]["message"]["content"] = json.dumps({
        "validation": {
            "is_valid": False,
            "confidence": 0.8,
            "explanation": "Invalid finding"
        }
    })
    
    result = await service.validate_finding(finding)
    assert result["validation"]["is_valid"] is False
    assert result["validation"]["confidence"] == 0.8
    assert result["validation"]["explanation"] == "Invalid finding"


@pytest.mark.asyncio
async def test_score_confidence(service, mock_response):
    """Test confidence scoring functionality."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Test successful scoring
    mock_response["choices"][0]["message"]["content"] = json.dumps({
        "confidence": {
            "score": 0.95,
            "explanation": "High confidence score"
        }
    })
    
    result = await service.score_confidence(finding)
    assert result["confidence"]["score"] == 0.95
    assert result["confidence"]["explanation"] == "High confidence score"
    assert "timestamp" in result
    assert "request_id" in result
    
    # Test low confidence
    mock_response["choices"][0]["message"]["content"] = json.dumps({
        "confidence": {
            "score": 0.3,
            "explanation": "Low confidence score"
        }
    })
    
    result = await service.score_confidence(finding)
    assert result["confidence"]["score"] == 0.3
    assert result["confidence"]["explanation"] == "Low confidence score"


@pytest.mark.asyncio
async def test_service_health(service):
    """Test service health check."""
    health = await service.get_service_health()
    assert health["status"] == "healthy"
    assert "metrics" in health
    assert "rate_limits" in health
    
    # Test rate-limited state
    service.monitor.metrics.total_requests = 70  # Exceed requests_per_minute
    health = await service.get_service_health()
    assert health["status"] == "rate_limited"
    assert health["rate_limits"]["requests_per_minute"]["exceeded"]


@pytest.mark.asyncio
async def test_service_metrics(service):
    """Test service metrics retrieval."""
    # Record some metrics
    await service.analyze_finding({
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    })
    
    metrics = await service.get_service_metrics()
    assert metrics["total_requests"] > 0
    assert metrics["successful_requests"] > 0
    assert metrics["total_tokens"] > 0
    assert metrics["total_cost"] > 0
    assert metrics["total_latency"] > 0
    assert "min_latency" in metrics
    assert "max_latency" in metrics
    assert "avg_latency" in metrics


@pytest.mark.asyncio
async def test_retry_logic(service, mock_response):
    """Test retry logic for failed requests."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Simulate temporary failure followed by success
    service.session.post.side_effect = [
        Exception("Temporary error"),
        mock_response
    ]
    
    result = await service.analyze_finding(finding)
    assert result["analysis"]["severity"] == "high"
    assert service.session.post.call_count == 2
    
    # Test max retries exceeded
    service.session.post.side_effect = Exception("Persistent error")
    
    with pytest.raises(AIServiceError) as exc_info:
        await service.analyze_finding(finding)
    assert "Max retries exceeded" in str(exc_info.value)


@pytest.mark.asyncio
async def test_prompt_formatting(service):
    """Test prompt formatting for different operations."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Test analysis prompt
    analysis_prompt = service._get_analysis_prompt(finding)
    assert "analyze" in analysis_prompt.lower()
    assert finding["title"] in analysis_prompt
    assert finding["description"] in analysis_prompt
    
    # Test validation prompt
    validation_prompt = service._get_validation_prompt(finding)
    assert "validate" in validation_prompt.lower()
    assert finding["title"] in validation_prompt
    assert finding["description"] in validation_prompt
    
    # Test confidence prompt
    confidence_prompt = service._get_confidence_prompt(finding)
    assert "confidence" in confidence_prompt.lower()
    assert finding["title"] in confidence_prompt
    assert finding["description"] in confidence_prompt


@pytest.mark.asyncio
async def test_metrics_recording(service, mock_response):
    """Test metrics recording after operations."""
    finding = {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": 0.8
    }
    
    # Record metrics for analysis
    await service.analyze_finding(finding)
    metrics = await service.get_service_metrics()
    assert metrics["total_requests"] == 1
    assert metrics["successful_requests"] == 1
    assert metrics["total_tokens"] == 100
    assert metrics["total_cost"] > 0
    assert metrics["total_latency"] > 0
    
    # Record metrics for validation
    await service.validate_finding(finding)
    metrics = await service.get_service_metrics()
    assert metrics["total_requests"] == 2
    assert metrics["successful_requests"] == 2
    assert metrics["total_tokens"] == 200
    
    # Record metrics for confidence scoring
    await service.score_confidence(finding)
    metrics = await service.get_service_metrics()
    assert metrics["total_requests"] == 3
    assert metrics["successful_requests"] == 3
    assert metrics["total_tokens"] == 300


@pytest.mark.asyncio
async def test_service_cleanup(service):
    """Test service cleanup on close."""
    assert service.session is not None
    assert service.is_initialized
    
    await service.close()
    assert service.session is None
    assert not service.is_initialized
    assert service.monitor._monitor_task is None 