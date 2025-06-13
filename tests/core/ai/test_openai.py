"""
Tests for the OpenAI service implementation.

This module contains comprehensive test cases for the OpenAI service,
verifying its functionality for AI-powered analysis, validation, and scoring.
Tests are organized into categories: basic functionality, analysis,
validation, scoring, monitoring, and integration.

Test Categories:
- Basic Functionality: Service initialization, configuration, and cleanup
- Analysis: Finding analysis, response processing, and error handling
- Validation: Finding validation and confidence scoring
- Monitoring: Service health, metrics, and rate limiting
- Integration: End-to-end service interaction and data flow

Each test category focuses on specific aspects of the OpenAI service:
1. Basic Functionality: Core service features and configuration
2. Analysis: AI-powered analysis capabilities
3. Validation: Finding validation and confidence assessment
4. Monitoring: System performance and health tracking
5. Integration: Complete service workflow
"""

import asyncio
import json
import pytest
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
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

# Test Configuration
TEST_CONFIG = {
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

# Test Data
TEST_FINDING = {
    "title": "Test Finding",
    "description": "Test description",
    "severity": "high",
    "confidence": 0.8,
    "evidence": {
        "url": "https://example.com/test",
        "method": "POST",
        "parameter": "test_param",
        "payload": "test_payload"
    }
}

TEST_ANALYSIS_RESPONSE = {
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

TEST_VALIDATION_RESPONSE = {
    "choices": [{
        "message": {
            "content": json.dumps({
                "validation": {
                    "is_valid": True,
                    "confidence": 0.9,
                    "explanation": "Valid finding"
                }
            })
        }
    }]
}

TEST_CONFIDENCE_RESPONSE = {
    "choices": [{
        "message": {
            "content": json.dumps({
                "confidence": {
                    "score": 0.95,
                    "explanation": "High confidence score"
                }
            })
        }
    }]
}

# Test Fixtures
@pytest.fixture
async def mock_session():
    """
    Create a mock aiohttp session for testing.
    
    This fixture provides a mock session that simulates OpenAI API responses
    and handles various HTTP scenarios (success, rate limiting, errors).
    
    Returns:
        AsyncMock: A mock aiohttp session.
    """
    session = AsyncMock()
    session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value=TEST_ANALYSIS_RESPONSE
    )
    session.post.return_value.__aenter__.return_value.status = 200
    return session

@pytest.fixture
async def openai_service(mock_session):
    """
    Create and initialize an OpenAIService instance for testing.
    
    This fixture ensures proper setup and cleanup of the OpenAI service
    for each test case. It also verifies that the service is properly
    initialized before use and cleaned up after use.
    
    Returns:
        OpenAIService: An initialized OpenAI service instance.
    """
    with patch("aiohttp.ClientSession", return_value=mock_session):
        service = OpenAIService(TEST_CONFIG)
        await service.initialize()
        yield service
        await service.close()

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic OpenAI service functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, mock_session):
        """Test OpenAI service initialization and configuration."""
        with patch("aiohttp.ClientSession", return_value=mock_session):
            # Test successful initialization
            service = OpenAIService(TEST_CONFIG)
            await service.initialize()
            assert service.is_initialized
            assert service.session is not None
            assert service.monitor is not None
            await service.close()
            
            # Test initialization with invalid config
            invalid_configs = [
                {**TEST_CONFIG, "api_key": None},
                {**TEST_CONFIG, "model_name": ""},
                {**TEST_CONFIG, "max_tokens": -1},
                {**TEST_CONFIG, "temperature": 2.0}
            ]
            
            for config in invalid_configs:
                with pytest.raises(AIServiceError) as exc_info:
                    service = OpenAIService(config)
                    await service.initialize()
                assert "Invalid configuration" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_cleanup(self, openai_service):
        """Test OpenAI service cleanup."""
        await openai_service.close()
        assert not openai_service.is_initialized
        assert openai_service.session is None
        
        # Test double cleanup
        await openai_service.close()  # Should not raise
    
    @pytest.mark.asyncio
    async def test_configuration_validation(self, openai_service):
        """Test OpenAI service configuration validation."""
        # Test valid configuration
        assert await openai_service.validate_configuration(TEST_CONFIG)
        
        # Test invalid configurations
        invalid_configs = [
            {**TEST_CONFIG, "api_key": None},
            {**TEST_CONFIG, "model_name": ""},
            {**TEST_CONFIG, "max_tokens": -1},
            {**TEST_CONFIG, "temperature": 2.0},
            {**TEST_CONFIG, "requests_per_minute": 0}
        ]
        
        for config in invalid_configs:
            with pytest.raises(AIServiceError) as exc_info:
                await openai_service.validate_configuration(config)
            assert "Invalid configuration" in str(exc_info.value)

# Analysis Tests
class TestAnalysis:
    """Tests for OpenAI analysis functionality."""
    
    @pytest.mark.asyncio
    async def test_finding_analysis(self, openai_service):
        """Test finding analysis functionality."""
        # Test successful analysis
        result = await openai_service.analyze_finding(TEST_FINDING)
        assert result["analysis"]["severity"] == "high"
        assert result["analysis"]["confidence"] == 0.9
        assert result["analysis"]["explanation"] == "Test explanation"
        assert "timestamp" in result
        assert "request_id" in result
    
    @pytest.mark.asyncio
    async def test_error_handling(self, openai_service, mock_session):
        """Test error handling during analysis."""
        # Test rate limit handling
        mock_session.post.return_value.__aenter__.return_value.status = 429
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={"error": {"message": "Rate limit exceeded"}}
        )
        
        with pytest.raises(AIServiceRateLimitError) as exc_info:
            await openai_service.analyze_finding(TEST_FINDING)
        assert "Rate limit exceeded" in str(exc_info.value)
        
        # Test connection error
        mock_session.post.side_effect = Exception("Connection error")
        with pytest.raises(AIServiceConnectionError) as exc_info:
            await openai_service.analyze_finding(TEST_FINDING)
        assert "Connection error" in str(exc_info.value)
        
        # Test invalid response
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={"choices": [{"message": {"content": "invalid json"}}]}
        )
        with pytest.raises(AIServiceError) as exc_info:
            await openai_service.analyze_finding(TEST_FINDING)
        assert "Invalid response" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_retry_logic(self, openai_service, mock_session):
        """Test retry logic for failed requests."""
        # Simulate temporary failures
        mock_session.post.side_effect = [
            Exception("Temporary error"),
            Exception("Temporary error"),
            mock_session.post.return_value
        ]
        
        result = await openai_service.analyze_finding(TEST_FINDING)
        assert result["analysis"]["severity"] == "high"
        assert mock_session.post.call_count == 3
        
        # Test max retries exceeded
        mock_session.post.side_effect = Exception("Persistent error")
        with pytest.raises(AIServiceError) as exc_info:
            await openai_service.analyze_finding(TEST_FINDING)
        assert "Max retries exceeded" in str(exc_info.value)

# Validation Tests
class TestValidation:
    """Tests for OpenAI validation functionality."""
    
    @pytest.mark.asyncio
    async def test_finding_validation(self, openai_service, mock_session):
        """Test finding validation functionality."""
        # Test successful validation
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value=TEST_VALIDATION_RESPONSE
        )
        
        result = await openai_service.validate_finding(TEST_FINDING)
        assert result["validation"]["is_valid"] is True
        assert result["validation"]["confidence"] == 0.9
        assert result["validation"]["explanation"] == "Valid finding"
        assert "timestamp" in result
        assert "request_id" in result
        
        # Test invalid finding
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "validation": {
                                "is_valid": False,
                                "confidence": 0.8,
                                "explanation": "Invalid finding"
                            }
                        })
                    }
                }]
            }
        )
        
        result = await openai_service.validate_finding(TEST_FINDING)
        assert result["validation"]["is_valid"] is False
        assert result["validation"]["confidence"] == 0.8
        assert result["validation"]["explanation"] == "Invalid finding"
    
    @pytest.mark.asyncio
    async def test_confidence_scoring(self, openai_service, mock_session):
        """Test confidence scoring functionality."""
        # Test successful scoring
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value=TEST_CONFIDENCE_RESPONSE
        )
        
        result = await openai_service.score_confidence(TEST_FINDING)
        assert result["confidence"]["score"] == 0.95
        assert result["confidence"]["explanation"] == "High confidence score"
        assert "timestamp" in result
        assert "request_id" in result
        
        # Test low confidence
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "confidence": {
                                "score": 0.3,
                                "explanation": "Low confidence score"
                            }
                        })
                    }
                }]
            }
        )
        
        result = await openai_service.score_confidence(TEST_FINDING)
        assert result["confidence"]["score"] == 0.3
        assert result["confidence"]["explanation"] == "Low confidence score"

# Monitoring Tests
class TestMonitoring:
    """Tests for OpenAI monitoring functionality."""
    
    @pytest.mark.asyncio
    async def test_service_health(self, openai_service):
        """Test service health check functionality."""
        # Test healthy state
        health = await openai_service.get_service_health()
        assert health["status"] == "healthy"
        assert "metrics" in health
        assert "rate_limits" in health
        
        # Test rate-limited state
        openai_service.monitor.metrics.total_requests = 70  # Exceed requests_per_minute
        health = await openai_service.get_service_health()
        assert health["status"] == "rate_limited"
        assert health["rate_limits"]["requests_per_minute"]["exceeded"]
    
    @pytest.mark.asyncio
    async def test_metrics_tracking(self, openai_service):
        """Test metrics tracking functionality."""
        # Track various metrics
        await openai_service.analyze_finding(TEST_FINDING)
        await openai_service.validate_finding(TEST_FINDING)
        await openai_service.score_confidence(TEST_FINDING)
        
        # Verify metrics
        metrics = await openai_service.get_metrics()
        assert metrics["total_requests"] == 3
        assert metrics["total_tokens"] > 0
        assert metrics["average_latency"] > 0
        assert "cost" in metrics
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, openai_service):
        """Test rate limiting functionality."""
        # Test normal rate limit
        for _ in range(TEST_CONFIG["requests_per_minute"]):
            await openai_service.analyze_finding(TEST_FINDING)
        
        # Test rate limit exceeded
        with pytest.raises(AIServiceRateLimitError) as exc_info:
            await openai_service.analyze_finding(TEST_FINDING)
        assert "Rate limit exceeded" in str(exc_info.value)
        
        # Test rate limit reset
        await asyncio.sleep(61)  # Wait for rate limit window to reset
        await openai_service.analyze_finding(TEST_FINDING)  # Should succeed

# Integration Tests
class TestIntegration:
    """Tests for OpenAI service integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self, openai_service, mock_session):
        """Test end-to-end service workflow."""
        # Configure mock responses
        mock_session.post.return_value.__aenter__.return_value.json = AsyncMock(
            side_effect=[
                TEST_ANALYSIS_RESPONSE,
                TEST_VALIDATION_RESPONSE,
                TEST_CONFIDENCE_RESPONSE
            ]
        )
        
        # Execute workflow
        analysis = await openai_service.analyze_finding(TEST_FINDING)
        validation = await openai_service.validate_finding(TEST_FINDING)
        confidence = await openai_service.score_confidence(TEST_FINDING)
        
        # Verify results
        assert analysis["analysis"]["severity"] == "high"
        assert validation["validation"]["is_valid"] is True
        assert confidence["confidence"]["score"] == 0.95
        
        # Verify metrics
        metrics = await openai_service.get_metrics()
        assert metrics["total_requests"] == 3
        assert metrics["total_tokens"] > 0
        assert metrics["average_latency"] > 0
    
    @pytest.mark.asyncio
    async def test_error_recovery(self, openai_service, mock_session):
        """Test error recovery and retry logic."""
        # Simulate temporary failures followed by success
        mock_session.post.side_effect = [
            Exception("Temporary error"),
            Exception("Temporary error"),
            mock_session.post.return_value
        ]
        
        # Execute workflow with retries
        result = await openai_service.analyze_finding(TEST_FINDING)
        assert result["analysis"]["severity"] == "high"
        assert mock_session.post.call_count == 3
        
        # Verify metrics include retries
        metrics = await openai_service.get_metrics()
        assert metrics["total_retries"] == 2
        assert metrics["total_requests"] == 1 