"""
Tests for the AI service layer.

This module contains comprehensive test cases for the AI services,
verifying their functionality for AI-powered analysis and monitoring.
Tests are organized into categories: basic functionality, analysis,
error handling, monitoring, and integration.

Test Categories:
- Basic Functionality: Service initialization, configuration, and cleanup
- Analysis: Finding analysis, OpenAI integration, and response processing
- Error Handling: API errors, invalid inputs, and service state management
- Monitoring: Metrics tracking, performance monitoring, and error tracking
- Integration: End-to-end service interaction and data flow

Each test category focuses on specific aspects of the AI system:
1. Basic Functionality: Core service features and configuration
2. Analysis: AI-powered analysis capabilities
3. Error Handling: Robust error management
4. Monitoring: System performance and health tracking
5. Integration: Complete service workflow
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

from bbf.core.ai.service import AIService
from bbf.core.ai.openai import OpenAIService
from bbf.core.ai.monitoring import AIMonitoringService
from bbf.core.exceptions import AIServiceError
from bbf.core.database.models import Finding, FindingSeverity

# Test Configuration
TEST_CONFIG = {
    'openai': {
        'model': 'gpt-4',
        'temperature': 0.7,
        'max_tokens': 1000,
        'timeout': 30
    },
    'monitoring': {
        'enable_metrics': True,
        'alert_threshold': 5,
        'metrics_interval': 60
    }
}

# Test Data
TEST_FINDING = {
    'type': 'vulnerability',
    'title': 'SQL Injection Vulnerability',
    'description': 'Found potential SQL injection in login form',
    'severity': FindingSeverity.HIGH,
    'confidence': 0.8,
    'evidence': {
        'url': 'https://example.com/login',
        'method': 'POST',
        'parameter': 'username',
        'payload': "' OR '1'='1"
    }
}

TEST_ANALYSIS_PROMPT = """
Analyze the following security finding and provide:
1. Severity assessment
2. False positive likelihood
3. Recommended remediation steps
4. Additional context or insights

Finding:
{finding}
"""

TEST_ANALYSIS_RESPONSE = {
    'severity': 'high',
    'false_positive_likelihood': 0.1,
    'remediation_steps': [
        'Use parameterized queries',
        'Implement input validation',
        'Add WAF rules'
    ],
    'additional_insights': [
        'Vulnerability appears to be in legacy code',
        'Similar patterns found in other endpoints'
    ]
}

# Test Fixtures
@pytest.fixture
async def ai_service():
    """
    Create and initialize an AIService instance for testing.
    
    This fixture ensures proper setup and cleanup of the AI service
    for each test case. It also verifies that the service is properly
    initialized before use and cleaned up after use.
    
    Returns:
        AIService: An initialized AI service instance.
    """
    service = AIService(TEST_CONFIG)
    await service.initialize()
    yield service
    await service.cleanup()

@pytest.fixture
async def openai_service():
    """
    Create and initialize an OpenAIService instance for testing.
    
    This fixture ensures proper setup and cleanup of the OpenAI service
    for each test case. It also verifies that the service is properly
    initialized before use and cleaned up after use.
    
    Returns:
        OpenAIService: An initialized OpenAI service instance.
    """
    service = OpenAIService(TEST_CONFIG['openai'])
    await service.initialize()
    yield service
    await service.cleanup()

@pytest.fixture
async def monitoring_service():
    """
    Create and initialize an AIMonitoringService instance for testing.
    
    This fixture ensures proper setup and cleanup of the monitoring service
    for each test case. It also verifies that the service is properly
    initialized before use and cleaned up after use.
    
    Returns:
        AIMonitoringService: An initialized monitoring service instance.
    """
    service = AIMonitoringService(TEST_CONFIG['monitoring'])
    await service.initialize()
    yield service
    await service.cleanup()

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic AI service functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, ai_service):
        """Test AI service initialization and configuration."""
        assert ai_service._initialized
        assert ai_service._openai_service is not None
        assert ai_service._monitoring_service is not None
        assert ai_service._config == TEST_CONFIG
    
    @pytest.mark.asyncio
    async def test_cleanup(self, ai_service):
        """Test AI service cleanup."""
        await ai_service.cleanup()
        assert not ai_service._initialized
        assert ai_service._openai_service is None
        assert ai_service._monitoring_service is None
    
    @pytest.mark.asyncio
    async def test_configuration_validation(self, ai_service):
        """Test AI service configuration validation."""
        # Test valid configuration
        assert await ai_service.validate_configuration(TEST_CONFIG)
        
        # Test invalid configurations
        invalid_configs = [
            {'openai': {'model': ''}},
            {'openai': {'temperature': 2.0}},
            {'openai': {'max_tokens': -1}},
            {'monitoring': {'alert_threshold': 0}}
        ]
        
        for config in invalid_configs:
            with pytest.raises(ValueError) as exc_info:
                await ai_service.validate_configuration(config)
            assert 'invalid configuration' in str(exc_info.value).lower()

# Analysis Tests
class TestAnalysis:
    """Tests for AI analysis functionality."""
    
    @pytest.mark.asyncio
    async def test_finding_analysis(self, ai_service):
        """Test finding analysis functionality."""
        with patch.object(ai_service._openai_service, 'analyze',
                         new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = TEST_ANALYSIS_RESPONSE
            
            # Test analysis
            analysis = await ai_service.analyze_finding(TEST_FINDING)
            
            # Verify analysis
            assert analysis['severity'] == TEST_ANALYSIS_RESPONSE['severity']
            assert analysis['false_positive_likelihood'] == TEST_ANALYSIS_RESPONSE['false_positive_likelihood']
            assert len(analysis['remediation_steps']) == len(TEST_ANALYSIS_RESPONSE['remediation_steps'])
            assert len(analysis['additional_insights']) == len(TEST_ANALYSIS_RESPONSE['additional_insights'])
            
            # Verify monitoring
            assert ai_service._monitoring_service.get_analysis_count() == 1
    
    @pytest.mark.asyncio
    async def test_openai_integration(self, openai_service):
        """Test OpenAI service integration."""
        mock_api_response = {
            'choices': [{
                'message': {
                    'content': json.dumps(TEST_ANALYSIS_RESPONSE)
                }
            }]
        }
        
        with patch('openai.ChatCompletion.create',
                  new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_api_response
            
            # Test analysis
            analysis = await openai_service.analyze(TEST_FINDING)
            
            # Verify analysis
            assert analysis == TEST_ANALYSIS_RESPONSE
            
            # Verify API call
            mock_create.assert_called_once()
            call_args = mock_create.call_args[1]
            assert 'messages' in call_args
            assert len(call_args['messages']) > 0
            assert TEST_FINDING['title'] in call_args['messages'][0]['content']
    
    @pytest.mark.asyncio
    async def test_response_processing(self, ai_service):
        """Test analysis response processing."""
        test_cases = [
            {
                'input': TEST_ANALYSIS_RESPONSE,
                'expected': TEST_ANALYSIS_RESPONSE
            },
            {
                'input': {
                    'severity': 'critical',
                    'false_positive_likelihood': 0.0,
                    'remediation_steps': ['Fix immediately'],
                    'additional_insights': ['Critical vulnerability']
                },
                'expected': {
                    'severity': 'critical',
                    'false_positive_likelihood': 0.0,
                    'remediation_steps': ['Fix immediately'],
                    'additional_insights': ['Critical vulnerability']
                }
            }
        ]
        
        for case in test_cases:
            processed = await ai_service._process_analysis_response(case['input'])
            assert processed == case['expected']

# Error Handling Tests
class TestErrorHandling:
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_api_errors(self, ai_service):
        """Test handling of API errors."""
        with patch.object(ai_service._openai_service, 'analyze',
                         new_callable=AsyncMock) as mock_analyze:
            mock_analyze.side_effect = AIServiceError("API error")
            
            with pytest.raises(AIServiceError) as exc_info:
                await ai_service.analyze_finding(TEST_FINDING)
            assert 'API error' in str(exc_info.value)
            
            # Verify error tracking
            assert ai_service._monitoring_service.get_error_count() == 1
    
    @pytest.mark.asyncio
    async def test_invalid_inputs(self, ai_service):
        """Test handling of invalid inputs."""
        invalid_inputs = [
            {},
            {'title': 'Test'},
            {'type': 'vulnerability'},
            None,
            ''
        ]
        
        for input_data in invalid_inputs:
            with pytest.raises(ValueError) as exc_info:
                await ai_service.analyze_finding(input_data)
            assert 'invalid input' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_service_state(self, ai_service):
        """Test service state management."""
        # Test uninitialized service
        await ai_service.cleanup()
        with pytest.raises(AIServiceError) as exc_info:
            await ai_service.analyze_finding(TEST_FINDING)
        assert 'not initialized' in str(exc_info.value).lower()
        
        # Test re-initialization
        await ai_service.initialize()
        assert ai_service._initialized
        
        # Test double initialization
        with pytest.raises(AIServiceError) as exc_info:
            await ai_service.initialize()
        assert 'already initialized' in str(exc_info.value).lower()

# Monitoring Tests
class TestMonitoring:
    """Tests for monitoring functionality."""
    
    @pytest.mark.asyncio
    async def test_metrics_tracking(self, monitoring_service):
        """Test metrics tracking functionality."""
        # Test analysis tracking
        for _ in range(3):
            monitoring_service.track_analysis()
        assert monitoring_service.get_analysis_count() == 3
        
        # Test error tracking
        for _ in range(2):
            monitoring_service.track_error()
        assert monitoring_service.get_error_count() == 2
        
        # Test performance tracking
        async def test_operation():
            await asyncio.sleep(0.1)
        
        await monitoring_service.track_performance('test_op', test_operation)
        metrics = monitoring_service.get_performance_metrics()
        assert 'test_op' in metrics
        assert metrics['test_op']['count'] == 1
        assert metrics['test_op']['avg_duration'] > 0
    
    @pytest.mark.asyncio
    async def test_alert_generation(self, monitoring_service):
        """Test alert generation functionality."""
        # Generate alerts
        for _ in range(TEST_CONFIG['monitoring']['alert_threshold'] + 1):
            monitoring_service.track_error()
        
        # Verify alerts
        alerts = monitoring_service.get_alerts()
        assert len(alerts) > 0
        
        threshold_alerts = [a for a in alerts if a['type'] == 'error_threshold']
        assert len(threshold_alerts) > 0
        
        for alert in threshold_alerts:
            assert alert['severity'] in ['high', 'critical']
            assert 'threshold' in alert['data']
            assert 'count' in alert['data']
    
    @pytest.mark.asyncio
    async def test_metrics_reset(self, monitoring_service):
        """Test metrics reset functionality."""
        # Track some metrics
        monitoring_service.track_analysis()
        monitoring_service.track_error()
        await monitoring_service.track_performance('test_op', lambda: asyncio.sleep(0.1))
        
        # Reset metrics
        monitoring_service.reset_metrics()
        
        # Verify reset
        assert monitoring_service.get_analysis_count() == 0
        assert monitoring_service.get_error_count() == 0
        metrics = monitoring_service.get_performance_metrics()
        assert not metrics

# Integration Tests
class TestIntegration:
    """Tests for service integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_analysis(self, ai_service):
        """Test end-to-end analysis workflow."""
        with patch.object(ai_service._openai_service, 'analyze',
                         new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = TEST_ANALYSIS_RESPONSE
            
            # Perform analysis
            analysis = await ai_service.analyze_finding(TEST_FINDING)
            
            # Verify complete workflow
            assert analysis == TEST_ANALYSIS_RESPONSE
            assert ai_service._monitoring_service.get_analysis_count() == 1
            assert ai_service._monitoring_service.get_error_count() == 0
            
            metrics = ai_service._monitoring_service.get_performance_metrics()
            assert 'analysis' in metrics
            assert metrics['analysis']['count'] == 1
            assert metrics['analysis']['avg_duration'] > 0
    
    @pytest.mark.asyncio
    async def test_service_interaction(self, ai_service, openai_service, monitoring_service):
        """Test interaction between services."""
        # Configure services
        ai_service._openai_service = openai_service
        ai_service._monitoring_service = monitoring_service
        
        # Test service interaction
        with patch.object(openai_service, 'analyze',
                         new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = TEST_ANALYSIS_RESPONSE
            
            # Perform analysis
            analysis = await ai_service.analyze_finding(TEST_FINDING)
            
            # Verify service interaction
            assert analysis == TEST_ANALYSIS_RESPONSE
            assert monitoring_service.get_analysis_count() == 1
            assert openai_service._initialized
            assert monitoring_service._initialized 