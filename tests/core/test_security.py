"""
Tests for the security module.

This module contains comprehensive test cases for the SecurityManager class,
verifying input validation, sanitization, access control, and security monitoring.
Tests are organized into categories: basic functionality, input validation,
sanitization, access control, and monitoring.

Test Categories:
- Basic Functionality: Manager initialization, configuration, and cleanup
- Input Validation: URL validation, input validation, pattern matching
- Sanitization: Input sanitization, URL sanitization, query parameter sanitization
- Access Control: Rate limiting, client management, access rules
- Monitoring: Security event tracking, alert generation, metrics collection

Each test category focuses on specific aspects of the security system:
1. Basic Functionality: Core security features and configuration
2. Input Validation: Protection against malicious inputs
3. Sanitization: Data cleaning and normalization
4. Access Control: Resource access management
5. Monitoring: Security event tracking and response
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import re
import json
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urlparse, parse_qs

from bbf.core.security import SecurityManager
from bbf.core.exceptions import SecurityError

# Test Configuration
TEST_CONFIG = {
    'max_input_length': 1000,
    'allowed_schemes': ['http', 'https'],
    'allowed_hosts': ['example.com', 'test.com'],
    'blocked_patterns': [
        r'\.\./',  # Directory traversal
        r'<script>',  # XSS
        r'UNION\s+SELECT',  # SQL injection
        r'exec\s*\('  # Command injection
    ],
    'rate_limits': {
        'requests_per_second': 10,
        'burst_limit': 20,
        'window_size': 60  # seconds
    },
    'access_rules': {
        'default': {
            'allowed_methods': ['GET', 'POST'],
            'max_payload_size': 1024 * 1024,  # 1MB
            'require_auth': False
        },
        'admin': {
            'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE'],
            'max_payload_size': 10 * 1024 * 1024,  # 10MB
            'require_auth': True
        }
    },
    'monitoring': {
        'enable_logging': True,
        'alert_threshold': 5,
        'metrics_interval': 60  # seconds
    }
}

# Test Data
TEST_URLS = [
    'http://example.com/path',
    'https://test.com/api/v1',
    'http://example.com/path?param=value',
    'https://test.com/api/v1?q=test&page=1'
]

TEST_INPUTS = [
    'normal input',
    '<script>alert("xss")</script>',
    '../../../etc/passwd',
    "'; DROP TABLE users; --",
    'normal/path/file.txt',
    'http://example.com/path?param=<script>alert(1)</script>'
]

TEST_PAYLOADS = [
    {'type': 'normal', 'data': '{"key": "value"}'},
    {'type': 'xss', 'data': '<script>alert(1)</script>'},
    {'type': 'sql', 'data': "'; DROP TABLE users; --"},
    {'type': 'cmd', 'data': 'exec(system("rm -rf /"))'},
    {'type': 'large', 'data': 'x' * (TEST_CONFIG['access_rules']['default']['max_payload_size'] + 1)}
]

# Test Fixtures
@pytest.fixture
async def security_manager():
    """
    Create and initialize a SecurityManager instance for testing.
    
    This fixture ensures proper setup and cleanup of the security manager
    for each test case. It also verifies that the manager is properly
    initialized before use and cleaned up after use.
    
    Returns:
        SecurityManager: An initialized security manager instance.
    """
    manager = SecurityManager(TEST_CONFIG)
    await manager.initialize()
    yield manager
    await manager.cleanup()

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic security manager functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, security_manager):
        """Test security manager initialization and configuration."""
        assert security_manager._initialized
        assert security_manager._rate_limiter is not None
        assert len(security_manager._blocked_patterns) == len(TEST_CONFIG['blocked_patterns'])
        assert security_manager._max_input_length == TEST_CONFIG['max_input_length']
        assert security_manager._allowed_schemes == TEST_CONFIG['allowed_schemes']
        assert security_manager._allowed_hosts == TEST_CONFIG['allowed_hosts']
        assert security_manager._access_rules == TEST_CONFIG['access_rules']
        assert security_manager._monitoring_config == TEST_CONFIG['monitoring']
    
    @pytest.mark.asyncio
    async def test_cleanup(self, security_manager):
        """Test security manager cleanup."""
        await security_manager.cleanup()
        assert not security_manager._initialized
        assert security_manager._rate_limiter is None
        assert not security_manager._blocked_patterns
    
    @pytest.mark.asyncio
    async def test_configuration_validation(self, security_manager):
        """Test security manager configuration validation."""
        # Test valid configuration
        assert await security_manager.validate_configuration(TEST_CONFIG)
        
        # Test invalid configurations
        invalid_configs = [
            {'max_input_length': -1},
            {'allowed_schemes': []},
            {'allowed_hosts': []},
            {'rate_limits': {'requests_per_second': 0}},
            {'access_rules': {'default': {'max_payload_size': -1}}}
        ]
        
        for config in invalid_configs:
            with pytest.raises(SecurityError) as exc_info:
                await security_manager.validate_configuration(config)
            assert 'invalid configuration' in str(exc_info.value).lower()

# Input Validation Tests
class TestInputValidation:
    """Tests for input validation functionality."""
    
    @pytest.mark.asyncio
    async def test_url_validation(self, security_manager):
        """Test URL validation functionality."""
        # Test valid URLs
        for url in TEST_URLS:
            assert await security_manager.validate_url(url)
            parsed = await security_manager.parse_url(url)
            assert parsed.scheme in TEST_CONFIG['allowed_schemes']
            assert parsed.netloc in TEST_CONFIG['allowed_hosts']
            assert parsed.path.startswith('/')
        
        # Test invalid URLs
        invalid_urls = [
            'ftp://example.com',  # Invalid scheme
            'http://malicious.com',  # Invalid host
            'not-a-url',
            'http://',  # Incomplete URL
            'https://example.com:99999',  # Invalid port
            None,
            '',
            'http://example.com/<script>alert(1)</script>'  # Contains blocked pattern
        ]
        
        for url in invalid_urls:
            with pytest.raises(SecurityError) as exc_info:
                await security_manager.validate_url(url)
            assert 'invalid url' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_input_validation(self, security_manager):
        """Test general input validation functionality."""
        # Test valid inputs
        valid_inputs = [
            'normal input',
            'normal/path/file.txt',
            'http://example.com/path?param=value',
            '{"json": "data"}',
            'application/json'
        ]
        
        for input_str in valid_inputs:
            assert await security_manager.validate_input(input_str)
        
        # Test invalid inputs
        invalid_inputs = [
            '<script>alert("xss")</script>',  # XSS
            '../../../etc/passwd',  # Directory traversal
            "'; DROP TABLE users; --",  # SQL injection
            'exec(system("rm -rf /"))',  # Command injection
            'x' * (TEST_CONFIG['max_input_length'] + 1),  # Too long
            None,
            ''
        ]
        
        for input_str in invalid_inputs:
            with pytest.raises(SecurityError) as exc_info:
                await security_manager.validate_input(input_str)
            assert 'invalid input' in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_pattern_matching(self, security_manager):
        """Test pattern matching functionality."""
        # Test blocked patterns
        blocked_inputs = [
            '<script>alert(1)</script>',
            '../../../etc/passwd',
            "'; DROP TABLE users; --",
            'exec(system("rm -rf /"))',
            'UNION SELECT * FROM users',
            'eval(base64_decode("..."))'
        ]
        
        for input_str in blocked_inputs:
            assert await security_manager.contains_blocked_pattern(input_str)
            with pytest.raises(SecurityError) as exc_info:
                await security_manager.validate_input(input_str)
            assert 'blocked pattern' in str(exc_info.value).lower()
        
        # Test allowed patterns
        allowed_inputs = [
            'normal input',
            'normal/path/file.txt',
            'http://example.com/path?param=value',
            '{"json": "data"}',
            'application/json'
        ]
        
        for input_str in allowed_inputs:
            assert not await security_manager.contains_blocked_pattern(input_str)
            assert await security_manager.validate_input(input_str)
        
        # Test custom pattern
        custom_pattern = r'custom\s+pattern'
        await security_manager.add_blocked_pattern(custom_pattern)
        assert await security_manager.contains_blocked_pattern('custom pattern')
        assert not await security_manager.contains_blocked_pattern('normal pattern')

# Sanitization Tests
class TestSanitization:
    """Tests for input sanitization functionality."""
    
    @pytest.mark.asyncio
    async def test_input_sanitization(self, security_manager):
        """Test general input sanitization."""
        test_cases = [
            ('<script>alert("xss")</script>', 'alert("xss")'),
            ('../../../etc/passwd', 'etc/passwd'),
            ("'; DROP TABLE users; --", "DROP TABLE users; --"),
            ('normal/path/file.txt', 'normal/path/file.txt'),
            ('http://example.com/path?param=<script>alert(1)</script>',
             'http://example.com/path?param=alert(1)'),
            ('{"json": "<script>alert(1)</script>"}',
             '{"json": "alert(1)"}'),
            ('application/json<script>alert(1)</script>',
             'application/jsonalert(1)')
        ]
        
        for input_str, expected in test_cases:
            sanitized = await security_manager.sanitize_input(input_str)
            assert sanitized == expected
            assert not await security_manager.contains_blocked_pattern(sanitized)
    
    @pytest.mark.asyncio
    async def test_url_sanitization(self, security_manager):
        """Test URL sanitization."""
        for url in TEST_URLS:
            sanitized = await security_manager.sanitize_url(url)
            parsed = urlparse(sanitized)
            
            # Verify scheme and host
            assert parsed.scheme in TEST_CONFIG['allowed_schemes']
            assert parsed.netloc in TEST_CONFIG['allowed_hosts']
            
            # Verify path sanitization
            assert not any(pattern in parsed.path 
                         for pattern in TEST_CONFIG['blocked_patterns'])
            
            # Verify query parameter sanitization
            if parsed.query:
                params = parse_qs(parsed.query)
                for value in params.values():
                    assert not any(re.search(pattern, value[0])
                                 for pattern in TEST_CONFIG['blocked_patterns'])
    
    @pytest.mark.asyncio
    async def test_payload_sanitization(self, security_manager):
        """Test payload sanitization."""
        for payload in TEST_PAYLOADS:
            if payload['type'] == 'normal':
                sanitized = await security_manager.sanitize_payload(payload['data'])
                assert sanitized == payload['data']
            else:
                sanitized = await security_manager.sanitize_payload(payload['data'])
                assert sanitized != payload['data']
                assert not await security_manager.contains_blocked_pattern(sanitized)

# Access Control Tests
class TestAccessControl:
    """Tests for access control functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, security_manager):
        """Test rate limiting functionality."""
        # Test normal rate limit
        for _ in range(TEST_CONFIG['rate_limits']['requests_per_second']):
            assert await security_manager.check_rate_limit('test_client')
        
        # Test burst limit
        for _ in range(TEST_CONFIG['rate_limits']['burst_limit']):
            assert await security_manager.check_rate_limit('test_client')
        
        # Test exceeding rate limit
        with pytest.raises(SecurityError) as exc_info:
            await security_manager.check_rate_limit('test_client')
        assert 'rate limit exceeded' in str(exc_info.value).lower()
        
        # Test different clients
        assert await security_manager.check_rate_limit('client_1')
        assert await security_manager.check_rate_limit('client_2')
        
        # Test rate limit reset
        await asyncio.sleep(1)  # Wait for rate limit window to reset
        assert await security_manager.check_rate_limit('test_client')
    
    @pytest.mark.asyncio
    async def test_access_rules(self, security_manager):
        """Test access rule enforcement."""
        # Test default access rules
        assert await security_manager.check_access('default', 'GET', 1024)
        assert await security_manager.check_access('default', 'POST', 1024)
        assert not await security_manager.check_access('default', 'PUT', 1024)
        assert not await security_manager.check_access('default', 'DELETE', 1024)
        
        # Test admin access rules
        assert await security_manager.check_access('admin', 'GET', 1024)
        assert await security_manager.check_access('admin', 'POST', 1024)
        assert await security_manager.check_access('admin', 'PUT', 1024)
        assert await security_manager.check_access('admin', 'DELETE', 1024)
        
        # Test payload size limits
        with pytest.raises(SecurityError) as exc_info:
            await security_manager.check_access('default', 'POST', 
                                             TEST_CONFIG['access_rules']['default']['max_payload_size'] + 1)
        assert 'payload too large' in str(exc_info.value).lower()
        
        # Test authentication requirements
        assert not await security_manager.check_access('admin', 'GET', 1024, auth=False)
        assert await security_manager.check_access('admin', 'GET', 1024, auth=True)

# Monitoring Tests
class TestMonitoring:
    """Tests for security monitoring functionality."""
    
    @pytest.mark.asyncio
    async def test_event_tracking(self, security_manager):
        """Test security event tracking."""
        # Track various events
        events = [
            ('url_validation', 'http://example.com'),
            ('input_validation', 'normal input'),
            ('rate_limit', 'test_client'),
            ('access_control', 'admin:GET'),
            ('pattern_match', '<script>alert(1)</script>')
        ]
        
        for event_type, event_data in events:
            await security_manager.track_event(event_type, event_data)
        
        # Verify event tracking
        tracked_events = await security_manager.get_events()
        assert len(tracked_events) == len(events)
        
        for event in tracked_events:
            assert 'timestamp' in event
            assert 'type' in event
            assert 'data' in event
    
    @pytest.mark.asyncio
    async def test_alert_generation(self, security_manager):
        """Test security alert generation."""
        # Generate alerts for various conditions
        alert_conditions = [
            ('rate_limit_exceeded', 'test_client'),
            ('blocked_pattern', '<script>alert(1)</script>'),
            ('invalid_url', 'ftp://example.com'),
            ('large_payload', 'x' * 1024 * 1024),
            ('unauthorized_access', 'admin:DELETE')
        ]
        
        for alert_type, alert_data in alert_conditions:
            await security_manager.generate_alert(alert_type, alert_data)
        
        # Verify alert generation
        alerts = await security_manager.get_alerts()
        assert len(alerts) == len(alert_conditions)
        
        for alert in alerts:
            assert 'timestamp' in alert
            assert 'type' in alert
            assert 'data' in alert
            assert 'severity' in alert
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, security_manager):
        """Test security metrics collection."""
        # Collect metrics for various operations
        operations = [
            ('url_validation', 100),
            ('input_validation', 200),
            ('rate_limit', 50),
            ('access_control', 75),
            ('pattern_match', 25)
        ]
        
        for op_type, count in operations:
            for _ in range(count):
                await security_manager.track_metric(op_type)
        
        # Verify metrics collection
        metrics = await security_manager.get_metrics()
        assert len(metrics) == len(operations)
        
        for metric in metrics:
            assert 'type' in metric
            assert 'count' in metric
            assert 'timestamp' in metric
            assert metric['count'] > 0
    
    @pytest.mark.asyncio
    async def test_threshold_monitoring(self, security_manager):
        """Test security threshold monitoring."""
        # Generate events that should trigger thresholds
        for _ in range(TEST_CONFIG['monitoring']['alert_threshold'] + 1):
            await security_manager.track_event('rate_limit_exceeded', 'test_client')
        
        # Verify threshold monitoring
        alerts = await security_manager.get_alerts()
        assert len(alerts) > 0
        
        threshold_alerts = [a for a in alerts if a['type'] == 'threshold_exceeded']
        assert len(threshold_alerts) > 0
        
        for alert in threshold_alerts:
            assert alert['severity'] in ['high', 'critical']
            assert 'threshold' in alert['data']
            assert 'count' in alert['data'] 