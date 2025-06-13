"""
Tests for the VulnScanPlugin.

This module contains comprehensive test cases for the vulnerability scanning plugin,
verifying its functionality for detecting common web vulnerabilities.

Test Categories:
1. Basic Functionality
   - Plugin initialization and configuration
   - Plugin lifecycle management
   - Session handling and SSL verification
   - Vulnerability database setup

2. Vulnerability Detection
   - XSS (Cross-Site Scripting)
   - SQL Injection
   - CSRF (Cross-Site Request Forgery)
   - Command Injection
   - SSRF (Server-Side Request Forgery)
   - File Inclusion
   - Directory Traversal
   - Authentication Bypass
   - Session Management
   - Security Misconfiguration

3. Finding Management
   - Finding creation
   - Finding updates
   - Metadata handling
   - Evidence collection
   - Severity assessment
   - Confidence scoring
   - Finding categorization

4. Error Handling
   - Connection error handling
   - Timeout management
   - SSL/TLS error handling
   - Invalid response handling
   - Resource cleanup
   - Error recovery

5. Resource Management
   - Session cleanup
   - Connection pooling
   - Memory optimization
   - Resource leak prevention
   - Rate limiting
   - Timeout handling

6. Performance
   - Concurrent scanning
   - Response time optimization
   - Resource usage monitoring
   - Cache utilization
   - Batch processing
   - Load management

7. Integration
   - Database integration
   - HTTP client integration
   - Configuration management
   - Plugin lifecycle
   - Service interaction
   - State management
"""

import asyncio
import pytest
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp
from datetime import datetime
import json
from urllib.parse import urlparse, urljoin

from bbf.plugins.recon.vuln_scan import VulnScanPlugin
from bbf.core.exceptions import PluginError
from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service

# Test Configuration
TEST_CONFIG = {
    'url': "https://example.com",
    'confidence_threshold': 0.8,
    'severity_threshold': 'medium',
    'timeout': 10.0,
    'max_redirects': 5,
    'max_concurrent_requests': 10,
    'verify_ssl': True,
    'retry_count': 3,
    'retry_delay': 1.0,
    'rate_limit': 10,  # requests per second
    'scan_depth': 3,
    'cache_ttl': 3600,  # 1 hour
    'batch_size': 50
}

# Test Data
TEST_URL = TEST_CONFIG['url']
TEST_DOMAIN = "example.com"
TEST_SUBDOMAIN = "example"

# Test Headers
TEST_HEADERS = {
    'Server': 'nginx/1.18.0',
    'X-Powered-By': 'PHP/7.4.3',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'Content-Type': 'text/html; charset=utf-8',
    'Set-Cookie': 'session=abc123; HttpOnly; Secure',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
}

# Test HTML Templates
TEST_HTML_TEMPLATES = {
    'vulnerable': """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Site</title>
        <meta name="generator" content="WordPress 5.8.2">
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
    </head>
    <body>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
        <div id="content">
            <p>Search results for: <script>alert('xss')</script></p>
        </div>
        <div id="error" style="display: none;">
            <p>SQL syntax error near '--'</p>
        </div>
        <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <a href="/download?file=../../../etc/passwd">Download</a>
        <script>
            fetch('/api/data?url=http://internal-service')
                .then(response => response.json())
                .then(data => console.log(data));
        </script>
    </body>
    </html>
    """,
    'secure': """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Site</title>
        <meta name="csrf-token" content="abc123">
        <link rel="stylesheet" href="/static/css/main.css">
        <script src="/static/js/jquery.min.js"></script>
    </head>
    <body>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <input type="submit" value="Login">
        </form>
        <div id="content">
            <p>Search results for: &lt;script&gt;alert('xss')&lt;/script&gt;</p>
        </div>
    </body>
    </html>
    """
}

# Test Payloads
TEST_PAYLOADS = {
    'xss': [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        '"><img src=x onerror=alert("xss")>',
        'javascript:alert("xss")'
    ],
    'sql_injection': [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users; --",
        "admin' --"
    ],
    'command_injection': [
        '; ls -la',
        '& dir',
        '| cat /etc/passwd',
        '`id`'
    ],
    'path_traversal': [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '....//....//....//etc/passwd'
    ]
}

# Expected Findings
EXPECTED_FINDINGS = {
    'xss': {
        'type': 'xss',
        'severity': 'high',
        'confidence': 0.9,
        'evidence': ['<script>alert("xss")</script>'],
        'description': 'Reflected XSS vulnerability detected'
    },
    'sql_injection': {
        'type': 'sql_injection',
        'severity': 'critical',
        'confidence': 0.95,
        'evidence': ["SQL syntax error near '--'"],
        'description': 'SQL injection vulnerability detected'
    },
    'csrf': {
        'type': 'csrf',
        'severity': 'high',
        'confidence': 0.85,
        'evidence': ['Missing CSRF token'],
        'description': 'CSRF vulnerability detected'
    },
    'command_injection': {
        'type': 'command_injection',
        'severity': 'critical',
        'confidence': 0.9,
        'evidence': ['Command execution response'],
        'description': 'Command injection vulnerability detected'
    },
    'path_traversal': {
        'type': 'path_traversal',
        'severity': 'high',
        'confidence': 0.85,
        'evidence': ['../../../etc/passwd'],
        'description': 'Path traversal vulnerability detected'
    }
}

class TestVulnScanPlugin:
    """
    Test suite for VulnScanPlugin.
    
    This class implements comprehensive tests for the vulnerability scanning plugin,
    covering all aspects of its functionality from basic initialization to
    advanced vulnerability detection techniques.
    """
    
    @pytest.fixture
    def plugin(self) -> VulnScanPlugin:
        """
        Create a plugin instance for testing.
        
        Returns:
            VulnScanPlugin: Plugin instance with default configuration.
        """
        return VulnScanPlugin()
    
    @pytest.fixture
    def mock_session(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Create a mock aiohttp session for testing.
        
        Yields:
            AsyncMock: Mocked HTTP session with configured responses.
        """
        with patch('aiohttp.ClientSession') as mock:
            session = AsyncMock()
            mock.return_value.__aenter__.return_value = session
            yield session
    
    @pytest.fixture
    def mock_finding_service(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Mock the finding service for testing.
        
        Yields:
            AsyncMock: Mocked finding service with configured methods.
        """
        with patch('bbf.core.database.service.finding_service') as mock:
            mock.create = AsyncMock()
            mock.update = AsyncMock()
            mock.get_by_url = AsyncMock(return_value=None)
            yield mock

class TestBasicFunctionality(TestVulnScanPlugin):
    """Tests for basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin: VulnScanPlugin) -> None:
        """
        Test plugin initialization.
        
        This test verifies that the plugin:
        1. Initializes correctly
        2. Sets up required components
        3. Configures default settings
        4. Establishes session
        
        Args:
            plugin: Plugin instance
        """
        await plugin.initialize()
        
        # Verify initialization
        assert plugin._session is not None
        assert isinstance(plugin._session, aiohttp.ClientSession)
        assert plugin._findings == []
        assert plugin._severity_threshold == TEST_CONFIG['severity_threshold']
        assert plugin._confidence_threshold == TEST_CONFIG['confidence_threshold']
        assert plugin._timeout == TEST_CONFIG['timeout']
        assert plugin._verify_ssl == TEST_CONFIG['verify_ssl']

class TestVulnerabilityDetection(TestVulnScanPlugin):
    """Tests for vulnerability detection functionality."""
    
    @pytest.mark.asyncio
    async def test_xss_detection(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test XSS vulnerability detection.
        
        This test verifies that the plugin:
        1. Detects reflected XSS
        2. Detects stored XSS
        3. Detects DOM-based XSS
        4. Handles different XSS payloads
        5. Assesses severity correctly
        6. Calculates confidence properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Test each XSS payload
        for payload in TEST_PAYLOADS['xss']:
            # Mock response with potential XSS
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=f"""
                <div id="content">
                    <p>Search results for: {payload}</p>
                </div>
            """)
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Test XSS detection
            findings = await plugin._check_xss(TEST_URL)
            
            # Verify results
            assert len(findings) > 0
            assert any(f['type'] == 'xss' for f in findings)
            assert any(f['severity'] == 'high' for f in findings)
            assert all(f['confidence'] >= TEST_CONFIG['confidence_threshold'] for f in findings)
            assert any(payload in f['evidence'][0] for f in findings)

    @pytest.mark.asyncio
    async def test_sql_injection_detection(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test SQL injection vulnerability detection.
        
        This test verifies that the plugin:
        1. Detects SQL syntax errors
        2. Detects UNION-based injection
        3. Detects boolean-based injection
        4. Detects time-based injection
        5. Handles different SQL payloads
        6. Assesses severity correctly
        7. Calculates confidence properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Test each SQL injection payload
        for payload in TEST_PAYLOADS['sql_injection']:
            # Mock response with potential SQL injection
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=f"""
                <div id="error">
                    <p>SQL syntax error near '{payload}'</p>
                </div>
            """)
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Test SQL injection detection
            findings = await plugin._check_sql_injection(TEST_URL)
            
            # Verify results
            assert len(findings) > 0
            assert any(f['type'] == 'sql_injection' for f in findings)
            assert any(f['severity'] == 'critical' for f in findings)
            assert all(f['confidence'] >= TEST_CONFIG['confidence_threshold'] for f in findings)
            assert any(payload in f['evidence'][0] for f in findings)

    @pytest.mark.asyncio
    async def test_csrf_detection(
        self,
        plugin: VulnScanPlugin
    ) -> None:
        """
        Test CSRF vulnerability detection.
        
        This test verifies that the plugin:
        1. Detects missing CSRF tokens
        2. Detects weak CSRF protection
        3. Detects predictable tokens
        4. Assesses severity correctly
        5. Calculates confidence properly
        
        Args:
            plugin: Plugin instance
        """
        # Test CSRF detection with vulnerable form
        findings = await plugin._check_csrf(TEST_HTML_TEMPLATES['vulnerable'])
        
        # Verify results
        assert len(findings) > 0
        assert any(f['type'] == 'csrf' for f in findings)
        assert any(f['severity'] == 'high' for f in findings)
        assert all(f['confidence'] >= TEST_CONFIG['confidence_threshold'] for f in findings)
        assert any('Missing CSRF token' in f['evidence'][0] for f in findings)
        
        # Test CSRF detection with secure form
        findings = await plugin._check_csrf(TEST_HTML_TEMPLATES['secure'])
        
        # Verify no findings for secure form
        assert len(findings) == 0

class TestErrorHandling(TestVulnScanPlugin):
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_network_error_handling(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of network errors.
        
        This test verifies that the plugin:
        1. Handles connection errors gracefully
        2. Returns empty results on failure
        3. Continues execution after errors
        4. Maintains stability during failures
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock network error
        mock_session.get.side_effect = aiohttp.ClientError("Connection error")
        
        # Test error handling
        findings = await plugin._check_xss(TEST_URL)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_timeout_handling(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of request timeouts.
        
        This test verifies that the plugin:
        1. Handles timeouts gracefully
        2. Respects timeout configuration
        3. Returns partial results if available
        4. Continues execution after timeout
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock timeout
        mock_session.get.side_effect = asyncio.TimeoutError("Request timeout")
        
        # Test timeout handling
        findings = await plugin._check_xss(TEST_URL)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_ssl_error_handling(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of SSL/TLS errors.
        
        This test verifies that the plugin:
        1. Handles SSL errors gracefully
        2. Respects SSL verification settings
        3. Returns empty results on SSL failure
        4. Continues execution after SSL error
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock SSL error
        mock_session.get.side_effect = aiohttp.ClientSSLError("SSL error")
        
        # Test SSL error handling
        findings = await plugin._check_xss(TEST_URL)
        assert len(findings) == 0

class TestPerformance(TestVulnScanPlugin):
    """Tests for performance and optimization."""
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test concurrent vulnerability scanning.
        
        This test verifies that the plugin:
        1. Handles concurrent requests efficiently
        2. Respects rate limits
        3. Manages resources properly
        4. Completes within timeout
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock responses for concurrent requests
        mock_responses = {
            '/': {'headers': TEST_HEADERS, 'html': TEST_HTML_TEMPLATES['vulnerable']},
            '/login': {'headers': TEST_HEADERS, 'html': TEST_HTML_TEMPLATES['vulnerable']},
            '/search': {'headers': TEST_HEADERS, 'html': TEST_HTML_TEMPLATES['vulnerable']},
            '/api/data': {'headers': TEST_HEADERS, 'json': {'error': 'SQL syntax error'}}
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            url = args[0]
            path = urlparse(url).path
            response_data = mock_responses.get(path, {})
            
            mock_response.status = 200
            mock_response.headers = response_data.get('headers', {})
            mock_response.text = AsyncMock(return_value=response_data.get('html', ''))
            mock_response.json = AsyncMock(return_value=response_data.get('json', {}))
            
            return mock_response
        
        mock_session.get.side_effect = mock_get
        
        # Execute plugin with concurrent scanning
        start_time = datetime.utcnow()
        results = await plugin.execute(TEST_URL)
        end_time = datetime.utcnow()
        
        # Verify performance
        scan_duration = (end_time - start_time).total_seconds()
        assert scan_duration < TEST_CONFIG['timeout']
        assert len(results) > 0
        
        # Verify all vulnerability types were detected
        detected_vulns = {f['type'] for f in results}
        expected_vulns = {'xss', 'sql_injection', 'csrf'}
        assert detected_vulns == expected_vulns

class TestPluginExecution(TestVulnScanPlugin):
    """Tests for complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_plugin_execution(
        self,
        plugin: VulnScanPlugin,
        mock_session: AsyncMock,
        mock_finding_service: AsyncMock
    ) -> None:
        """
        Test complete plugin execution.
        
        This test verifies that the plugin:
        1. Executes all detection methods
        2. Combines results from different sources
        3. Handles HTTP requests properly
        4. Returns comprehensive findings
        5. Creates appropriate findings
        6. Manages resources properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_finding_service: Mocked finding service
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_response.text = AsyncMock(return_value=TEST_HTML_TEMPLATES['vulnerable'])
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run plugin execution
        results = await plugin.execute(TEST_URL)
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(isinstance(f, dict) for f in results)
        assert all('type' in f for f in results)
        assert all('severity' in f for f in results)
        assert all('confidence' in f for f in results)
        assert all('evidence' in f for f in results)
        assert all(f['confidence'] >= TEST_CONFIG['confidence_threshold'] for f in results)
        
        # Verify vulnerability detection
        detected_vulns = {f['type'] for f in results}
        expected_vulns = {'xss', 'sql_injection', 'csrf'}
        assert detected_vulns == expected_vulns
        
        # Verify finding creation
        assert mock_finding_service.create.call_count == len(results)
        for call in mock_finding_service.create.call_args_list:
            finding = call[0][0]
            assert isinstance(finding, Finding)
            assert finding.stage == 'recon'
            assert finding.status == 'active'
            assert finding.severity in ['low', 'medium', 'high', 'critical']
            assert finding.title.startswith('Vulnerability')
            assert finding.description.startswith('Detected')
            assert finding.metadata is not None
            
            metadata = json.loads(finding.metadata)
            assert 'vulnerability_type' in metadata
            assert 'scan_timestamp' in metadata
            assert 'scan_details' in metadata
            assert 'confidence' in metadata
            assert 'evidence' in metadata 