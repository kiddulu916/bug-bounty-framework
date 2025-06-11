"""
Test suite for the Vulnerability Scanner Plugin.

This module contains tests for the VulnerabilityScannerPlugin class, including:
- Plugin initialization
- Security header checks
- SSL/TLS checks
- XSS detection
- SQL injection detection
- CSRF protection checks
- Misconfiguration detection
- Error handling
- Resource cleanup
"""

import asyncio
import pytest
import ssl
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime, timedelta

from bbf.plugins.recon.vuln_scan import (
    VulnerabilityScannerPlugin,
    Vulnerability,
    VulnCategory
)
from bbf.core.plugin import PluginError
from bbf.core.types import ScanResult, ScanStatus

# Test data
TEST_URL = "http://example.com"
TEST_HTTPS_URL = "https://example.com"
TEST_HTML = """
<html>
    <form action="/submit" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    <form action="/update" method="post">
        <input type="text" name="data">
        <input type="submit" value="Update">
    </form>
</html>
"""
TEST_HTML_WITH_CSRF = """
<html>
    <form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="text" name="username">
        <input type="submit" value="Login">
    </form>
</html>
"""
TEST_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "Referrer-Policy": "strict-origin-when-cross-origin"
}
TEST_HEADERS_MISSING = {
    "X-Content-Type-Options": "nosniff"
}
TEST_HEADERS_HSTS_DISABLED = {
    "Strict-Transport-Security": "max-age=0"
}

@pytest.fixture
async def plugin():
    """Create a VulnerabilityScannerPlugin instance for testing."""
    plugin = VulnerabilityScannerPlugin()
    yield plugin
    await plugin.cleanup()

@pytest.fixture
def mock_session():
    """Create a mock aiohttp.ClientSession."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    return session

@pytest.fixture
def mock_response():
    """Create a mock aiohttp.ClientResponse."""
    response = AsyncMock(spec=aiohttp.ClientResponse)
    response.headers = {}
    response.status = 200
    return response

@pytest.mark.asyncio
async def test_plugin_initialization():
    """Test plugin initialization with default and custom config."""
    # Test with default config
    plugin = VulnerabilityScannerPlugin()
    assert plugin.name == "vulnerability_scanner"
    assert plugin.description == "Scans web applications for common vulnerabilities"
    assert plugin.version == "1.0.0"
    assert plugin.enabled is True
    assert plugin.timeout == 30
    assert plugin.max_redirects == 5
    assert plugin.user_agent == "BBF/1.0"
    assert plugin.verify_ssl is True
    assert "xss" in plugin.enabled_checks
    assert "sqli" in plugin.enabled_checks
    assert plugin.rate_limit == 10
    
    # Test with custom config
    custom_config = {
        "timeout": 60,
        "max_redirects": 3,
        "user_agent": "Custom/1.0",
        "verify_ssl": False,
        "enabled_checks": ["headers", "ssl"],
        "rate_limit": 5
    }
    plugin = VulnerabilityScannerPlugin(custom_config)
    assert plugin.timeout == 60
    assert plugin.max_redirects == 3
    assert plugin.user_agent == "Custom/1.0"
    assert plugin.verify_ssl is False
    assert plugin.enabled_checks == ["headers", "ssl"]
    assert plugin.rate_limit == 5
    
    await plugin.cleanup()

@pytest.mark.asyncio
async def test_security_headers_check(plugin, mock_session, mock_response):
    """Test security headers check functionality."""
    # Test with all headers present
    mock_response.headers = TEST_HEADERS
    mock_session.get.return_value.__aenter__.return_value = mock_response
    plugin.session = mock_session
    
    vulnerabilities = await plugin._check_security_headers(TEST_URL)
    assert len(vulnerabilities) == 0
    
    # Test with missing headers
    mock_response.headers = TEST_HEADERS_MISSING
    vulnerabilities = await plugin._check_security_headers(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "Missing X-Frame-Options" for v in vulnerabilities)
    assert any(v.name == "Missing Content-Security-Policy" for v in vulnerabilities)
    
    # Test with disabled HSTS
    mock_response.headers = TEST_HEADERS_HSTS_DISABLED
    vulnerabilities = await plugin._check_security_headers(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "HSTS Disabled" for v in vulnerabilities)
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    vulnerabilities = await plugin._check_security_headers(TEST_URL)
    assert len(vulnerabilities) == 0

@pytest.mark.asyncio
async def test_ssl_tls_check(plugin):
    """Test SSL/TLS check functionality."""
    # Test HTTP URL
    vulnerabilities = await plugin._check_ssl_tls(TEST_URL)
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].name == "No HTTPS"
    
    # Test with valid HTTPS
    with patch("ssl.create_default_context") as mock_context, \
         patch("socket.create_connection") as mock_conn:
        mock_ssl_context = Mock()
        mock_context.return_value = mock_ssl_context
        mock_ssl_sock = Mock()
        mock_ssl_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.getpeercert.return_value = {
            "notAfter": (datetime.now() + timedelta(days=30)).strftime("%b %d %H:%M:%S %Y %Z"),
            "issuer": {"commonName": "Test CA"}
        }
        
        vulnerabilities = await plugin._check_ssl_tls(TEST_HTTPS_URL)
        assert len(vulnerabilities) == 0
        
    # Test with expired certificate
    with patch("ssl.create_default_context") as mock_context, \
         patch("socket.create_connection") as mock_conn:
        mock_ssl_context = Mock()
        mock_context.return_value = mock_ssl_context
        mock_ssl_sock = Mock()
        mock_ssl_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.getpeercert.return_value = {
            "notAfter": (datetime.now() - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y %Z"),
            "issuer": {"commonName": "Test CA"}
        }
        
        vulnerabilities = await plugin._check_ssl_tls(TEST_HTTPS_URL)
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].name == "Expired SSL Certificate"
        
    # Test with SSL error
    with patch("ssl.create_default_context") as mock_context, \
         patch("socket.create_connection") as mock_conn:
        mock_context.side_effect = ssl.SSLError("Invalid certificate")
        
        vulnerabilities = await plugin._check_ssl_tls(TEST_HTTPS_URL)
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].name == "SSL/TLS Error"

@pytest.mark.asyncio
async def test_xss_check(plugin, mock_session, mock_response):
    """Test XSS check functionality."""
    # Test with vulnerable form
    mock_response.text = AsyncMock(return_value=TEST_HTML)
    mock_response2 = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response2.text = AsyncMock(return_value="<script>alert(1)</script>")
    mock_session.get.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aenter__.return_value = mock_response2
    plugin.session = mock_session
    
    vulnerabilities = await plugin._check_xss(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "Cross-Site Scripting (XSS)" for v in vulnerabilities)
    
    # Test with non-vulnerable form
    mock_response2.text = AsyncMock(return_value="Form submitted")
    vulnerabilities = await plugin._check_xss(TEST_URL)
    assert len(vulnerabilities) == 0
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    vulnerabilities = await plugin._check_xss(TEST_URL)
    assert len(vulnerabilities) == 0

@pytest.mark.asyncio
async def test_sqli_check(plugin, mock_session, mock_response):
    """Test SQL injection check functionality."""
    # Test with SQL error
    mock_response.text = AsyncMock(return_value="SQL syntax error")
    mock_session.get.return_value.__aenter__.return_value = mock_response
    plugin.session = mock_session
    
    vulnerabilities = await plugin._check_sqli(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "SQL Injection" for v in vulnerabilities)
    
    # Test without SQL error
    mock_response.text = AsyncMock(return_value="Normal response")
    vulnerabilities = await plugin._check_sqli(TEST_URL)
    assert len(vulnerabilities) == 0
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    vulnerabilities = await plugin._check_sqli(TEST_URL)
    assert len(vulnerabilities) == 0

@pytest.mark.asyncio
async def test_csrf_check(plugin, mock_session, mock_response):
    """Test CSRF check functionality."""
    # Test form without CSRF token
    mock_response.text = AsyncMock(return_value=TEST_HTML)
    mock_session.get.return_value.__aenter__.return_value = mock_response
    plugin.session = mock_session
    
    vulnerabilities = await plugin._check_csrf(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "Missing CSRF Protection" for v in vulnerabilities)
    
    # Test form with CSRF token
    mock_response.text = AsyncMock(return_value=TEST_HTML_WITH_CSRF)
    vulnerabilities = await plugin._check_csrf(TEST_URL)
    assert len(vulnerabilities) == 0
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    vulnerabilities = await plugin._check_csrf(TEST_URL)
    assert len(vulnerabilities) == 0

@pytest.mark.asyncio
async def test_misconfigurations_check(plugin, mock_session, mock_response):
    """Test misconfigurations check functionality."""
    # Test directory listing
    mock_response.text = AsyncMock(return_value="<title>Index of /images</title>")
    mock_session.get.return_value.__aenter__.return_value = mock_response
    plugin.session = mock_session
    
    vulnerabilities = await plugin._check_misconfigurations(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "Directory Listing Enabled" for v in vulnerabilities)
    
    # Test sensitive file exposure
    mock_response.text = AsyncMock(return_value="DB_PASSWORD=secret")
    vulnerabilities = await plugin._check_misconfigurations(TEST_URL)
    assert len(vulnerabilities) > 0
    assert any(v.name == "Sensitive File Exposure" for v in vulnerabilities)
    
    # Test with no misconfigurations
    mock_response.status = 404
    vulnerabilities = await plugin._check_misconfigurations(TEST_URL)
    assert len(vulnerabilities) == 0
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    vulnerabilities = await plugin._check_misconfigurations(TEST_URL)
    assert len(vulnerabilities) == 0

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_session, mock_response):
    """Test complete plugin execution."""
    # Mock responses for different checks
    mock_response.headers = TEST_HEADERS_MISSING
    mock_response.text = AsyncMock(return_value=TEST_HTML)
    mock_response2 = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response2.text = AsyncMock(return_value="<script>alert(1)</script>")
    mock_session.get.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aenter__.return_value = mock_response2
    plugin.session = mock_session
    
    result = await plugin.execute(TEST_URL)
    assert isinstance(result, ScanResult)
    assert result.plugin_name == plugin.name
    assert result.status == ScanStatus.COMPLETED
    assert "vulnerabilities" in result.data
    assert len(result.data["vulnerabilities"]) > 0
    
    # Test with invalid URL
    with pytest.raises(PluginError):
        await plugin.execute("invalid-url")
    
    # Test with request error
    mock_session.get.side_effect = aiohttp.ClientError
    with pytest.raises(PluginError):
        await plugin.execute(TEST_URL)

@pytest.mark.asyncio
async def test_plugin_cleanup(plugin, mock_session):
    """Test plugin cleanup functionality."""
    plugin.session = mock_session
    await plugin.cleanup()
    assert plugin.session is None
    assert plugin.semaphore is None
    mock_session.close.assert_called_once()

@pytest.mark.asyncio
async def test_plugin_error_handling(plugin, mock_session):
    """Test plugin error handling."""
    # Test with connection error
    mock_session.get.side_effect = aiohttp.ClientError
    with pytest.raises(PluginError):
        await plugin.execute(TEST_URL)
    
    # Test with timeout
    mock_session.get.side_effect = asyncio.TimeoutError
    with pytest.raises(PluginError):
        await plugin.execute(TEST_URL)
    
    # Test with invalid response
    mock_session.get.side_effect = ValueError
    with pytest.raises(PluginError):
        await plugin.execute(TEST_URL)

@pytest.mark.asyncio
async def test_plugin_rate_limiting(plugin, mock_session, mock_response):
    """Test plugin rate limiting functionality."""
    mock_response.headers = TEST_HEADERS
    mock_response.text = AsyncMock(return_value=TEST_HTML)
    mock_session.get.return_value.__aenter__.return_value = mock_response
    plugin.session = mock_session
    plugin.rate_limit = 2  # Set low rate limit for testing
    
    # Run multiple checks in parallel
    tasks = [
        plugin._check_security_headers(TEST_URL),
        plugin._check_xss(TEST_URL),
        plugin._check_sqli(TEST_URL)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Verify that rate limiting was applied
    assert all(not isinstance(r, Exception) for r in results)
    assert mock_session.get.call_count > 0 