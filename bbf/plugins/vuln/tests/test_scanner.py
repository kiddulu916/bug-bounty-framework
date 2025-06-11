"""
Test suite for the Vulnerability Scanner Plugin.

This module tests:
- Plugin initialization and cleanup
- SQL Injection detection
- XSS detection
- CSRF detection
- Open Redirect detection
- File Inclusion detection
- Command Injection detection
- SSRF detection
- Database integration
- Error handling
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from bs4 import BeautifulSoup
import aiohttp
from aiohttp import ClientResponse, ClientSession
import json
from urllib.parse import urlparse

from bbf.plugins.vuln.scanner import VulnScannerPlugin, VulnResult, PluginError
from bbf.core.database.models import VulnerabilityFinding, Finding
from bbf.core.database.service import finding_service

# Test data
TEST_URL = "https://example.com"
TEST_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <form action="/search" method="get">
        <input type="text" name="q" value="">
        <input type="submit" value="Search">
    </form>
    
    <form action="/login" method="post">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Login">
    </form>
    
    <form action="/upload" method="post">
        <input type="file" name="file" value="">
        <input type="submit" value="Upload">
    </form>
    
    <a href="/redirect?url=https://example.com">Redirect</a>
    <a href="/download?file=document.pdf">Download</a>
    <a href="/proxy?url=https://example.com">Proxy</a>
</body>
</html>
"""

TEST_SQL_ERROR = """
MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' OR '1'='1'' at line 1
"""

TEST_XSS_REFLECTED = """
<div class="search-results">
    <p>Search results for: <script>alert(1)</script></p>
</div>
"""

TEST_FILE_INCLUSION_ERROR = """
PHP Warning: include(): Failed opening '../../etc/passwd' for inclusion (include_path='.:/usr/share/php') in /var/www/html/index.php on line 5
"""

TEST_COMMAND_INJECTION_OUTPUT = """
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)
"""

@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock()
        mock.return_value = session
        yield session

@pytest.fixture
def mock_finding_service():
    """Create a mock finding service."""
    with patch('bbf.core.database.service.finding_service') as mock:
        mock.add_or_update_finding = AsyncMock()
        yield mock

@pytest.fixture
def mock_payloads():
    """Create mock payloads."""
    return {
        'sql_injection': ["' OR '1'='1"],
        'xss': ["<script>alert(1)</script>"],
        'open_redirect': ["//google.com"],
        'file_inclusion': ["../../../etc/passwd"],
        'command_injection': ["; ls -la"],
        'ssrf': ["http://localhost/"],
        'xxe': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
    }

@pytest.fixture
def mock_error_patterns():
    """Create mock error patterns."""
    return {
        'sql_injection': [r"SQL syntax.*MySQL"],
        'xss': [r"<script>alert\(1\)</script>"],
        'file_inclusion': [r"root:.*:0:0:"],
        'command_injection': [r"root:.*:0:0:"]
    }

@pytest.fixture
def plugin(mock_payloads, mock_error_patterns):
    """Create a plugin instance with mocked dependencies."""
    with patch('bbf.plugins.config.get_payloads', return_value=mock_payloads), \
         patch('bbf.plugins.config.get_error_patterns', return_value=mock_error_patterns):
        plugin = VulnScannerPlugin()
        return plugin

@pytest.mark.asyncio
async def test_plugin_initialization(plugin):
    """Test plugin initialization."""
    assert plugin.name == "vuln_scanner"
    assert plugin.description == "Vulnerability detection and analysis"
    assert plugin.version == "1.0.0"
    assert plugin.author == "BBF Team"
    assert plugin.timeout == 10.0
    assert plugin.max_redirects == 5
    assert plugin.max_concurrent_requests == 10
    assert plugin.verify_ssl is True
    assert plugin.payloads == mock_payloads
    assert plugin.error_patterns == mock_error_patterns

@pytest.mark.asyncio
async def test_plugin_cleanup(plugin, mock_session):
    """Test plugin cleanup."""
    await plugin.initialize()
    assert plugin.session is not None
    await plugin.cleanup()
    assert plugin.session is None
    mock_session.close.assert_called_once()

@pytest.mark.asyncio
async def test_sql_injection_detection(plugin, mock_session):
    """Test SQL injection detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="SQL syntax near '1'")
    mock_response.url = "http://example.com/login"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test form
    form_html = """
    <form action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    """
    form = BeautifulSoup(form_html, 'html.parser').find('form')
    
    # Test detection
    result = await plugin._scan_form_sql_injection(form, "http://example.com")
    assert result is not None
    assert result.type == "sql_injection"
    assert result.severity == "high"
    assert result.url == "http://example.com/login"
    assert result.parameter == "username"
    assert result.payload == "' OR '1'='1"
    assert result.stage == "vuln"
    assert result.status == "active"

@pytest.mark.asyncio
async def test_xss_detection(plugin, mock_session):
    """Test XSS detection."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="<script>alert(1)</script>")
    mock_response.url = "http://example.com/search"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Create test form
    form_html = """
    <form action="/search" method="GET">
        <input type="text" name="q">
        <input type="submit" value="Search">
    </form>
    """
    form = BeautifulSoup(form_html, 'html.parser').find('form')
    
    # Test detection
    result = await plugin._scan_form_xss(form, "http://example.com")
    assert result is not None
    assert result.type == "xss"
    assert result.severity == "high"
    assert result.url == "http://example.com/search"
    assert result.parameter == "q"
    assert result.payload == "<script>alert(1)</script>"
    assert result.stage == "vuln"
    assert result.status == "active"

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

@pytest.mark.asyncio
async def test_store_findings(plugin, mock_finding_service):
    """Test storing findings in database."""
    # Create test findings
    findings = [
        {
            'url': 'http://example.com/login',
            'type': 'sql_injection',
            'severity': 'high',
            'description': 'SQL injection vulnerability',
            'evidence': 'SQL syntax error',
            'payload': "' OR '1'='1",
            'parameter': 'username',
            'confidence': 0.9,
            'timestamp': datetime.utcnow(),
            'stage': 'vuln',
            'status': 'active'
        },
        {
            'url': 'http://example.com/search',
            'type': 'xss',
            'severity': 'high',
            'description': 'XSS vulnerability',
            'evidence': '<script>alert(1)</script>',
            'payload': '<script>alert(1)</script>',
            'parameter': 'q',
            'confidence': 0.9,
            'timestamp': datetime.utcnow(),
            'stage': 'vuln',
            'status': 'active'
        }
    ]
    
    # Store findings
    await plugin._store_findings("http://example.com", findings)
    
    # Verify finding service call
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    finding_data = call_args['finding_data']
    
    assert finding_data['root_domain'] == 'example.com'
    assert finding_data['subdomain'] == 'example'
    assert finding_data['source'] == 'vulnerability_scan'
    assert finding_data['stage'] == 'vuln'
    assert finding_data['status'] == 'active'
    
    metadata = json.loads(finding_data['metadata'])
    assert metadata['scan_type'] == 'comprehensive'
    assert metadata['vulnerabilities_found'] == 2
    assert 'sql_injection' in metadata['vulnerabilities_by_type']
    assert 'xss' in metadata['vulnerabilities_by_type']
    assert 'scan_timestamp' in metadata
    assert 'scan_details' in metadata

@pytest.mark.asyncio
async def test_store_findings_error(plugin, mock_finding_service):
    """Test error handling when storing findings."""
    # Mock finding service to raise an error
    mock_finding_service.add_or_update_finding.side_effect = Exception("Database error")
    
    # Create test findings
    findings = [
        {
            'url': 'http://example.com/login',
            'type': 'sql_injection',
            'severity': 'high',
            'description': 'SQL injection vulnerability',
            'evidence': 'SQL syntax error',
            'payload': "' OR '1'='1",
            'parameter': 'username',
            'confidence': 0.9,
            'timestamp': datetime.utcnow(),
            'stage': 'vuln',
            'status': 'active'
        }
    ]
    
    # Test error handling
    with pytest.raises(PluginError) as exc_info:
        await plugin._store_findings("http://example.com", findings)
    assert "Failed to store findings in database" in str(exc_info.value)

@pytest.mark.asyncio
async def test_execute_with_no_findings(plugin, mock_session):
    """Test plugin execution with no findings."""
    # Mock response
    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="<html><body>No vulnerabilities</body></html>")
    mock_response.url = "http://example.com"
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Execute plugin
    results = await plugin.execute("http://example.com")
    assert results == []
    mock_finding_service.add_or_update_finding.assert_not_called()

@pytest.mark.asyncio
async def test_execute_with_findings(plugin, mock_session, mock_finding_service):
    """Test plugin execution with findings."""
    # Mock responses for different scan types
    mock_responses = {
        '/login': "SQL syntax error",
        '/search': "<script>alert(1)</script>",
        '/redirect': "https://google.com",
        '/include': "root:x:0:0:root:/root:/bin/bash",
        '/exec': "root:x:0:0:root:/root:/bin/bash",
        '/fetch': "SSRF detected"
    }
    
    async def mock_get(*args, **kwargs):
        mock_response = AsyncMock()
        url = args[0]
        path = urlparse(url).path
        mock_response.text = AsyncMock(return_value=mock_responses.get(path, ""))
        mock_response.url = url
        return mock_response
    
    mock_session.get.side_effect = mock_get
    
    # Execute plugin
    results = await plugin.execute("http://example.com")
    
    # Verify results
    assert len(results) > 0
    assert any(r['type'] == 'sql_injection' for r in results)
    assert any(r['type'] == 'xss' for r in results)
    assert any(r['type'] == 'open_redirect' for r in results)
    assert any(r['type'] == 'file_inclusion' for r in results)
    assert any(r['type'] == 'command_injection' for r in results)
    assert any(r['type'] == 'ssrf' for r in results)
    
    # Verify finding service call
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    finding_data = call_args['finding_data']
    
    assert finding_data['root_domain'] == 'example.com'
    assert finding_data['subdomain'] == 'example'
    assert finding_data['source'] == 'vulnerability_scan'
    assert finding_data['stage'] == 'vuln'
    assert finding_data['status'] == 'active'
    
    metadata = json.loads(finding_data['metadata'])
    assert metadata['scan_type'] == 'comprehensive'
    assert metadata['vulnerabilities_found'] == len(results)
    assert all(vuln_type in metadata['vulnerabilities_by_type'] 
              for vuln_type in ['sql_injection', 'xss', 'open_redirect', 
                              'file_inclusion', 'command_injection', 'ssrf'])
    assert 'scan_timestamp' in metadata
    assert 'scan_details' in metadata

@pytest.mark.asyncio
async def test_execute_with_error(plugin, mock_session):
    """Test plugin execution with error."""
    # Mock session to raise an error
    mock_session.get.side_effect = Exception("Network error")
    
    # Execute plugin
    results = await plugin.execute("http://example.com")
    assert results == []
    mock_finding_service.add_or_update_finding.assert_not_called() 