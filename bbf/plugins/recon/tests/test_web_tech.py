"""
Test suite for the Web Technology Detection Plugin.

This module tests:
- Plugin initialization and cleanup
- HTTP header analysis
- HTML content analysis
- Meta tag analysis
- Cookie analysis
- Script analysis
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
import yarl

from bbf.plugins.recon.web_tech import WebTechPlugin, TechResult
from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service

# Test data
TEST_URL = "https://example.com"
TEST_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta name="generator" content="WordPress 5.8.2">
    <meta name="framework" content="React 17.0.2">
    <script src="https://example.com/js/jquery-3.6.0.min.js"></script>
    <script>
        ReactDOM.render(<App />, document.getElementById('root'));
    </script>
</head>
<body>
    <div ng-app="myApp" ng-controller="myCtrl">
        <div data-drupal-selector="content">
            <script src="https://example.com/js/angular.min.js"></script>
        </div>
    </div>
</body>
</html>
"""

TEST_HEADERS = {
    'server': 'nginx/1.18.0',
    'x-powered-by': 'PHP/7.4.21',
    'set-cookie': 'wordpress_test_cookie=WP Cookie check'
}

@pytest.fixture
async def plugin():
    """Create a plugin instance for testing."""
    plugin = WebTechPlugin()
    await plugin.initialize()
    yield plugin
    await plugin.cleanup()

@pytest.fixture
def mock_session():
    """Create mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock(spec=ClientSession)
        mock.return_value = session
        session.get.return_value.__aenter__.return_value = AsyncMock(spec=ClientResponse)
        session.get.return_value.__aenter__.return_value.status = 200
        session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value=TEST_HTML)
        session.get.return_value.__aenter__.return_value.headers = TEST_HEADERS
        session.get.return_value.__aenter__.return_value.cookies = {'wordpress_test_cookie': 'WP Cookie check'}
        session.get.return_value.__aenter__.return_value.url = yarl.URL(TEST_URL)
        yield session

@pytest.fixture
def mock_finding_service():
    """Create mock finding service."""
    with patch('bbf.core.database.service.finding_service') as mock:
        mock.get_finding = AsyncMock(return_value=None)
        mock.add_or_update_finding = AsyncMock()
        yield mock

def test_plugin_initialization(plugin):
    """Test plugin initialization and cleanup."""
    assert plugin.name == "web_tech"
    assert plugin.description == "Web technology and framework detection"
    assert plugin.version == "1.0.0"
    assert plugin.session is not None
    
    # Test cleanup
    asyncio.run(plugin.cleanup())
    assert plugin.session is None

@pytest.mark.asyncio
async def test_detect_from_headers(plugin):
    """Test technology detection from HTTP headers."""
    results = await plugin._detect_from_headers(TEST_HEADERS, TEST_URL)
    
    # Check server detection
    nginx_result = next((r for r in results if r.name == 'nginx'), None)
    assert nginx_result is not None
    assert nginx_result.category == 'server'
    assert nginx_result.confidence == 0.9
    assert 'Server header' in nginx_result.evidence
    assert nginx_result.stage == 'recon'
    assert nginx_result.status == 'active'
    
    # Check X-Powered-By detection
    php_result = next((r for r in results if r.name == 'apache'), None)
    assert php_result is not None
    assert php_result.category == 'server'
    assert php_result.confidence == 0.8
    assert 'X-Powered-By header' in php_result.evidence
    assert php_result.stage == 'recon'
    assert php_result.status == 'active'

@pytest.mark.asyncio
async def test_detect_from_html(plugin):
    """Test technology detection from HTML content."""
    soup = BeautifulSoup(TEST_HTML, 'html.parser')
    results = await plugin._detect_from_html(soup, TEST_URL)
    
    # Check framework detection
    react_result = next((r for r in results if r.name == 'react'), None)
    assert react_result is not None
    assert react_result.category == 'framework'
    assert react_result.confidence == 0.9
    assert react_result.stage == 'recon'
    assert react_result.status == 'active'
    
    # Check CMS detection
    drupal_result = next((r for r in results if r.name == 'drupal'), None)
    assert drupal_result is not None
    assert drupal_result.category == 'cms'
    assert drupal_result.confidence == 0.9
    assert drupal_result.stage == 'recon'
    assert drupal_result.status == 'active'

@pytest.mark.asyncio
async def test_detect_from_meta(plugin):
    """Test technology detection from meta tags."""
    soup = BeautifulSoup(TEST_HTML, 'html.parser')
    results = await plugin._detect_from_meta(soup, TEST_URL)
    
    # Check WordPress detection
    wp_result = next((r for r in results if r.name == 'wordpress'), None)
    assert wp_result is not None
    assert wp_result.category == 'cms'
    assert wp_result.version == '5.8.2'
    assert wp_result.confidence == 1.0
    assert wp_result.stage == 'recon'
    assert wp_result.status == 'active'
    
    # Check React detection
    react_result = next((r for r in results if r.name == 'react'), None)
    assert react_result is not None
    assert react_result.category == 'framework'
    assert react_result.version == '17.0.2'
    assert react_result.confidence == 0.9
    assert react_result.stage == 'recon'
    assert react_result.status == 'active'

@pytest.mark.asyncio
async def test_detect_from_cookies(plugin):
    """Test technology detection from cookies."""
    cookies = {'wordpress_test_cookie': 'WP Cookie check'}
    results = await plugin._detect_from_cookies(cookies, TEST_URL)
    
    # Check WordPress detection
    wp_result = next((r for r in results if r.name == 'wordpress'), None)
    assert wp_result is not None
    assert wp_result.category == 'cms'
    assert wp_result.confidence == 0.8
    assert 'Cookie name' in wp_result.evidence
    assert wp_result.stage == 'recon'
    assert wp_result.status == 'active'

@pytest.mark.asyncio
async def test_detect_from_scripts(plugin):
    """Test technology detection from script tags."""
    soup = BeautifulSoup(TEST_HTML, 'html.parser')
    results = await plugin._detect_from_scripts(soup, TEST_URL)
    
    # Check jQuery detection
    jquery_result = next((r for r in results if r.name == 'jquery'), None)
    assert jquery_result is not None
    assert jquery_result.category == 'framework'
    assert jquery_result.version == '3.6.0'
    assert jquery_result.confidence == 0.9
    assert jquery_result.stage == 'recon'
    assert jquery_result.status == 'active'
    
    # Check React detection from inline script
    react_result = next((r for r in results if r.name == 'react'), None)
    assert react_result is not None
    assert react_result.category == 'framework'
    assert react_result.confidence == 0.9
    assert react_result.stage == 'recon'
    assert react_result.status == 'active'

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_session, mock_finding_service):
    """Test complete plugin execution."""
    plugin.session = mock_session
    
    results = await plugin.execute(TEST_URL)
    
    # Verify results
    assert len(results) > 0
    
    # Check WordPress detection
    wp_result = next((r for r in results if r['name'] == 'wordpress'), None)
    assert wp_result is not None
    assert wp_result['category'] == 'cms'
    assert wp_result['version'] == '5.8.2'
    assert wp_result['stage'] == 'recon'
    assert wp_result['status'] == 'active'
    
    # Check React detection
    react_result = next((r for r in results if r['name'] == 'react'), None)
    assert react_result is not None
    assert react_result['category'] == 'framework'
    assert react_result['version'] == '17.0.2'
    assert react_result['stage'] == 'recon'
    assert react_result['status'] == 'active'
    
    # Verify database integration
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    assert call_args['root_domain'] == 'example.com'
    assert call_args['subdomain'] == 'example'
    assert call_args['merge_metadata'] is True

@pytest.mark.asyncio
async def test_database_integration(plugin, mock_session, mock_finding_service):
    """Test database integration."""
    plugin.session = mock_session
    
    # Execute plugin
    await plugin.execute(TEST_URL)
    
    # Verify database calls
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    
    # Verify finding data
    finding_data = call_args['finding_data']
    assert finding_data['root_domain'] == 'example.com'
    assert finding_data['subdomain'] == 'example'
    assert finding_data['source'] == 'web_tech_detection'
    assert finding_data['stage'] == 'recon'
    assert finding_data['status'] == 'active'
    
    # Verify technology data
    tech_data = json.loads(finding_data['web_tech'])
    assert len(tech_data) > 0
    assert 'wordpress' in tech_data
    assert 'react' in tech_data
    
    # Verify metadata
    metadata = json.loads(finding_data['metadata'])
    assert metadata['scan_type'] == 'comprehensive'
    assert 'technologies_detected' in metadata
    assert 'scan_timestamp' in metadata
    assert 'scan_details' in metadata

@pytest.mark.asyncio
async def test_concurrent_execution(plugin, mock_session, mock_finding_service):
    """Test concurrent plugin execution."""
    plugin.session = mock_session
    
    # Execute multiple instances concurrently
    tasks = [
        plugin.execute(TEST_URL),
        plugin.execute(TEST_URL),
        plugin.execute(TEST_URL)
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Verify all executions completed
    assert len(results) == 3
    assert all(len(r) > 0 for r in results)
    
    # Verify database calls
    assert mock_finding_service.add_or_update_finding.call_count == 3

@pytest.mark.asyncio
async def test_error_handling(plugin, mock_session, mock_finding_service):
    """Test error handling."""
    plugin.session = mock_session
    
    # Test network error
    mock_session.get.side_effect = aiohttp.ClientError("Network error")
    results = await plugin.execute(TEST_URL)
    assert len(results) == 0
    
    # Test database error
    mock_session.get.side_effect = None
    mock_finding_service.add_or_update_finding.side_effect = Exception("Database error")
    with pytest.raises(Exception) as exc_info:
        await plugin.execute(TEST_URL)
    assert "Database error" in str(exc_info.value)
    
    # Test invalid URL
    results = await plugin.execute("invalid-url")
    assert len(results) == 0 