"""
Tests for the directory bruteforce plugin.

This module contains test cases for the DirBrutePlugin class, verifying
its ability to discover directories and files on web servers.
"""

import asyncio
import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
import aiohttp
import os
import tempfile
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from bbf.plugins.recon.dir_brute import (
    DirBrutePlugin,
    Resource,
    ResourceType
)
from bbf.core.exceptions import PluginError
from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service

# Test data
TEST_URL = "https://example.com"
TEST_WORDLIST = [
    "admin",
    "login",
    "backup",
    "config",
    "test",
    "api",
    "docs",
    "images",
    "css",
    "js"
]

TEST_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': '1234',
    'Server': 'nginx/1.18.0'
}

@pytest.fixture
def mock_wordlist():
    """Mock the centralized wordlist."""
    with patch('bbf.plugins.config.get_wordlist') as mock:
        mock.return_value = TEST_WORDLIST
        yield mock

@pytest.fixture
def plugin(mock_wordlist):
    """Create a DirBrutePlugin instance for testing."""
    plugin = DirBrutePlugin()
    return plugin

@pytest.fixture
def mock_session():
    """Create mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock(spec=aiohttp.ClientSession)
        mock.return_value = session
        session.get.return_value.__aenter__.return_value = AsyncMock(spec=aiohttp.ClientResponse)
        session.head.return_value.__aenter__.return_value = AsyncMock(spec=aiohttp.ClientResponse)
        session.get.return_value.__aenter__.return_value.status = 200
        session.head.return_value.__aenter__.return_value.status = 200
        session.get.return_value.__aenter__.return_value.headers = TEST_HEADERS
        session.head.return_value.__aenter__.return_value.headers = TEST_HEADERS
        session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value="<html>Test</html>")
        session.get.return_value.__aenter__.return_value.url = urlparse(TEST_URL)
        session.head.return_value.__aenter__.return_value.url = urlparse(TEST_URL)
        yield session

@pytest.fixture
def mock_finding_service():
    """Create mock finding service."""
    with patch('bbf.core.database.service.finding_service') as mock:
        mock.get_finding = AsyncMock(return_value=None)
        mock.add_or_update_finding = AsyncMock()
        yield mock

@pytest.mark.asyncio
async def test_plugin_initialization(plugin, mock_wordlist):
    """Test plugin initialization."""
    await plugin.initialize()
    assert plugin._session is not None
    assert isinstance(plugin._session, aiohttp.ClientSession)
    assert plugin._semaphore is not None
    assert isinstance(plugin._semaphore, asyncio.Semaphore)
    assert len(plugin._wordlist) == len(TEST_WORDLIST)
    assert plugin._results == {}
    mock_wordlist.assert_called_once_with('directory')

@pytest.mark.asyncio
async def test_plugin_initialization_missing_wordlist(mock_wordlist):
    """Test plugin initialization with missing wordlist."""
    mock_wordlist.return_value = None
    plugin = DirBrutePlugin()
    with pytest.raises(PluginError) as exc_info:
        await plugin.initialize()
    assert "Failed to load directory wordlist" in str(exc_info.value)

@pytest.mark.asyncio
async def test_plugin_initialization_failure():
    """Test plugin initialization failure."""
    plugin = DirBrutePlugin()
    with patch('aiohttp.ClientSession', side_effect=Exception("Connection failed")):
        with pytest.raises(PluginError) as exc_info:
            await plugin.initialize()
        assert "Plugin initialization failed" in str(exc_info.value)

@pytest.mark.asyncio
async def test_scan_directories(plugin, mock_session, mock_wordlist):
    """Test directory scanning."""
    await plugin.initialize()
    plugin._session = mock_session
    
    resources = await plugin._scan_directories(TEST_URL)
    
    assert len(resources) > 0
    for resource in resources:
        assert resource.type == ResourceType.DIRECTORY
        assert resource.status_code == 200
        assert resource.is_accessible
        assert resource.content_type == 'text/html; charset=utf-8'
        assert resource.content_length == 1234
        assert resource.stage == 'recon'
        assert resource.status == 'active'

@pytest.mark.asyncio
async def test_scan_files(plugin, mock_session, mock_wordlist):
    """Test file scanning."""
    await plugin.initialize()
    plugin._session = mock_session
    
    resources = await plugin._scan_files(TEST_URL)
    
    assert len(resources) > 0
    for resource in resources:
        assert resource.type == ResourceType.FILE
        assert resource.status_code == 200
        assert resource.is_accessible
        assert any(resource.path.endswith(ext) for ext in plugin.extensions)
        assert resource.stage == 'recon'
        assert resource.status == 'active'

@pytest.mark.asyncio
async def test_scan_backups(plugin, mock_session, mock_wordlist):
    """Test backup file scanning."""
    await plugin.initialize()
    plugin._session = mock_session
    
    resources = await plugin._scan_backups(TEST_URL)
    
    assert len(resources) > 0
    for resource in resources:
        assert resource.type == ResourceType.BACKUP
        assert resource.status_code == 200
        assert resource.is_accessible
        assert any(resource.path.endswith(ext) for ext in plugin.backup_extensions)
        assert resource.stage == 'recon'
        assert resource.status == 'active'

@pytest.mark.asyncio
async def test_scan_sensitive(plugin, mock_session, mock_wordlist):
    """Test sensitive file scanning."""
    await plugin.initialize()
    plugin._session = mock_session
    
    resources = await plugin._scan_sensitive(TEST_URL)
    
    assert len(resources) > 0
    for resource in resources:
        assert resource.type == ResourceType.SENSITIVE
        assert resource.status_code == 200
        assert resource.is_accessible
        assert any(pattern in resource.path for pattern in plugin.sensitive_patterns)
        assert resource.stage == 'recon'
        assert resource.status == 'active'

@pytest.mark.asyncio
async def test_check_resource_accessible(plugin, mock_session, mock_wordlist):
    """Test resource checking for accessible resources."""
    await plugin.initialize()
    plugin._session = mock_session
    
    resource = await plugin._check_resource(
        f"{TEST_URL}/admin",
        ResourceType.DIRECTORY
    )
    
    assert resource is not None
    assert resource.path == '/admin'
    assert resource.type == ResourceType.DIRECTORY
    assert resource.status_code == 200
    assert resource.is_accessible
    assert resource.content_type == 'text/html; charset=utf-8'
    assert resource.content_length == 1234
    assert resource.stage == 'recon'
    assert resource.status == 'active'

@pytest.mark.asyncio
async def test_check_resource_inaccessible(plugin, mock_session, mock_wordlist):
    """Test resource checking for inaccessible resources."""
    await plugin.initialize()
    plugin._session = mock_session
    
    # Mock 403 response
    mock_session.head.return_value.__aenter__.return_value.status = 403
    
    resource = await plugin._check_resource(
        f"{TEST_URL}/private",
        ResourceType.SENSITIVE
    )
    
    assert resource is not None
    assert resource.path == '/private'
    assert resource.type == ResourceType.SENSITIVE
    assert resource.status_code == 403
    assert not resource.is_accessible
    assert resource.is_interesting
    assert resource.stage == 'recon'
    assert resource.status == 'active'

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_session, mock_wordlist, mock_finding_service):
    """Test complete plugin execution."""
    await plugin.initialize()
    plugin._session = mock_session
    
    result = await plugin.execute(TEST_URL)
    
    assert result['target'] == TEST_URL
    assert 'resources' in result
    assert 'count' in result
    assert 'execution_time' in result
    
    # Verify resource types
    resource_types = {r['type'] for r in result['resources']}
    assert ResourceType.DIRECTORY.value in resource_types
    assert ResourceType.FILE.value in resource_types
    assert ResourceType.BACKUP.value in resource_types
    assert ResourceType.SENSITIVE.value in resource_types
    
    # Verify database integration
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    assert call_args['finding_data']['root_domain'] == 'example.com'
    assert call_args['finding_data']['subdomain'] == 'example'
    assert call_args['finding_data']['source'] == 'directory_bruteforce'
    assert call_args['finding_data']['stage'] == 'recon'
    assert call_args['finding_data']['status'] == 'active'
    assert call_args['merge_metadata'] is True
    
    # Verify metadata
    metadata = json.loads(call_args['finding_data']['metadata'])
    assert metadata['scan_type'] == 'comprehensive'
    assert 'resources_found' in metadata
    assert 'resources_by_type' in metadata
    assert 'scan_timestamp' in metadata
    assert 'scan_details' in metadata

@pytest.mark.asyncio
async def test_database_integration(plugin, mock_session, mock_wordlist, mock_finding_service):
    """Test database integration."""
    await plugin.initialize()
    plugin._session = mock_session
    
    # Execute plugin
    await plugin.execute(TEST_URL)
    
    # Verify database calls
    mock_finding_service.add_or_update_finding.assert_called_once()
    call_args = mock_finding_service.add_or_update_finding.call_args[1]
    
    # Verify finding data
    finding_data = call_args['finding_data']
    assert finding_data['root_domain'] == 'example.com'
    assert finding_data['subdomain'] == 'example'
    assert finding_data['source'] == 'directory_bruteforce'
    assert finding_data['stage'] == 'recon'
    assert finding_data['status'] == 'active'
    
    # Verify metadata
    metadata = json.loads(finding_data['metadata'])
    assert metadata['scan_type'] == 'comprehensive'
    assert 'resources_found' in metadata
    assert 'resources_by_type' in metadata
    assert 'scan_timestamp' in metadata
    assert 'scan_details' in metadata
    assert 'extensions_checked' in metadata['scan_details']
    assert 'backup_extensions_checked' in metadata['scan_details']
    assert 'sensitive_patterns_checked' in metadata['scan_details']

@pytest.mark.asyncio
async def test_concurrent_execution(plugin, mock_session, mock_wordlist, mock_finding_service):
    """Test concurrent plugin execution."""
    await plugin.initialize()
    plugin._session = mock_session
    
    # Execute multiple instances concurrently
    tasks = [
        plugin.execute(TEST_URL),
        plugin.execute(TEST_URL),
        plugin.execute(TEST_URL)
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Verify all executions completed
    assert len(results) == 3
    assert all(len(r['resources']) > 0 for r in results)
    
    # Verify database calls
    assert mock_finding_service.add_or_update_finding.call_count == 3

@pytest.mark.asyncio
async def test_error_handling(plugin, mock_session, mock_wordlist, mock_finding_service):
    """Test error handling."""
    await plugin.initialize()
    plugin._session = mock_session
    
    # Test network error
    mock_session.head.side_effect = aiohttp.ClientError("Network error")
    results = await plugin.execute(TEST_URL)
    assert len(results['resources']) == 0
    
    # Test database error
    mock_session.head.side_effect = None
    mock_finding_service.add_or_update_finding.side_effect = Exception("Database error")
    with pytest.raises(PluginError) as exc_info:
        await plugin.execute(TEST_URL)
    assert "Failed to store findings in database" in str(exc_info.value)
    
    # Test invalid URL
    results = await plugin.execute("invalid-url")
    assert len(results['resources']) == 0 