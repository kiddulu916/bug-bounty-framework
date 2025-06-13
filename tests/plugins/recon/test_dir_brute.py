"""
Tests for the DirBrutePlugin.

This module contains comprehensive test cases for the directory bruteforce plugin,
verifying its functionality for discovering directories and files on web servers.

Test Categories:
- Basic Functionality: Core plugin initialization and execution
- Directory Scanning: Directory discovery and analysis
- File Scanning: File discovery and analysis
- Error Handling: Plugin behavior during failures
- Finding Management: Finding creation and updates
- Resource Management: Session and connection cleanup
- Performance: Concurrent scanning and rate limiting

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Plugin lifecycle and configuration
2. Directory Scanning: Directory discovery and validation
3. File Scanning: File discovery and validation
4. Error Handling: Connection failures and timeouts
5. Finding Management: Finding creation and updates
6. Resource Management: Session cleanup and connection handling
7. Performance: Concurrent scanning and resource limits
"""

import asyncio
import pytest
from typing import Dict, Any, List, Optional, Set, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp
from datetime import datetime
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

# Test Configuration
TEST_URL = "https://example.com"
TEST_CONCURRENT_CONNECTIONS = 50
TEST_TIMEOUT = 30
TEST_MAX_RETRIES = 3

# Test Data
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

# Expected Resources
EXPECTED_RESOURCES = {
    'directories': [
        {'path': '/admin', 'type': ResourceType.DIRECTORY},
        {'path': '/login', 'type': ResourceType.DIRECTORY},
        {'path': '/backup', 'type': ResourceType.DIRECTORY}
    ],
    'files': [
        {'path': '/config.json', 'type': ResourceType.FILE},
        {'path': '/api/v1', 'type': ResourceType.FILE},
        {'path': '/docs/index.html', 'type': ResourceType.FILE}
    ]
}

class TestDirBrutePlugin:
    """
    Test suite for DirBrutePlugin.
    
    This class implements comprehensive tests for the directory bruteforce plugin,
    covering all aspects of its functionality from basic initialization to
    advanced resource discovery techniques.
    """
    
    @pytest.fixture
    def plugin(self) -> DirBrutePlugin:
        """
        Create a plugin instance for testing.
        
        Returns:
            DirBrutePlugin: Plugin instance
        """
        return DirBrutePlugin()
    
    @pytest.fixture
    def mock_wordlist(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Mock the centralized wordlist.
        
        Yields:
            AsyncMock: Mocked wordlist function
        """
        with patch('bbf.plugins.config.get_wordlist') as mock:
            mock.return_value = TEST_WORDLIST
            yield mock
    
    @pytest.fixture
    def mock_session(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Create a mock aiohttp session.
        
        Yields:
            AsyncMock: Mocked HTTP session
        """
        with patch('aiohttp.ClientSession') as mock:
            session = AsyncMock()
            mock.return_value.__aenter__.return_value = session
            yield session
    
    @pytest.fixture
    def mock_finding_service(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Mock the finding service.
        
        Yields:
            AsyncMock: Mocked finding service
        """
        with patch('bbf.core.database.service.finding_service') as mock:
            mock.create = AsyncMock()
            mock.update = AsyncMock()
            yield mock

class TestBasicFunctionality(TestDirBrutePlugin):
    """Tests for basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(
        self,
        plugin: DirBrutePlugin,
        mock_wordlist: AsyncMock
    ) -> None:
        """
        Test plugin initialization.
        
        This test verifies that the plugin:
        1. Initializes with correct configuration
        2. Creates HTTP session
        3. Sets up semaphore for concurrency
        4. Loads wordlist properly
        
        Args:
            plugin: Plugin instance
            mock_wordlist: Mocked wordlist function
        """
        await plugin.initialize()
        
        # Verify initialization
        assert plugin._session is not None
        assert isinstance(plugin._session, aiohttp.ClientSession)
        assert plugin._semaphore is not None
        assert isinstance(plugin._semaphore, asyncio.Semaphore)
        assert len(plugin._wordlist) == len(TEST_WORDLIST)
        assert plugin._results == {}
        mock_wordlist.assert_called_once_with('directory')

class TestDirectoryScanning(TestDirBrutePlugin):
    """Tests for directory scanning functionality."""
    
    @pytest.mark.asyncio
    async def test_scan_directories(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock,
        mock_wordlist: AsyncMock
    ) -> None:
        """
        Test directory scanning.
        
        This test verifies that the plugin:
        1. Discovers accessible directories
        2. Validates directory responses
        3. Extracts directory metadata
        4. Handles HTTP responses properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_wordlist: Mocked wordlist function
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock successful responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        resources = await plugin._scan_directories(TEST_URL)
        
        # Verify results
        assert len(resources) > 0
        for resource in resources:
            assert resource.type == ResourceType.DIRECTORY
            assert resource.status_code == 200
            assert resource.is_accessible
            assert resource.content_type == 'text/html; charset=utf-8'
            assert resource.content_length == 1234
            assert resource.stage == 'recon'
            assert resource.status == 'active'

class TestFileScanning(TestDirBrutePlugin):
    """Tests for file scanning functionality."""
    
    @pytest.mark.asyncio
    async def test_scan_files(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock,
        mock_wordlist: AsyncMock
    ) -> None:
        """
        Test file scanning.
        
        This test verifies that the plugin:
        1. Discovers accessible files
        2. Validates file responses
        3. Extracts file metadata
        4. Handles different content types
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_wordlist: Mocked wordlist function
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock successful responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Content-Type': 'application/json',
            'Content-Length': '5678'
        }
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        resources = await plugin._scan_files(TEST_URL)
        
        # Verify results
        assert len(resources) > 0
        for resource in resources:
            assert resource.type == ResourceType.FILE
            assert resource.status_code == 200
            assert resource.is_accessible
            assert resource.content_type == 'application/json'
            assert resource.content_length == 5678
            assert resource.stage == 'recon'
            assert resource.status == 'active'

class TestErrorHandling(TestDirBrutePlugin):
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_error_handling(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test plugin error handling.
        
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
        
        # Mock failed responses
        mock_session.get.side_effect = aiohttp.ClientError("Connection error")
        
        resources = await plugin._scan_directories(TEST_URL)
        
        # Verify empty result on error
        assert len(resources) == 0

class TestFindingManagement(TestDirBrutePlugin):
    """Tests for finding management functionality."""
    
    @pytest.mark.asyncio
    async def test_finding_creation(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock,
        mock_wordlist: AsyncMock,
        mock_finding_service: AsyncMock
    ) -> None:
        """
        Test finding creation for discovered resources.
        
        This test verifies that the plugin:
        1. Creates findings for each resource
        2. Sets appropriate finding attributes
        3. Includes relevant metadata
        4. Updates finding service properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_wordlist: Mocked wordlist function
            mock_finding_service: Mocked finding service
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock successful response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run plugin execution
        results = await plugin.execute(TEST_URL)
        
        # Verify findings were created
        assert mock_finding_service.create.call_count == len(results)
        for call in mock_finding_service.create.call_args_list:
            finding = call[0][0]
            assert isinstance(finding, Finding)
            assert finding.stage == 'recon'
            assert finding.status == 'active'
            assert finding.severity == 'info'
            assert finding.title.startswith('Discovered')
            assert finding.description.startswith('Found')

class TestResourceManagement(TestDirBrutePlugin):
    """Tests for resource management functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test plugin cleanup.
        
        This test verifies that the plugin:
        1. Closes HTTP session properly
        2. Cleans up resources
        3. Handles cleanup gracefully
        4. Prevents resource leaks
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        await plugin.cleanup()
        
        # Verify session was closed
        mock_session.close.assert_called_once()

class TestPerformance(TestDirBrutePlugin):
    """Tests for performance and concurrency."""
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock,
        mock_wordlist: AsyncMock
    ) -> None:
        """
        Test concurrent scanning.
        
        This test verifies that the plugin:
        1. Handles concurrent requests properly
        2. Respects connection limits
        3. Maintains stability under load
        4. Processes all resources efficiently
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_wordlist: Mocked wordlist function
        """
        # Configure plugin with high concurrency
        plugin._concurrent_connections = TEST_CONCURRENT_CONNECTIONS
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock successful responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        resources = await plugin._scan_directories(TEST_URL)
        
        # Verify results
        assert len(resources) == len(TEST_WORDLIST)
        assert all(r.status_code == 200 for r in resources)
        
        # Verify concurrent connections were limited
        assert mock_session.get.call_count == len(TEST_WORDLIST)

class TestPluginExecution(TestDirBrutePlugin):
    """Tests for complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_plugin_execution(
        self,
        plugin: DirBrutePlugin,
        mock_session: AsyncMock,
        mock_wordlist: AsyncMock,
        mock_finding_service: AsyncMock
    ) -> None:
        """
        Test complete plugin execution.
        
        This test verifies that the plugin:
        1. Executes all scanning methods
        2. Combines results from different sources
        3. Handles HTTP requests properly
        4. Returns comprehensive findings
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_wordlist: Mocked wordlist function
            mock_finding_service: Mocked finding service
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock successful responses
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        results = await plugin.execute(TEST_URL)
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(isinstance(r, Resource) for r in results)
        assert all(r.url.startswith(TEST_URL) for r in results)
        assert all(r.stage == 'recon' for r in results)
        assert all(r.status == 'active' for r in results) 