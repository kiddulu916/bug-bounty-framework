"""
Integration tests for the Directory Bruteforce Plugin.

This module contains comprehensive test cases for the Directory Bruteforce Plugin,
verifying its functionality for discovering and analyzing web directories and files.

Test Categories:
- Basic Functionality: Core directory bruteforce features
- Custom Wordlist: Directory discovery using custom wordlists
- Error Handling: Plugin behavior during failures
- Performance: Execution time and resource usage
- Concurrent Execution: Multi-target scanning
- Data Management: Finding updates and metadata handling
- Extension Handling: File extension bruteforcing

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Directory discovery and analysis
2. Custom Wordlist: Custom wordlist processing
3. Error Handling: HTTP failures and error recovery
4. Performance: Execution time and resource usage
5. Concurrent Execution: Multi-target scanning efficiency
6. Data Management: Finding updates and metadata merging
7. Extension Handling: File extension discovery
"""

import pytest
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.dir_brute import DirBrutePlugin
from bbf.core.database.models import Finding, FindingStatus

# Test Configuration
TEST_BASE_URL = "http://example.com"
TEST_WORDLIST = ["test", "dev", "staging", "prod"]
TEST_PERF_WORDLIST = [f"dir{i}" for i in range(100)]  # 100 directories
TEST_CONCURRENT_SITES = [f"http://site{i}.example.com" for i in range(5)]  # 5 sites
TEST_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html"]

# Test Data
KNOWN_PATHS = {
    "/admin": (200, "Admin Panel"),
    "/login": (200, "Login Page"),
    "/api": (200, "API Documentation"),
    "/backup": (403, "Access Denied"),
    "/.git": (403, "Access Denied"),
    "/wp-config.php": (403, "Access Denied"),
    "/config.php": (403, "Access Denied"),
    "/.env": (403, "Access Denied"),
    "/robots.txt": (200, "User-agent: *\nDisallow: /admin/"),
    "/sitemap.xml": (200, "<?xml version='1.0' encoding='UTF-8'?>")
}

class TestDirBrutePlugin(PluginIntegrationTest):
    """
    Test suite for Directory Bruteforce Plugin integration.
    
    This class implements comprehensive tests for the Directory Bruteforce Plugin,
    covering all aspects of its functionality from basic discovery to advanced features.
    
    Attributes:
        plugin_name (str): Name of the plugin being tested
        http_mock (AsyncMock): Mocked HTTP client
    """
    
    @property
    def plugin_name(self) -> str:
        """
        Return the name of the plugin being tested.
        
        Returns:
            str: Plugin name
        """
        return "dir_brute"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self) -> None:
        """
        Set up mock responses for directory bruteforcing.
        
        This fixture initializes mock HTTP responses for various test scenarios,
        including basic requests, custom wordlists, and error conditions.
        """
        super().setup_mocks()
        self.http_mock.get.side_effect = self._mock_get
        self.http_mock.head.side_effect = self._mock_head
    
    async def _mock_get(self, url: str, **kwargs: Any) -> ClientResponse:
        """
        Mock HTTP GET responses.
        
        Args:
            url: URL to request
            **kwargs: Additional request parameters
        
        Returns:
            ClientResponse: Mock HTTP response
        """
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        path = url.split("/", 3)[-1] if "/" in url else ""
        if path in KNOWN_PATHS:
            status, body = KNOWN_PATHS[path]
            response.status = status
            response.headers = {
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": str(len(body))
            }
            response.text.return_value = body
        else:
            response.status = 404
            response.headers = {}
            response.text.return_value = "Not Found"
        
        return response
    
    async def _mock_head(self, url: str, **kwargs: Any) -> ClientResponse:
        """
        Mock HTTP HEAD responses.
        
        Args:
            url: URL to request
            **kwargs: Additional request parameters
        
        Returns:
            ClientResponse: Mock HTTP response
        """
        return await self._mock_get(url, **kwargs)

class TestBasicFunctionality(TestDirBrutePlugin):
    """Tests for basic directory bruteforce functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_directory_bruteforce(self) -> None:
        """
        Test basic directory bruteforcing.
        
        This test verifies that the plugin can:
        1. Discover common directories and files
        2. Identify sensitive paths
        3. Store findings with correct metadata
        4. Handle different HTTP status codes
        """
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "dir_brute",
                "confidence": 0.9,
                "metadata": {
                    "resources": [
                        {
                            "path": "/admin",
                            "status": 200,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 11
                        },
                        {
                            "path": "/login",
                            "status": 200,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 10
                        },
                        {
                            "path": "/api",
                            "status": 200,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 16
                        }
                    ],
                    "sensitive_paths": [
                        {
                            "path": "/backup",
                            "status": 403,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 13
                        },
                        {
                            "path": "/.git",
                            "status": 403,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 13
                        },
                        {
                            "path": "/wp-config.php",
                            "status": 403,
                            "type": "file",
                            "content_type": "text/html",
                            "content_length": 13
                        }
                    ],
                    "techniques": ["directory_bruteforce"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestCustomWordlist(TestDirBrutePlugin):
    """Tests for custom wordlist directory bruteforcing."""
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_with_custom_wordlist(self) -> None:
        """
        Test directory bruteforcing with custom wordlist.
        
        This test verifies that the plugin can:
        1. Process a custom wordlist for directory discovery
        2. Handle multiple directories efficiently
        3. Store findings with appropriate metadata
        """
        # Mock responses for custom wordlist
        async def mock_custom_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in TEST_WORDLIST:
                response.status = 200
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": "10"
                }
                response.text.return_value = "Test Page"
            else:
                response.status = 404
                response.headers = {}
                response.text.return_value = "Not Found"
            
            return response
        
        self.http_mock.get.side_effect = mock_custom_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "dir_brute",
                "confidence": 0.9,
                "metadata": {
                    "resources": [
                        {
                            "path": f"/{path}",
                            "status": 200,
                            "type": "directory",
                            "content_type": "text/html",
                            "content_length": 10
                        }
                        for path in TEST_WORDLIST
                    ],
                    "techniques": ["directory_bruteforce"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestErrorHandling(TestDirBrutePlugin):
    """Tests for error handling during directory bruteforcing."""
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_error_handling(self) -> None:
        """
        Test error handling during directory bruteforcing.
        
        This test verifies that the plugin:
        1. Handles HTTP request failures gracefully
        2. Reports errors appropriately
        3. Maintains data integrity during failures
        """
        # Mock HTTP request to raise an exception
        self.http_mock.get.side_effect = Exception("Connection error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(TEST_BASE_URL)
        assert results["status"] == "error"
        assert "error" in results
        assert "Connection error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(
            TEST_BASE_URL,
            source="dir_brute",
            expected_count=0
        )

class TestPerformance(TestDirBrutePlugin):
    """Tests for directory bruteforce performance."""
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_performance(self) -> None:
        """
        Test directory bruteforcing performance.
        
        This test verifies that the plugin:
        1. Handles large wordlists efficiently
        2. Completes within acceptable time limits
        3. Maintains performance under load
        """
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in TEST_PERF_WORDLIST:
                response.status = 200
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": "10"
                }
                response.text.return_value = "Test Page"
            else:
                response.status = 404
                response.headers = {}
                response.text.return_value = "Not Found"
            
            return response
        
        self.http_mock.get.side_effect = mock_perf_get
        
        # Test performance with 100 directories
        await self.assert_performance(
            self.execute_plugin,
            TEST_BASE_URL,
            max_time=10.0  # Should complete within 10 seconds
        )
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_concurrent(self) -> None:
        """
        Test concurrent directory bruteforcing.
        
        This test verifies that the plugin:
        1. Handles multiple targets efficiently
        2. Respects concurrency limits
        3. Maintains performance under concurrent load
        """
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in ["admin", "login", "api"]:
                response.status = 200
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": "10"
                }
                response.text.return_value = "Test Page"
            else:
                response.status = 404
                response.headers = {}
                response.text.return_value = "Not Found"
            
            return response
        
        self.http_mock.get.side_effect = mock_concurrent_get
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in TEST_CONCURRENT_SITES],
            max_time=15.0,  # Should complete within 15 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )

class TestDataManagement(TestDirBrutePlugin):
    """Tests for finding updates and metadata management."""
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_metadata_merging(self) -> None:
        """
        Test metadata merging for directory findings.
        
        This test verifies that the plugin:
        1. Updates findings with new information
        2. Preserves existing metadata
        3. Merges techniques correctly
        4. Maintains data integrity during updates
        """
        # First scan
        await self.execute_plugin(TEST_BASE_URL)
        finding = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "dir_brute"
        )
        
        # Update with new metadata
        new_paths = {
            "/new-admin": (200, "New Admin Panel"),
            "/new-api": (200, "New API Documentation")
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in new_paths:
                status, body = new_paths[path]
                response.status = status
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": str(len(body))
                }
                response.text.return_value = body
            else:
                return await self._mock_get(url, **kwargs)
        
        self.http_mock.get.side_effect = mock_updated_get
        
        await self.execute_plugin(TEST_BASE_URL)
        updated = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "dir_brute"
        )
        
        # Verify metadata merging
        assert len(updated.metadata["resources"]) > len(finding.metadata["resources"])
        assert any(r["path"] == "/new-admin" for r in updated.metadata["resources"])
        assert any(r["path"] == "/new-api" for r in updated.metadata["resources"])
        assert "directory_bruteforce" in updated.metadata["techniques"]

class TestExtensionHandling(TestDirBrutePlugin):
    """Tests for file extension bruteforcing."""
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_with_extensions(self) -> None:
        """
        Test directory bruteforcing with file extensions.
        
        This test verifies that the plugin can:
        1. Discover files with different extensions
        2. Handle extension-based bruteforcing
        3. Store findings with appropriate metadata
        """
        # Mock responses for extension testing
        async def mock_ext_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if any(path.endswith(ext) for ext in TEST_EXTENSIONS):
                response.status = 200
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": "10"
                }
                response.text.return_value = "Test File"
            else:
                response.status = 404
                response.headers = {}
                response.text.return_value = "Not Found"
            
            return response
        
        self.http_mock.get.side_effect = mock_ext_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "dir_brute",
                "confidence": 0.9,
                "metadata": {
                    "resources": [
                        {
                            "path": f"/test{ext}",
                            "status": 200,
                            "type": "file",
                            "content_type": "text/html",
                            "content_length": 10
                        }
                        for ext in TEST_EXTENSIONS
                    ],
                    "techniques": ["directory_bruteforce", "extension_bruteforce"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings) 