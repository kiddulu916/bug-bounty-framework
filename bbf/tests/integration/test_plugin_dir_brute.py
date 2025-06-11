"""Integration tests for the Directory Bruteforce Plugin."""

import pytest
from typing import Dict, Any, List
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.dir_brute import DirBrutePlugin

class TestDirBrutePlugin(PluginIntegrationTest):
    """Test suite for Directory Bruteforce Plugin integration."""
    
    @property
    def plugin_name(self) -> str:
        return "dir_brute"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Set up mock responses for directory bruteforcing."""
        super().setup_mocks()
        
        # Mock HTTP responses
        self.http_mock.get.side_effect = self._mock_get
        self.http_mock.head.side_effect = self._mock_head
    
    async def _mock_get(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP GET responses."""
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        # Define known paths and their responses
        known_paths = {
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
        
        path = url.split("/", 3)[-1] if "/" in url else ""
        if path in known_paths:
            status, body = known_paths[path]
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
    
    async def _mock_head(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP HEAD responses."""
        return await self._mock_get(url, **kwargs)
    
    @pytest.mark.asyncio
    async def test_basic_directory_bruteforce(self):
        """Test basic directory bruteforcing."""
        target = "http://example.com"
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
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_with_custom_wordlist(self):
        """Test directory bruteforcing with custom wordlist."""
        target = "http://example.com"
        wordlist = ["test", "dev", "staging", "prod"]
        
        # Mock responses for custom wordlist
        async def mock_custom_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in wordlist:
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
                        for path in wordlist
                    ],
                    "techniques": ["directory_bruteforce"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_error_handling(self):
        """Test error handling during directory bruteforcing."""
        target = "http://example.com"
        
        # Mock HTTP request to raise an exception
        self.http_mock.get.side_effect = Exception("Connection error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(target)
        assert results["status"] == "error"
        assert "error" in results
        assert "Connection error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(target, source="dir_brute", expected_count=0)
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_performance(self):
        """Test directory bruteforcing performance."""
        target = "http://example.com"
        wordlist = [f"dir{i}" for i in range(100)]  # 100 directories
        
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path in wordlist:
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
            target,
            max_time=10.0  # Should complete within 10 seconds
        )
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_concurrent(self):
        """Test concurrent directory bruteforcing."""
        targets = [
            f"http://site{i}.example.com" for i in range(5)
        ]  # 5 sites
        
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs) -> ClientResponse:
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
            [(target,) for target in targets],
            max_time=15.0,  # Should complete within 15 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_metadata_merging(self):
        """Test metadata merging for directory bruteforce findings."""
        target = "http://example.com"
        
        # First scan
        await self.execute_plugin(target)
        finding = await self.assert_finding_exists(
            target,
            "example.com",
            "dir_brute"
        )
        
        # Update with new metadata
        new_metadata = {
            "resources": [
                {
                    "path": "/new-admin",
                    "status": 200,
                    "type": "directory",
                    "content_type": "text/html",
                    "content_length": 15
                }
            ]
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if path == "new-admin":
                response.status = 200
                response.headers = {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": "15"
                }
                response.text.return_value = "New Admin Panel"
            else:
                response.status = 404
                response.headers = {}
                response.text.return_value = "Not Found"
            
            return response
        
        self.http_mock.get.side_effect = mock_updated_get
        
        await self.execute_plugin(target)
        updated = await self.assert_finding_exists(
            target,
            "example.com",
            "dir_brute"
        )
        
        # Verify metadata merging
        assert any(r["path"] == "/new-admin" for r in updated.metadata["resources"])  # New resource
        assert any(r["path"] == "/admin" for r in updated.metadata["resources"])  # Preserved resource
        assert "sensitive_paths" in updated.metadata  # Preserved metadata
        assert "techniques" in updated.metadata  # Preserved metadata
    
    @pytest.mark.asyncio
    async def test_directory_bruteforce_with_extensions(self):
        """Test directory bruteforcing with file extensions."""
        target = "http://example.com"
        extensions = [".php", ".asp", ".aspx", ".jsp"]
        
        # Mock responses for file extensions
        async def mock_ext_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            path = url.split("/", 3)[-1] if "/" in url else ""
            
            if any(path.endswith(ext) for ext in extensions):
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
                            "content_length": 10,
                            "extension": ext
                        }
                        for ext in extensions
                    ],
                    "techniques": ["file_bruteforce"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings) 