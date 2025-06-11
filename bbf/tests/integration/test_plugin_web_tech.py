"""Integration tests for the Web Technology Detection Plugin."""

import pytest
from typing import Dict, Any, List
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse, ClientSession

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.web_tech import WebTechPlugin

class TestWebTechPlugin(PluginIntegrationTest):
    """Test suite for Web Technology Detection Plugin integration."""
    
    @property
    def plugin_name(self) -> str:
        return "web_tech"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Set up mock responses for web technology detection."""
        super().setup_mocks()
        
        # Mock HTTP responses
        self.http_mock.get.side_effect = self._mock_get
        self.http_mock.head.side_effect = self._mock_head
    
    async def _mock_get(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP GET responses."""
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        if "example.com" in url:
            response.status = 200
            response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0",
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Type": "text/html; charset=UTF-8"
            }
            response.text.return_value = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Example Site</title>
                    <script src="/static/jquery-3.6.0.min.js"></script>
                    <script src="/static/bootstrap-5.1.3.min.js"></script>
                </head>
                <body>
                    <div id="app" data-vue="2.6.14"></div>
                </body>
                </html>
            """
        else:
            response.status = 404
            response.headers = {}
            response.text.return_value = "Not Found"
        
        return response
    
    async def _mock_head(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP HEAD responses."""
        return await self._mock_get(url, **kwargs)
    
    @pytest.mark.asyncio
    async def test_basic_web_tech_detection(self):
        """Test basic web technology detection."""
        target = "http://example.com"
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "web_tech",
                "confidence": 0.9,
                "metadata": {
                    "web_tech": [
                        "nginx",
                        "php",
                        "jquery",
                        "bootstrap",
                        "vue.js"
                    ],
                    "versions": {
                        "nginx": "1.18.0",
                        "php": "7.4.0",
                        "jquery": "3.6.0",
                        "bootstrap": "5.1.3",
                        "vue.js": "2.6.14"
                    },
                    "headers": {
                        "Server": "nginx/1.18.0",
                        "X-Powered-By": "PHP/7.4.0",
                        "X-Frame-Options": "SAMEORIGIN"
                    },
                    "techniques": ["header_analysis", "content_analysis"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_with_js_analysis(self):
        """Test web technology detection with JavaScript analysis."""
        target = "http://example.com"
        
        # Mock JavaScript file responses
        async def mock_js_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {"Content-Type": "application/javascript"}
            
            if "jquery" in url:
                response.text.return_value = "/* jQuery v3.6.0 */"
            elif "bootstrap" in url:
                response.text.return_value = "/* Bootstrap v5.1.3 */"
            elif "vue" in url:
                response.text.return_value = "/* Vue.js v2.6.14 */"
            else:
                response.text.return_value = ""
            
            return response
        
        self.http_mock.get.side_effect = mock_js_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "web_tech",
                "confidence": 0.95,
                "metadata": {
                    "web_tech": [
                        "jquery",
                        "bootstrap",
                        "vue.js"
                    ],
                    "versions": {
                        "jquery": "3.6.0",
                        "bootstrap": "5.1.3",
                        "vue.js": "2.6.14"
                    },
                    "techniques": ["js_analysis"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_error_handling(self):
        """Test error handling during web technology detection."""
        target = "http://example.com"
        
        # Mock HTTP request to raise an exception
        self.http_mock.get.side_effect = Exception("Connection error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(target)
        assert results["status"] == "error"
        assert "error" in results
        assert "Connection error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(target, source="web_tech", expected_count=0)
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_performance(self):
        """Test web technology detection performance."""
        target = "http://example.com"
        
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0"
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_perf_get
        
        # Test performance with multiple requests
        await self.assert_performance(
            self.execute_plugin,
            target,
            max_time=5.0  # Should complete within 5 seconds
        )
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_concurrent(self):
        """Test concurrent web technology detection."""
        targets = [
            f"http://site{i}.example.com" for i in range(5)
        ]  # 5 sites
        
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0"
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_concurrent_get
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in targets],
            max_time=10.0,  # Should complete within 10 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_metadata_merging(self):
        """Test metadata merging for web technology findings."""
        target = "http://example.com"
        
        # First scan
        await self.execute_plugin(target)
        finding = await self.assert_finding_exists(
            target,
            "example.com",
            "web_tech"
        )
        
        # Update with new metadata
        new_metadata = {
            "web_tech": ["nginx", "php", "react"],  # Added react
            "versions": {
                "nginx": "1.18.0",
                "php": "7.4.0",
                "react": "17.0.2"  # New version
            }
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0",
                "X-React-Version": "17.0.2"
            }
            response.text.return_value = """
                <!DOCTYPE html>
                <html>
                <head>
                    <script src="/static/react-17.0.2.min.js"></script>
                </head>
                <body>
                    <div id="root"></div>
                </body>
                </html>
            """
            return response
        
        self.http_mock.get.side_effect = mock_updated_get
        
        await self.execute_plugin(target)
        updated = await self.assert_finding_exists(
            target,
            "example.com",
            "web_tech"
        )
        
        # Verify metadata merging
        assert "react" in updated.metadata["web_tech"]  # Added technology
        assert updated.metadata["versions"]["react"] == "17.0.2"  # New version
        assert "nginx" in updated.metadata["web_tech"]  # Preserved technology
        assert updated.metadata["versions"]["nginx"] == "1.18.0"  # Preserved version
        assert "headers" in updated.metadata  # Preserved metadata
        assert "techniques" in updated.metadata  # Preserved metadata
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_with_custom_headers(self):
        """Test web technology detection with custom headers."""
        target = "http://example.com"
        custom_headers = {
            "User-Agent": "BBF-Test/1.0",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9"
        }
        
        # Mock response with custom headers
        async def mock_custom_get(url: str, **kwargs) -> ClientResponse:
            assert "headers" in kwargs
            assert kwargs["headers"]["User-Agent"] == custom_headers["User-Agent"]
            assert kwargs["headers"]["Accept"] == custom_headers["Accept"]
            
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0"
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_custom_get
        
        await self.execute_plugin(target, headers=custom_headers)
        finding = await self.assert_finding_exists(
            target,
            "example.com",
            "web_tech"
        )
        
        # Verify custom headers were used
        assert finding.metadata["request_headers"] == custom_headers 