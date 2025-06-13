"""
Integration tests for the Web Technology Detection Plugin.

This module contains comprehensive test cases for the Web Technology Detection Plugin,
verifying its functionality for discovering and analyzing web technologies and frameworks.

Test Categories:
- Basic Functionality: Core web technology detection features
- JavaScript Analysis: Framework and library detection in JS files
- Error Handling: Plugin behavior during failures
- Performance: Execution time and resource usage
- Concurrent Execution: Multi-target scanning
- Data Management: Finding updates and metadata handling
- Header Analysis: Custom header and technology detection

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Technology discovery and analysis
2. JavaScript Analysis: JS framework and library detection
3. Error Handling: Network failures and error recovery
4. Performance: Execution time and resource usage
5. Concurrent Execution: Multi-target scanning efficiency
6. Data Management: Finding updates and metadata merging
7. Header Analysis: Custom header processing and technology detection
"""

import pytest
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse, ClientSession

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.web_tech import WebTechPlugin
from bbf.core.database.models import Finding, FindingStatus

# Test Configuration
TEST_BASE_URL = "http://example.com"
TEST_CONCURRENT_SITES = [f"http://site{i}.example.com" for i in range(5)]  # 5 sites

# Test Data
KNOWN_TECHNOLOGIES = {
    "server": {
        "name": "nginx",
        "version": "1.18.0",
        "header": "Server",
        "value": "nginx/1.18.0"
    },
    "language": {
        "name": "php",
        "version": "7.4.0",
        "header": "X-Powered-By",
        "value": "PHP/7.4.0"
    },
    "frameworks": {
        "jquery": {
            "version": "3.6.0",
            "script": "/static/jquery-3.6.0.min.js",
            "content": "/* jQuery v3.6.0 */"
        },
        "bootstrap": {
            "version": "5.1.3",
            "script": "/static/bootstrap-5.1.3.min.js",
            "content": "/* Bootstrap v5.1.3 */"
        },
        "vue": {
            "version": "2.6.14",
            "script": "/static/vue.min.js",
            "content": "/* Vue.js v2.6.14 */",
            "attribute": "data-vue"
        }
    }
}

class TestWebTechPlugin(PluginIntegrationTest):
    """
    Test suite for Web Technology Detection Plugin integration.
    
    This class implements comprehensive tests for the Web Technology Detection Plugin,
    covering all aspects of its functionality from basic technology discovery to
    advanced framework detection.
    
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
        return "web_tech"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self) -> None:
        """
        Set up mock responses for web technology detection.
        
        This fixture initializes mock HTTP responses for various test scenarios,
        including basic requests, JavaScript analysis, and error conditions.
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
        
        if "example.com" in url:
            response.status = 200
            response.headers = {
                KNOWN_TECHNOLOGIES["server"]["header"]: KNOWN_TECHNOLOGIES["server"]["value"],
                KNOWN_TECHNOLOGIES["language"]["header"]: KNOWN_TECHNOLOGIES["language"]["value"],
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Type": "text/html; charset=UTF-8"
            }
            
            # Generate HTML with framework references
            frameworks = KNOWN_TECHNOLOGIES["frameworks"]
            html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Example Site</title>
                    <script src="{frameworks['jquery']['script']}"></script>
                    <script src="{frameworks['bootstrap']['script']}"></script>
                </head>
                <body>
                    <div id="app" {frameworks['vue']['attribute']}="{frameworks['vue']['version']}"></div>
                </body>
                </html>
            """
            response.text.return_value = html
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

class TestBasicFunctionality(TestWebTechPlugin):
    """Tests for basic web technology detection."""
    
    @pytest.mark.asyncio
    async def test_basic_web_tech_detection(self) -> None:
        """
        Test basic web technology detection.
        
        This test verifies that the plugin can:
        1. Discover web technologies from headers
        2. Identify frameworks from HTML content
        3. Store findings with correct metadata
        4. Handle different technology types
        """
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "web_tech",
                "confidence": 0.9,
                "metadata": {
                    "web_tech": [
                        KNOWN_TECHNOLOGIES["server"]["name"],
                        KNOWN_TECHNOLOGIES["language"]["name"],
                        *KNOWN_TECHNOLOGIES["frameworks"].keys()
                    ],
                    "versions": {
                        KNOWN_TECHNOLOGIES["server"]["name"]: KNOWN_TECHNOLOGIES["server"]["version"],
                        KNOWN_TECHNOLOGIES["language"]["name"]: KNOWN_TECHNOLOGIES["language"]["version"],
                        **{name: data["version"] for name, data in KNOWN_TECHNOLOGIES["frameworks"].items()}
                    },
                    "headers": {
                        KNOWN_TECHNOLOGIES["server"]["header"]: KNOWN_TECHNOLOGIES["server"]["value"],
                        KNOWN_TECHNOLOGIES["language"]["header"]: KNOWN_TECHNOLOGIES["language"]["value"],
                        "X-Frame-Options": "SAMEORIGIN"
                    },
                    "techniques": ["header_analysis", "content_analysis"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestJavaScriptAnalysis(TestWebTechPlugin):
    """Tests for JavaScript framework and library detection."""
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_with_js_analysis(self) -> None:
        """
        Test web technology detection with JavaScript analysis.
        
        This test verifies that the plugin can:
        1. Analyze JavaScript files for frameworks
        2. Extract version information from JS content
        3. Store findings with appropriate metadata
        4. Handle various JS framework formats
        """
        # Mock JavaScript file responses
        async def mock_js_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {"Content-Type": "application/javascript"}
            
            frameworks = KNOWN_TECHNOLOGIES["frameworks"]
            for name, data in frameworks.items():
                if data["script"] in url:
                    response.text.return_value = data["content"]
                    return response
            
            response.text.return_value = ""
            return response
        
        self.http_mock.get.side_effect = mock_js_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "web_tech",
                "confidence": 0.95,
                "metadata": {
                    "web_tech": list(KNOWN_TECHNOLOGIES["frameworks"].keys()),
                    "versions": {
                        name: data["version"]
                        for name, data in KNOWN_TECHNOLOGIES["frameworks"].items()
                    },
                    "techniques": ["js_analysis"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestErrorHandling(TestWebTechPlugin):
    """Tests for error handling during web technology detection."""
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_error_handling(self) -> None:
        """
        Test error handling during web technology detection.
        
        This test verifies that the plugin:
        1. Handles network failures gracefully
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
            source="web_tech",
            expected_count=0
        )

class TestPerformance(TestWebTechPlugin):
    """Tests for web technology detection performance."""
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_performance(self) -> None:
        """
        Test web technology detection performance.
        
        This test verifies that the plugin:
        1. Handles multiple requests efficiently
        2. Completes within acceptable time limits
        3. Maintains performance under load
        """
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                KNOWN_TECHNOLOGIES["server"]["header"]: KNOWN_TECHNOLOGIES["server"]["value"],
                KNOWN_TECHNOLOGIES["language"]["header"]: KNOWN_TECHNOLOGIES["language"]["value"]
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_perf_get
        
        # Test performance with multiple requests
        await self.assert_performance(
            self.execute_plugin,
            TEST_BASE_URL,
            max_time=5.0  # Should complete within 5 seconds
        )
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_concurrent(self) -> None:
        """
        Test concurrent web technology detection.
        
        This test verifies that the plugin:
        1. Handles multiple targets efficiently
        2. Respects concurrency limits
        3. Maintains performance under concurrent load
        """
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                KNOWN_TECHNOLOGIES["server"]["header"]: KNOWN_TECHNOLOGIES["server"]["value"],
                KNOWN_TECHNOLOGIES["language"]["header"]: KNOWN_TECHNOLOGIES["language"]["value"]
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_concurrent_get
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in TEST_CONCURRENT_SITES],
            max_time=10.0,  # Should complete within 10 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )

class TestDataManagement(TestWebTechPlugin):
    """Tests for finding updates and metadata management."""
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_metadata_merging(self) -> None:
        """
        Test metadata merging for web technology findings.
        
        This test verifies that the plugin:
        1. Updates findings with new information
        2. Preserves existing metadata
        3. Merges technology lists correctly
        4. Maintains data integrity during updates
        """
        # First scan
        await self.execute_plugin(TEST_BASE_URL)
        finding = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "web_tech"
        )
        
        # Update with new metadata
        new_tech = {
            "name": "react",
            "version": "17.0.2",
            "script": "/static/react.production.min.js",
            "content": "/* React v17.0.2 */"
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                KNOWN_TECHNOLOGIES["server"]["header"]: KNOWN_TECHNOLOGIES["server"]["value"],
                KNOWN_TECHNOLOGIES["language"]["header"]: KNOWN_TECHNOLOGIES["language"]["value"]
            }
            
            if new_tech["script"] in url:
                response.headers["Content-Type"] = "application/javascript"
                response.text.return_value = new_tech["content"]
            else:
                response.headers["Content-Type"] = "text/html; charset=UTF-8"
                html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Example Site</title>
                        <script src="{new_tech['script']}"></script>
                    </head>
                    <body>
                        <div id="root"></div>
                    </body>
                    </html>
                """
                response.text.return_value = html
            
            return response
        
        self.http_mock.get.side_effect = mock_updated_get
        
        await self.execute_plugin(TEST_BASE_URL)
        updated = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "web_tech"
        )
        
        # Verify metadata merging
        assert new_tech["name"] in updated.metadata["web_tech"]  # New technology
        assert updated.metadata["versions"][new_tech["name"]] == new_tech["version"]  # New version
        assert KNOWN_TECHNOLOGIES["server"]["name"] in updated.metadata["web_tech"]  # Preserved technology
        assert "techniques" in updated.metadata  # Preserved metadata

class TestHeaderAnalysis(TestWebTechPlugin):
    """Tests for custom header and technology detection."""
    
    @pytest.mark.asyncio
    async def test_web_tech_detection_with_custom_headers(self) -> None:
        """
        Test web technology detection with custom headers.
        
        This test verifies that the plugin can:
        1. Process custom technology headers
        2. Extract version information from headers
        3. Store findings with appropriate metadata
        4. Handle various header formats
        """
        # Mock responses with custom headers
        async def mock_custom_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            response.status = 200
            response.headers = {
                "Server": "CustomServer/2.0",
                "X-Powered-By": "CustomFramework/1.2.3",
                "X-Technology": "CustomTech/4.5.6",
                "Content-Type": "text/html; charset=UTF-8"
            }
            response.text.return_value = "<html><body>Test</body></html>"
            return response
        
        self.http_mock.get.side_effect = mock_custom_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "web_tech",
                "confidence": 0.9,
                "metadata": {
                    "web_tech": [
                        "CustomServer",
                        "CustomFramework",
                        "CustomTech"
                    ],
                    "versions": {
                        "CustomServer": "2.0",
                        "CustomFramework": "1.2.3",
                        "CustomTech": "4.5.6"
                    },
                    "headers": {
                        "Server": "CustomServer/2.0",
                        "X-Powered-By": "CustomFramework/1.2.3",
                        "X-Technology": "CustomTech/4.5.6"
                    },
                    "techniques": ["header_analysis"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings) 