"""
Integration tests for the Vulnerability Scanner Plugin.

This module contains comprehensive test cases for the Vulnerability Scanner Plugin,
verifying its functionality for detecting various types of security vulnerabilities.

Test Categories:
- Basic Functionality: Core vulnerability scanning features
- Custom Payloads: Testing with user-defined payloads
- Error Handling: Plugin behavior during failures
- Performance: Execution time and resource usage
- Concurrent Execution: Multi-target scanning
- Data Management: Finding updates and metadata handling
- Header Analysis: Custom header and injection testing

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Common vulnerability detection
2. Custom Payloads: User-defined test payloads
3. Error Handling: Network failures and error recovery
4. Performance: Execution time and resource usage
5. Concurrent Execution: Multi-target scanning efficiency
6. Data Management: Finding updates and metadata merging
7. Header Analysis: Custom header processing and injection testing
"""

import pytest
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.vuln.scanner import VulnScannerPlugin
from bbf.core.database.models import Finding, FindingStatus

# Test Configuration
TEST_BASE_URL = "http://example.com"
TEST_CONCURRENT_SITES = [f"http://site{i}.example.com" for i in range(5)]  # 5 sites

# Test Data
VULNERABLE_ENDPOINTS = {
    "GET": {
        "/search?q=1'": {
            "status": 500,
            "body": "SQL syntax error near '1'",
            "headers": {"Content-Type": "text/html"},
            "vuln_type": "sql_injection",
            "severity": "high"
        },
        "/search?q=<script>alert(1)</script>": {
            "status": 200,
            "body": "<script>alert(1)</script>",
            "headers": {"Content-Type": "text/html"},
            "vuln_type": "xss",
            "severity": "medium"
        },
        "/redirect?url=https://evil.com": {
            "status": 302,
            "body": "",
            "headers": {"Location": "https://evil.com"},
            "vuln_type": "open_redirect",
            "severity": "medium"
        },
        "/include?file=../../../etc/passwd": {
            "status": 200,
            "body": "root:x:0:0:root:/root:/bin/bash",
            "headers": {"Content-Type": "text/plain"},
            "vuln_type": "path_traversal",
            "severity": "high"
        },
        "/ping?host=127.0.0.1": {
            "status": 200,
            "body": "PING 127.0.0.1",
            "headers": {"Content-Type": "text/plain"},
            "vuln_type": "command_injection",
            "severity": "high"
        },
        "/proxy?url=http://internal": {
            "status": 200,
            "body": "Internal Service Response",
            "headers": {"Content-Type": "text/plain"},
            "vuln_type": "ssrf",
            "severity": "high"
        },
        "/xml?data=<!DOCTYPE": {
            "status": 200,
            "body": "XML parsing error",
            "headers": {"Content-Type": "text/xml"},
            "vuln_type": "xxe",
            "severity": "high"
        }
    },
    "POST": {
        "/login": {
            "status": 200,
            "body": "Invalid username or password",
            "headers": {"Content-Type": "text/html"},
            "vuln_type": "auth_bypass",
            "severity": "high"
        },
        "/api/user": {
            "status": 200,
            "body": "User created successfully",
            "headers": {"Content-Type": "application/json"},
            "vuln_type": "idor",
            "severity": "medium"
        }
    }
}

CUSTOM_PAYLOADS = {
    "sql_injection": ["1' OR '1'='1", "1' UNION SELECT NULL--"],
    "xss": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "open_redirect": ["//evil.com", "\\evil.com"]
}

class TestVulnScannerPlugin(PluginIntegrationTest):
    """
    Test suite for Vulnerability Scanner Plugin integration.
    
    This class implements comprehensive tests for the Vulnerability Scanner Plugin,
    covering all aspects of its functionality from basic vulnerability detection to
    advanced security testing.
    
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
        return "vuln_scanner"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self) -> None:
        """
        Set up mock responses for vulnerability scanning.
        
        This fixture initializes mock HTTP responses for various test scenarios,
        including basic requests, custom payloads, and error conditions.
        """
        super().setup_mocks()
        self.http_mock.get.side_effect = self._mock_get
        self.http_mock.post.side_effect = self._mock_post
    
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
        
        # Check if URL matches any vulnerable endpoint
        for endpoint, data in VULNERABLE_ENDPOINTS["GET"].items():
            if endpoint in url:
                response.status = data["status"]
                response.headers = data["headers"]
                response.text.return_value = data["body"]
                return response
        
        # Default response for non-vulnerable endpoints
        response.status = 200
        response.headers = {"Content-Type": "text/html"}
        response.text.return_value = "Normal Response"
        return response
    
    async def _mock_post(self, url: str, **kwargs: Any) -> ClientResponse:
        """
        Mock HTTP POST responses.
        
        Args:
            url: URL to request
            **kwargs: Additional request parameters
        
        Returns:
            ClientResponse: Mock HTTP response
        """
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        # Check if URL matches any vulnerable endpoint
        for endpoint, data in VULNERABLE_ENDPOINTS["POST"].items():
            if endpoint in url:
                response.status = data["status"]
                response.headers = data["headers"]
                response.text.return_value = data["body"]
                return response
        
        # Default response for non-vulnerable endpoints
        response.status = 200
        response.headers = {"Content-Type": "text/html"}
        response.text.return_value = "Normal Response"
        return response

class TestBasicFunctionality(TestVulnScannerPlugin):
    """Tests for basic vulnerability scanning."""
    
    @pytest.mark.asyncio
    async def test_basic_vulnerability_scanning(self) -> None:
        """
        Test basic vulnerability scanning.
        
        This test verifies that the plugin can:
        1. Detect common vulnerabilities (SQLi, XSS, etc.)
        2. Identify vulnerability types and severity
        3. Store findings with correct metadata
        4. Handle different vulnerability categories
        """
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "vuln_scanner",
                "confidence": 0.9,
                "metadata": {
                    "vulnerabilities": [
                        {
                            "type": data["vuln_type"],
                            "endpoint": endpoint.split("?")[0],
                            "parameter": endpoint.split("?")[1].split("=")[0],
                            "payload": endpoint.split("=")[1],
                            "evidence": data["body"],
                            "severity": data["severity"]
                        }
                        for endpoint, data in VULNERABLE_ENDPOINTS["GET"].items()
                        if "?" in endpoint
                    ],
                    "techniques": ["vulnerability_scanning"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestCustomPayloads(TestVulnScannerPlugin):
    """Tests for vulnerability scanning with custom payloads."""
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_with_custom_payloads(self) -> None:
        """
        Test vulnerability scanning with custom payloads.
        
        This test verifies that the plugin can:
        1. Use user-defined test payloads
        2. Detect vulnerabilities with custom inputs
        3. Store findings with appropriate metadata
        4. Handle various payload formats
        """
        # Mock responses for custom payloads
        async def mock_custom_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            # Check for custom payloads in URL
            for vuln_type, payloads in CUSTOM_PAYLOADS.items():
                for payload in payloads:
                    if payload in url:
                        if vuln_type == "sql_injection":
                            response.status = 500
                            response.headers = {"Content-Type": "text/html"}
                            response.text.return_value = "SQL syntax error"
                        elif vuln_type == "xss":
                            response.status = 200
                            response.headers = {"Content-Type": "text/html"}
                            response.text.return_value = payload
                        elif vuln_type == "open_redirect":
                            response.status = 302
                            response.headers = {"Location": payload}
                            response.text.return_value = ""
                        return response
            
            # Default response
            response.status = 200
            response.headers = {"Content-Type": "text/html"}
            response.text.return_value = "Normal Response"
            return response
        
        self.http_mock.get.side_effect = mock_custom_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "vuln_scanner",
                "confidence": 0.9,
                "metadata": {
                    "vulnerabilities": [
                        {
                            "type": vuln_type,
                            "endpoint": "/search",
                            "parameter": "q",
                            "payload": payload,
                            "evidence": f"Detected {vuln_type} vulnerability",
                            "severity": "high" if vuln_type == "sql_injection" else "medium"
                        }
                        for vuln_type, payloads in CUSTOM_PAYLOADS.items()
                        for payload in payloads
                    ],
                    "techniques": ["vulnerability_scanning"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings)

class TestErrorHandling(TestVulnScannerPlugin):
    """Tests for error handling during vulnerability scanning."""
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_error_handling(self) -> None:
        """
        Test error handling during vulnerability scanning.
        
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
            source="vuln_scanner",
            expected_count=0
        )

class TestPerformance(TestVulnScannerPlugin):
    """Tests for vulnerability scanning performance."""
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_performance(self) -> None:
        """
        Test vulnerability scanning performance.
        
        This test verifies that the plugin:
        1. Handles multiple requests efficiently
        2. Completes within acceptable time limits
        3. Maintains performance under load
        """
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            # Simulate different response times for different endpoints
            if "search" in url:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Search Results"
            elif "login" in url:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Login Page"
            else:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Normal Response"
            
            return response
        
        self.http_mock.get.side_effect = mock_perf_get
        
        # Test performance with multiple endpoints
        await self.assert_performance(
            self.execute_plugin,
            TEST_BASE_URL,
            max_time=30.0  # Should complete within 30 seconds
        )
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_concurrent(self) -> None:
        """
        Test concurrent vulnerability scanning.
        
        This test verifies that the plugin:
        1. Handles multiple targets efficiently
        2. Respects concurrency limits
        3. Maintains performance under concurrent load
        """
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            # Simulate different vulnerabilities for different sites
            if "site0" in url and "search" in url:
                response.status = 500
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "SQL syntax error"
            elif "site1" in url and "search" in url:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "<script>alert(1)</script>"
            else:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Normal Response"
            
            return response
        
        self.http_mock.get.side_effect = mock_concurrent_get
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in TEST_CONCURRENT_SITES],
            max_time=60.0,  # Should complete within 60 seconds
            max_concurrent=2  # Maximum 2 concurrent scans
        )

class TestDataManagement(TestVulnScannerPlugin):
    """Tests for finding updates and metadata management."""
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_metadata_merging(self) -> None:
        """
        Test metadata merging for vulnerability findings.
        
        This test verifies that the plugin:
        1. Updates findings with new information
        2. Preserves existing metadata
        3. Merges vulnerability lists correctly
        4. Maintains data integrity during updates
        """
        # First scan
        await self.execute_plugin(TEST_BASE_URL)
        finding = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "vuln_scanner"
        )
        
        # Update with new metadata
        new_vuln = {
            "type": "new_vuln",
            "endpoint": "/api",
            "parameter": "id",
            "payload": "1'",
            "evidence": "New vulnerability found",
            "severity": "high"
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            if "/api" in url and "id=1'" in url:
                response.status = 500
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "New vulnerability found"
            else:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Normal Response"
            
            return response
        
        self.http_mock.get.side_effect = mock_updated_get
        
        await self.execute_plugin(TEST_BASE_URL)
        updated = await self.assert_finding_exists(
            TEST_BASE_URL,
            "example.com",
            "vuln_scanner"
        )
        
        # Verify metadata merging
        assert any(v["type"] == new_vuln["type"] for v in updated.metadata["vulnerabilities"])  # New vulnerability
        assert any(v["type"] == "sql_injection" for v in updated.metadata["vulnerabilities"])  # Preserved vulnerability
        assert "techniques" in updated.metadata  # Preserved metadata

class TestHeaderAnalysis(TestVulnScannerPlugin):
    """Tests for custom header and injection testing."""
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_with_custom_headers(self) -> None:
        """
        Test vulnerability scanning with custom headers.
        
        This test verifies that the plugin can:
        1. Process custom headers for testing
        2. Detect header-based vulnerabilities
        3. Store findings with appropriate metadata
        4. Handle various header injection scenarios
        """
        custom_headers = {
            "X-Custom-Header": "test",
            "Authorization": "Bearer test-token"
        }
        
        # Mock responses for custom headers
        async def mock_headers_get(url: str, **kwargs: Any) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            # Verify custom headers are present
            headers = kwargs.get("headers", {})
            assert all(header in headers for header in custom_headers)
            
            # Simulate vulnerability based on headers
            if headers.get("X-Custom-Header") == "test":
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Header-based vulnerability"
            else:
                response.status = 200
                response.headers = {"Content-Type": "text/html"}
                response.text.return_value = "Normal Response"
            
            return response
        
        self.http_mock.get.side_effect = mock_headers_get
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "vuln_scanner",
                "confidence": 0.9,
                "metadata": {
                    "vulnerabilities": [
                        {
                            "type": "header_injection",
                            "endpoint": "/search",
                            "parameter": "X-Custom-Header",
                            "payload": "test",
                            "evidence": "Header-based vulnerability",
                            "severity": "medium"
                        }
                    ],
                    "techniques": ["vulnerability_scanning"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_BASE_URL, expected_findings) 