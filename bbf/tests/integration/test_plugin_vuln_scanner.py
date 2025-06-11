"""Integration tests for the Vulnerability Scanner Plugin."""

import pytest
from typing import Dict, Any, List
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.vuln.scanner import VulnScannerPlugin

class TestVulnScannerPlugin(PluginIntegrationTest):
    """Test suite for Vulnerability Scanner Plugin integration."""
    
    @property
    def plugin_name(self) -> str:
        return "vuln_scanner"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Set up mock responses for vulnerability scanning."""
        super().setup_mocks()
        
        # Mock HTTP responses
        self.http_mock.get.side_effect = self._mock_get
        self.http_mock.post.side_effect = self._mock_post
    
    async def _mock_get(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP GET responses."""
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        # Define vulnerable endpoints and their responses
        vulnerable_endpoints = {
            "/search?q=1'": {
                "status": 500,
                "body": "SQL syntax error near '1'",
                "headers": {"Content-Type": "text/html"}
            },
            "/search?q=<script>alert(1)</script>": {
                "status": 200,
                "body": "<script>alert(1)</script>",
                "headers": {"Content-Type": "text/html"}
            },
            "/redirect?url=https://evil.com": {
                "status": 302,
                "body": "",
                "headers": {"Location": "https://evil.com"}
            },
            "/include?file=../../../etc/passwd": {
                "status": 200,
                "body": "root:x:0:0:root:/root:/bin/bash",
                "headers": {"Content-Type": "text/plain"}
            },
            "/ping?host=127.0.0.1": {
                "status": 200,
                "body": "PING 127.0.0.1",
                "headers": {"Content-Type": "text/plain"}
            },
            "/proxy?url=http://internal": {
                "status": 200,
                "body": "Internal Service Response",
                "headers": {"Content-Type": "text/plain"}
            },
            "/xml?data=<!DOCTYPE": {
                "status": 200,
                "body": "XML parsing error",
                "headers": {"Content-Type": "text/xml"}
            }
        }
        
        # Check if URL matches any vulnerable endpoint
        for endpoint, data in vulnerable_endpoints.items():
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
    
    async def _mock_post(self, url: str, **kwargs) -> ClientResponse:
        """Mock HTTP POST responses."""
        response = AsyncMock(spec=ClientResponse)
        response.url = url
        
        # Define vulnerable POST endpoints and their responses
        vulnerable_endpoints = {
            "/login": {
                "status": 200,
                "body": "Invalid username or password",
                "headers": {"Content-Type": "text/html"}
            },
            "/api/user": {
                "status": 200,
                "body": "User created successfully",
                "headers": {"Content-Type": "application/json"}
            }
        }
        
        # Check if URL matches any vulnerable endpoint
        for endpoint, data in vulnerable_endpoints.items():
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
    
    @pytest.mark.asyncio
    async def test_basic_vulnerability_scanning(self):
        """Test basic vulnerability scanning."""
        target = "http://example.com"
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "vuln_scanner",
                "confidence": 0.9,
                "metadata": {
                    "vulnerabilities": [
                        {
                            "type": "sql_injection",
                            "endpoint": "/search",
                            "parameter": "q",
                            "payload": "1'",
                            "evidence": "SQL syntax error near '1'",
                            "severity": "high"
                        },
                        {
                            "type": "xss",
                            "endpoint": "/search",
                            "parameter": "q",
                            "payload": "<script>alert(1)</script>",
                            "evidence": "Reflected XSS in response",
                            "severity": "medium"
                        },
                        {
                            "type": "open_redirect",
                            "endpoint": "/redirect",
                            "parameter": "url",
                            "payload": "https://evil.com",
                            "evidence": "Redirect to external domain",
                            "severity": "medium"
                        }
                    ],
                    "techniques": ["vulnerability_scanning"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_with_custom_payloads(self):
        """Test vulnerability scanning with custom payloads."""
        target = "http://example.com"
        custom_payloads = {
            "sql_injection": ["1' OR '1'='1", "1' UNION SELECT NULL--"],
            "xss": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "open_redirect": ["//evil.com", "\\evil.com"]
        }
        
        # Mock responses for custom payloads
        async def mock_custom_get(url: str, **kwargs) -> ClientResponse:
            response = AsyncMock(spec=ClientResponse)
            response.url = url
            
            # Check for custom payloads in URL
            for vuln_type, payloads in custom_payloads.items():
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
                        for vuln_type, payloads in custom_payloads.items()
                        for payload in payloads
                    ],
                    "techniques": ["vulnerability_scanning"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_error_handling(self):
        """Test error handling during vulnerability scanning."""
        target = "http://example.com"
        
        # Mock HTTP request to raise an exception
        self.http_mock.get.side_effect = Exception("Connection error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(target)
        assert results["status"] == "error"
        assert "error" in results
        assert "Connection error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(target, source="vuln_scanner", expected_count=0)
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_performance(self):
        """Test vulnerability scanning performance."""
        target = "http://example.com"
        
        # Mock responses for performance testing
        async def mock_perf_get(url: str, **kwargs) -> ClientResponse:
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
            target,
            max_time=30.0  # Should complete within 30 seconds
        )
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_concurrent(self):
        """Test concurrent vulnerability scanning."""
        targets = [
            f"http://site{i}.example.com" for i in range(5)
        ]  # 5 sites
        
        # Mock responses for concurrent testing
        async def mock_concurrent_get(url: str, **kwargs) -> ClientResponse:
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
            [(target,) for target in targets],
            max_time=60.0,  # Should complete within 60 seconds
            max_concurrent=2  # Maximum 2 concurrent scans
        )
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_metadata_merging(self):
        """Test metadata merging for vulnerability findings."""
        target = "http://example.com"
        
        # First scan
        await self.execute_plugin(target)
        finding = await self.assert_finding_exists(
            target,
            "example.com",
            "vuln_scanner"
        )
        
        # Update with new metadata
        new_metadata = {
            "vulnerabilities": [
                {
                    "type": "new_vuln",
                    "endpoint": "/api",
                    "parameter": "id",
                    "payload": "1'",
                    "evidence": "New vulnerability found",
                    "severity": "high"
                }
            ]
        }
        
        # Second scan with new metadata
        async def mock_updated_get(url: str, **kwargs) -> ClientResponse:
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
        
        await self.execute_plugin(target)
        updated = await self.assert_finding_exists(
            target,
            "example.com",
            "vuln_scanner"
        )
        
        # Verify metadata merging
        assert any(v["type"] == "new_vuln" for v in updated.metadata["vulnerabilities"])  # New vulnerability
        assert any(v["type"] == "sql_injection" for v in updated.metadata["vulnerabilities"])  # Preserved vulnerability
        assert "techniques" in updated.metadata  # Preserved metadata
    
    @pytest.mark.asyncio
    async def test_vulnerability_scanning_with_custom_headers(self):
        """Test vulnerability scanning with custom headers."""
        target = "http://example.com"
        custom_headers = {
            "X-Custom-Header": "test",
            "Authorization": "Bearer test-token"
        }
        
        # Mock responses for custom headers
        async def mock_headers_get(url: str, **kwargs) -> ClientResponse:
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
        
        await self.assert_plugin_findings(target, expected_findings) 