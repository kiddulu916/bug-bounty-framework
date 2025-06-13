"""
Integration tests for the Port Scanning Plugin.

This module contains comprehensive test cases for the Port Scanning Plugin,
verifying its functionality for discovering and analyzing open ports and services.

Test Categories:
- Basic Functionality: Core port scanning features
- Custom Port Lists: Port discovery using custom port lists
- Error Handling: Plugin behavior during failures
- Performance: Execution time and resource usage
- Concurrent Execution: Multi-target scanning
- Data Management: Finding updates and metadata handling
- Service Detection: Service and banner detection

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Port discovery and analysis
2. Custom Port Lists: Custom port list processing
3. Error Handling: Network failures and error recovery
4. Performance: Execution time and resource usage
5. Concurrent Execution: Multi-target scanning efficiency
6. Data Management: Finding updates and metadata merging
7. Service Detection: Service identification and banner grabbing
"""

import pytest
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import AsyncMock, patch

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.port_scan import PortScannerPlugin
from bbf.core.database.models import Finding, FindingStatus

# Test Configuration
TEST_HOST = "example.com"
TEST_DEFAULT_PORTS = [80, 443, 8080, 8443]  # Common web ports
TEST_CUSTOM_PORTS = [22, 25, 3306, 5432]  # SSH, SMTP, MySQL, PostgreSQL
TEST_PERF_PORTS = list(range(1, 1025))  # First 1024 ports
TEST_CONCURRENT_HOSTS = [f"host{i}.example.com" for i in range(5)]  # 5 hosts

# Test Data
KNOWN_SERVICES = {
    80: ("http", "nginx/1.18.0"),
    443: ("https", "nginx/1.18.0"),
    8080: ("http-alt", "nginx/1.18.0"),
    8443: ("https-alt", "nginx/1.18.0"),
    22: ("ssh", "OpenSSH_8.2p1"),
    25: ("smtp", "Postfix"),
    3306: ("mysql", "MySQL 5.7.28"),
    5432: ("postgresql", "PostgreSQL 12.3")
}

class TestPortScanPlugin(PluginIntegrationTest):
    """
    Test suite for Port Scanning Plugin integration.
    
    This class implements comprehensive tests for the Port Scanning Plugin,
    covering all aspects of its functionality from basic port discovery to
    advanced service detection.
    
    Attributes:
        plugin_name (str): Name of the plugin being tested
        socket_mock (AsyncMock): Mocked socket client
        socket_patch (patch): Socket creation patch
    """
    
    @property
    def plugin_name(self) -> str:
        """
        Return the name of the plugin being tested.
        
        Returns:
            str: Plugin name
        """
        return "port_scan"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self) -> None:
        """
        Set up mock responses for port scanning.
        
        This fixture initializes mock socket responses for various test scenarios,
        including basic connections, custom ports, and error conditions.
        """
        super().setup_mocks()
        
        # Mock socket responses
        self.socket_mock = AsyncMock()
        self.socket_mock.connect.side_effect = self._mock_connect
        self.socket_mock.recv.side_effect = self._mock_recv
        
        # Patch socket creation
        self.socket_patch = patch("socket.socket", return_value=self.socket_mock)
        self.socket_patch.start()
    
    def teardown_method(self, method: Any) -> None:
        """
        Clean up after each test method.
        
        Args:
            method: The test method that was executed
        """
        super().teardown_method(method)
        self.socket_patch.stop()
    
    async def _mock_connect(self, address: Tuple[str, int]) -> None:
        """
        Mock socket connection responses.
        
        Args:
            address: Tuple of (host, port) to connect to
        
        Raises:
            ConnectionRefusedError: If port is not in known ports
        """
        host, port = address
        if port in TEST_DEFAULT_PORTS:
            return None  # Connection successful
        raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
    
    async def _mock_recv(self, bufsize: int) -> bytes:
        """
        Mock socket receive responses.
        
        Args:
            bufsize: Maximum number of bytes to receive
        
        Returns:
            bytes: Mocked service banner
        """
        return b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"

class TestBasicFunctionality(TestPortScanPlugin):
    """Tests for basic port scanning functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_port_scanning(self) -> None:
        """
        Test basic port scanning functionality.
        
        This test verifies that the plugin can:
        1. Discover common open ports
        2. Identify services running on ports
        3. Store findings with correct metadata
        4. Handle different port states
        """
        expected_findings = [
            {
                "subdomain": TEST_HOST,
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": TEST_DEFAULT_PORTS,
                    "protocols": ["tcp"],
                    "services": {
                        str(port): service
                        for port, (service, _) in KNOWN_SERVICES.items()
                        if port in TEST_DEFAULT_PORTS
                    },
                    "banners": {
                        str(port): banner
                        for port, (_, banner) in KNOWN_SERVICES.items()
                        if port in TEST_DEFAULT_PORTS
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_HOST, expected_findings)

class TestCustomPortLists(TestPortScanPlugin):
    """Tests for custom port list scanning."""
    
    @pytest.mark.asyncio
    async def test_port_scanning_with_custom_ports(self) -> None:
        """
        Test port scanning with custom port list.
        
        This test verifies that the plugin can:
        1. Process a custom port list for scanning
        2. Handle multiple ports efficiently
        3. Store findings with appropriate metadata
        """
        # Mock responses for custom ports
        async def mock_custom_connect(address: Tuple[str, int]) -> None:
            host, port = address
            if port in TEST_CUSTOM_PORTS:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_custom_connect
        
        expected_findings = [
            {
                "subdomain": TEST_HOST,
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": TEST_CUSTOM_PORTS,
                    "protocols": ["tcp"],
                    "services": {
                        str(port): service
                        for port, (service, _) in KNOWN_SERVICES.items()
                        if port in TEST_CUSTOM_PORTS
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_HOST, expected_findings)

class TestErrorHandling(TestPortScanPlugin):
    """Tests for error handling during port scanning."""
    
    @pytest.mark.asyncio
    async def test_port_scanning_error_handling(self) -> None:
        """
        Test error handling during port scanning.
        
        This test verifies that the plugin:
        1. Handles network failures gracefully
        2. Reports errors appropriately
        3. Maintains data integrity during failures
        """
        # Mock socket to raise an exception
        self.socket_mock.connect.side_effect = Exception("Network error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(TEST_HOST)
        assert results["status"] == "error"
        assert "error" in results
        assert "Network error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(
            TEST_HOST,
            source="port_scan",
            expected_count=0
        )

class TestPerformance(TestPortScanPlugin):
    """Tests for port scanning performance."""
    
    @pytest.mark.asyncio
    async def test_port_scanning_performance(self) -> None:
        """
        Test port scanning performance.
        
        This test verifies that the plugin:
        1. Handles large port ranges efficiently
        2. Completes within acceptable time limits
        3. Maintains performance under load
        """
        # Mock responses for performance testing
        async def mock_perf_connect(address: Tuple[str, int]) -> None:
            host, port = address
            if port in TEST_DEFAULT_PORTS:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_perf_connect
        
        # Test performance with 1024 ports
        await self.assert_performance(
            self.execute_plugin,
            TEST_HOST,
            max_time=30.0  # Should complete within 30 seconds
        )
    
    @pytest.mark.asyncio
    async def test_port_scanning_concurrent(self) -> None:
        """
        Test concurrent port scanning.
        
        This test verifies that the plugin:
        1. Handles multiple targets efficiently
        2. Respects concurrency limits
        3. Maintains performance under concurrent load
        """
        # Mock responses for concurrent testing
        async def mock_concurrent_connect(address: Tuple[str, int]) -> None:
            host, port = address
            if port in [80, 443]:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_concurrent_connect
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in TEST_CONCURRENT_HOSTS],
            max_time=15.0,  # Should complete within 15 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )

class TestDataManagement(TestPortScanPlugin):
    """Tests for finding updates and metadata management."""
    
    @pytest.mark.asyncio
    async def test_port_scanning_metadata_merging(self) -> None:
        """
        Test metadata merging for port scan findings.
        
        This test verifies that the plugin:
        1. Updates findings with new information
        2. Preserves existing metadata
        3. Merges port lists correctly
        4. Maintains data integrity during updates
        """
        # First scan
        await self.execute_plugin(TEST_HOST)
        finding = await self.assert_finding_exists(
            TEST_HOST,
            TEST_HOST,
            "port_scan"
        )
        
        # Update with new metadata
        updated_ports = [80, 443, 8080]  # Removed 8443
        
        # Second scan with new metadata
        async def mock_updated_connect(address: Tuple[str, int]) -> None:
            host, port = address
            if port in updated_ports:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_updated_connect
        
        await self.execute_plugin(TEST_HOST)
        updated = await self.assert_finding_exists(
            TEST_HOST,
            TEST_HOST,
            "port_scan"
        )
        
        # Verify metadata merging
        assert set(updated.metadata["ports"]) == set(updated_ports)  # Updated ports
        assert "8443" not in updated.metadata["services"]  # Removed service
        assert updated.metadata["services"]["80"] == "http"  # Preserved service
        assert "protocols" in updated.metadata  # Preserved metadata
        assert "banners" in updated.metadata  # Preserved metadata

class TestServiceDetection(TestPortScanPlugin):
    """Tests for service and banner detection."""
    
    @pytest.mark.asyncio
    async def test_port_scanning_with_service_detection(self) -> None:
        """
        Test port scanning with service detection.
        
        This test verifies that the plugin can:
        1. Detect different services on ports
        2. Extract service banners
        3. Store findings with service metadata
        4. Handle various service responses
        """
        # Mock different service banners
        async def mock_service_recv(bufsize: int) -> bytes:
            port = self.socket_mock.getpeername.return_value[1]
            if port in KNOWN_SERVICES:
                service, banner = KNOWN_SERVICES[port]
                if service == "http":
                    return f"HTTP/1.1 200 OK\r\nServer: {banner}\r\n\r\n".encode()
                elif service == "mysql":
                    return b"\x4a\x00\x00\x00\x0a" + banner.encode()
                elif service == "ssh":
                    return f"SSH-2.0-{banner}\r\n".encode()
                elif service == "smtp":
                    return f"220 {banner} ESMTP\r\n".encode()
            return b""
        
        self.socket_mock.recv.side_effect = mock_service_recv
        
        expected_findings = [
            {
                "subdomain": TEST_HOST,
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": list(KNOWN_SERVICES.keys()),
                    "protocols": ["tcp"],
                    "services": {
                        str(port): service
                        for port, (service, _) in KNOWN_SERVICES.items()
                    },
                    "banners": {
                        str(port): banner
                        for port, (_, banner) in KNOWN_SERVICES.items()
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_HOST, expected_findings) 