"""Integration tests for the Port Scanning Plugin."""

import pytest
from typing import Dict, Any, List
from unittest.mock import AsyncMock, patch

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.port_scan import PortScanPlugin

class TestPortScanPlugin(PluginIntegrationTest):
    """Test suite for Port Scanning Plugin integration."""
    
    @property
    def plugin_name(self) -> str:
        return "port_scan"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Set up mock responses for port scanning."""
        super().setup_mocks()
        
        # Mock socket responses
        self.socket_mock = AsyncMock()
        self.socket_mock.connect.side_effect = self._mock_connect
        self.socket_mock.recv.side_effect = self._mock_recv
        
        # Patch socket creation
        self.socket_patch = patch("socket.socket", return_value=self.socket_mock)
        self.socket_patch.start()
    
    def teardown_method(self, method):
        """Clean up after each test method."""
        super().teardown_method(method)
        self.socket_patch.stop()
    
    async def _mock_connect(self, address: tuple):
        """Mock socket connection responses."""
        host, port = address
        if port in [80, 443, 8080, 8443]:
            return None  # Connection successful
        raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
    
    async def _mock_recv(self, bufsize: int) -> bytes:
        """Mock socket receive responses."""
        return b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
    
    @pytest.mark.asyncio
    async def test_basic_port_scanning(self):
        """Test basic port scanning functionality."""
        target = "example.com"
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": [80, 443, 8080, 8443],
                    "protocols": ["tcp"],
                    "services": {
                        "80": "http",
                        "443": "https",
                        "8080": "http-alt",
                        "8443": "https-alt"
                    },
                    "banners": {
                        "80": "nginx/1.18.0",
                        "443": "nginx/1.18.0",
                        "8080": "nginx/1.18.0",
                        "8443": "nginx/1.18.0"
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_port_scanning_with_custom_ports(self):
        """Test port scanning with custom port list."""
        target = "example.com"
        ports = [22, 25, 3306, 5432]  # SSH, SMTP, MySQL, PostgreSQL
        
        # Mock responses for custom ports
        async def mock_custom_connect(address: tuple):
            host, port = address
            if port in ports:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_custom_connect
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": ports,
                    "protocols": ["tcp"],
                    "services": {
                        "22": "ssh",
                        "25": "smtp",
                        "3306": "mysql",
                        "5432": "postgresql"
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_port_scanning_error_handling(self):
        """Test error handling during port scanning."""
        target = "example.com"
        
        # Mock socket to raise an exception
        self.socket_mock.connect.side_effect = Exception("Network error")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(target)
        assert results["status"] == "error"
        assert "error" in results
        assert "Network error" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(target, source="port_scan", expected_count=0)
    
    @pytest.mark.asyncio
    async def test_port_scanning_performance(self):
        """Test port scanning performance."""
        target = "example.com"
        ports = list(range(1, 1025))  # Scan first 1024 ports
        
        # Mock responses for performance testing
        async def mock_perf_connect(address: tuple):
            host, port = address
            if port in [80, 443, 8080, 8443]:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_perf_connect
        
        # Test performance with 1024 ports
        await self.assert_performance(
            self.execute_plugin,
            target,
            max_time=30.0  # Should complete within 30 seconds
        )
    
    @pytest.mark.asyncio
    async def test_port_scanning_concurrent(self):
        """Test concurrent port scanning."""
        targets = [f"host{i}.example.com" for i in range(5)]  # 5 hosts
        
        # Mock responses for concurrent testing
        async def mock_concurrent_connect(address: tuple):
            host, port = address
            if port in [80, 443]:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_concurrent_connect
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in targets],
            max_time=15.0,  # Should complete within 15 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )
    
    @pytest.mark.asyncio
    async def test_port_scanning_metadata_merging(self):
        """Test metadata merging for port scan findings."""
        target = "example.com"
        
        # First scan
        await self.execute_plugin(target)
        finding = await self.assert_finding_exists(
            target,
            "example.com",
            "port_scan"
        )
        
        # Update with new metadata
        new_metadata = {
            "ports": [80, 443, 8080],  # Removed 8443
            "services": {
                "80": "http",
                "443": "https",
                "8080": "http-alt",
                "8443": "https-alt"  # Will be removed
            }
        }
        
        # Second scan with new metadata
        async def mock_updated_connect(address: tuple):
            host, port = address
            if port in [80, 443, 8080]:
                return None
            raise ConnectionRefusedError(f"Connection refused: {host}:{port}")
        
        self.socket_mock.connect.side_effect = mock_updated_connect
        
        await self.execute_plugin(target)
        updated = await self.assert_finding_exists(
            target,
            "example.com",
            "port_scan"
        )
        
        # Verify metadata merging
        assert set(updated.metadata["ports"]) == {80, 443, 8080}  # Updated ports
        assert "8443" not in updated.metadata["services"]  # Removed service
        assert updated.metadata["services"]["80"] == "http"  # Preserved service
        assert "protocols" in updated.metadata  # Preserved metadata
        assert "banners" in updated.metadata  # Preserved metadata
    
    @pytest.mark.asyncio
    async def test_port_scanning_with_service_detection(self):
        """Test port scanning with service detection."""
        target = "example.com"
        
        # Mock different service banners
        async def mock_service_recv(bufsize: int) -> bytes:
            if self.socket_mock.getpeername.return_value[1] == 80:
                return b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            elif self.socket_mock.getpeername.return_value[1] == 443:
                return b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"
            elif self.socket_mock.getpeername.return_value[1] == 3306:
                return b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x38\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e\x31\x38\x2e\x30\x34\x2e\x31"
            return b""
        
        self.socket_mock.recv.side_effect = mock_service_recv
        
        expected_findings = [
            {
                "subdomain": "example.com",
                "source": "port_scan",
                "confidence": 0.95,
                "metadata": {
                    "ports": [80, 443, 3306],
                    "protocols": ["tcp"],
                    "services": {
                        "80": "http",
                        "443": "https",
                        "3306": "mysql"
                    },
                    "banners": {
                        "80": "nginx/1.18.0",
                        "443": "Apache/2.4.41",
                        "3306": "MySQL 5.7.28"
                    }
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings) 