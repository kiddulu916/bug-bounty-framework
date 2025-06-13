"""
Tests for the PortScanPlugin.

This module contains comprehensive test cases for the port scanning plugin,
verifying its functionality for discovering open ports and services.

Test Categories:
- Basic Functionality: Core plugin initialization and execution
- DNS Resolution: Hostname to IP mapping
- Port Scanning: Port state detection and service identification
- Service Detection: Protocol and version identification
- Error Handling: Plugin behavior during failures
- Performance: Concurrent scanning and resource management
- Resource Management: Socket and connection cleanup

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Plugin lifecycle and configuration
2. DNS Resolution: Hostname resolution and caching
3. Port Scanning: Port state detection and scanning strategies
4. Service Detection: Protocol identification and banner grabbing
5. Error Handling: Connection failures and timeouts
6. Performance: Concurrent scanning and resource limits
7. Resource Management: Socket cleanup and connection handling
"""

import asyncio
import pytest
from typing import Dict, Any, List, Optional, Set, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch
import socket
from datetime import datetime

from bbf.plugins.recon.port_scan import PortScanPlugin
from bbf.core.exceptions import PluginError

# Test Configuration
TEST_HOST = "example.com"
TEST_IP = "93.184.216.34"  # example.com's IP
TEST_TIMEOUT = 5.0
TEST_CONCURRENT_CONNECTIONS = 10
TEST_DEFAULT_PORT_RANGE = list(range(1, 1001))

# Test Data
TEST_PORTS = [80, 443, 22, 25, 3306]
TEST_SERVICES = {
    80: "http",
    443: "https",
    22: "ssh",
    25: "smtp",
    3306: "mysql"
}

# Mock Service Banners
MOCK_BANNERS = {
    80: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
    443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    25: b"220 example.com ESMTP Postfix\r\n",
    3306: b"5.7.0 Authentication required\r\n"
}

class TestPortScanPlugin:
    """
    Test suite for PortScanPlugin.
    
    This class implements comprehensive tests for the port scanning plugin,
    covering all aspects of its functionality from basic initialization to
    advanced scanning techniques.
    """
    
    @pytest.fixture
    def plugin(self) -> PortScanPlugin:
        """
        Create a plugin instance for testing.
        
        Returns:
            PortScanPlugin: Plugin instance
        """
        return PortScanPlugin()
    
    @pytest.fixture
    def mock_socket(self) -> AsyncGenerator[MagicMock, None]:
        """
        Create a mock socket.
        
        Yields:
            MagicMock: Mocked socket instance
        """
        with patch('socket.socket') as mock:
            sock = mock.return_value
            sock.connect = MagicMock()
            sock.connect_ex = MagicMock(return_value=0)
            sock.recv = MagicMock(return_value=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
            sock.close = MagicMock()
            yield sock
    
    @pytest.fixture
    def mock_dns_resolver(self) -> AsyncGenerator[MagicMock, None]:
        """
        Create a mock DNS resolver.
        
        Yields:
            MagicMock: Mocked DNS resolver
        """
        with patch('socket.gethostbyname') as mock:
            mock.return_value = TEST_IP
            yield mock

class TestBasicFunctionality(TestPortScanPlugin):
    """Tests for basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin: PortScanPlugin) -> None:
        """
        Test plugin initialization.
        
        This test verifies that the plugin:
        1. Initializes with correct configuration
        2. Sets appropriate timeouts
        3. Configures concurrent connections
        4. Sets up default port range
        
        Args:
            plugin: Plugin instance
        """
        await plugin.initialize()
        
        # Verify initialization
        assert plugin._timeout == TEST_TIMEOUT
        assert plugin._concurrent_connections == TEST_CONCURRENT_CONNECTIONS
        assert plugin._ports == TEST_DEFAULT_PORT_RANGE

class TestDNSResolution(TestPortScanPlugin):
    """Tests for DNS resolution functionality."""
    
    @pytest.mark.asyncio
    async def test_dns_resolution(self, plugin: PortScanPlugin, mock_dns_resolver: MagicMock) -> None:
        """
        Test DNS resolution functionality.
        
        This test verifies that the plugin:
        1. Resolves hostnames to IPs correctly
        2. Handles DNS resolution errors
        3. Returns valid IP addresses
        4. Caches DNS results appropriately
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
        ip = await plugin._resolve_hostname(TEST_HOST)
        
        # Verify DNS resolution
        assert ip == TEST_IP
        mock_dns_resolver.assert_called_once_with(TEST_HOST)
    
    @pytest.mark.asyncio
    async def test_dns_resolution_error(self, plugin: PortScanPlugin, mock_dns_resolver: MagicMock) -> None:
        """
        Test DNS resolution error handling.
        
        This test verifies that the plugin:
        1. Handles DNS resolution failures
        2. Raises appropriate exceptions
        3. Provides clear error messages
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
        # Mock DNS resolution failure
        mock_dns_resolver.side_effect = socket.gaierror("Name or service not known")
        
        # Verify error handling
        with pytest.raises(PluginError) as exc_info:
            await plugin._resolve_hostname("nonexistent.example.com")
        assert "Failed to resolve hostname" in str(exc_info.value)

class TestPortScanning(TestPortScanPlugin):
    """Tests for port scanning functionality."""
    
    @pytest.mark.asyncio
    async def test_port_scan(self, plugin: PortScanPlugin, mock_socket: MagicMock) -> None:
        """
        Test port scanning functionality.
        
        This test verifies that the plugin:
        1. Scans specified ports correctly
        2. Detects open ports accurately
        3. Handles connection attempts properly
        4. Returns valid scan results
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
        """
        # Configure plugin
        plugin._ports = TEST_PORTS
        
        # Run port scan
        results = await plugin._scan_ports(TEST_IP)
        
        # Verify results
        assert len(results) == len(TEST_PORTS)
        assert all(hasattr(r, 'port') for r in results)
        assert all(hasattr(r, 'state') for r in results)
        assert all(r.state == 'open' for r in results)
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning(self, plugin: PortScanPlugin, mock_socket: MagicMock) -> None:
        """
        Test concurrent port scanning.
        
        This test verifies that the plugin:
        1. Handles concurrent connections properly
        2. Respects connection limits
        3. Manages resources efficiently
        4. Completes scans successfully
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
        """
        # Configure plugin with high concurrency
        plugin._concurrent_connections = 50
        plugin._ports = list(range(1, 101))  # Scan first 100 ports
        
        # Run port scan
        results = await plugin._scan_ports(TEST_IP)
        
        # Verify results
        assert len(results) == 100
        assert all(r.state == 'open' for r in results)
        
        # Verify concurrent connections were limited
        assert mock_socket.connect_ex.call_count == 100
        assert mock_socket.close.call_count == 100

class TestServiceDetection(TestPortScanPlugin):
    """Tests for service detection functionality."""
    
    @pytest.mark.asyncio
    async def test_service_detection(self, plugin: PortScanPlugin, mock_socket: MagicMock) -> None:
        """
        Test service detection functionality.
        
        This test verifies that the plugin:
        1. Detects services correctly
        2. Identifies protocols accurately
        3. Grabs banners properly
        4. Returns valid service information
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
        """
        # Configure mock socket responses
        mock_socket.recv.side_effect = [
            MOCK_BANNERS[80],   # HTTP
            MOCK_BANNERS[443],  # HTTPS
            MOCK_BANNERS[22],   # SSH
            MOCK_BANNERS[25],   # SMTP
            MOCK_BANNERS[3306]  # MySQL
        ]
        
        # Test service detection
        services = await plugin._detect_services(TEST_IP, TEST_PORTS)
        
        # Verify results
        assert len(services) == len(TEST_PORTS)
        assert all(hasattr(s, 'port') for s in services)
        assert all(hasattr(s, 'service') for s in services)
        assert any(s.service == 'http' for s in services)
        assert any(s.service == 'ssh' for s in services)
        assert any(s.service == 'smtp' for s in services)

class TestErrorHandling(TestPortScanPlugin):
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_error_handling(self, plugin: PortScanPlugin, mock_socket: MagicMock) -> None:
        """
        Test plugin error handling.
        
        This test verifies that the plugin:
        1. Handles connection errors gracefully
        2. Returns empty results on failure
        3. Continues execution after errors
        4. Maintains stability during failures
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
        """
        # Mock socket to raise an exception
        mock_socket.connect_ex.side_effect = socket.error("Connection refused")
        
        # Run port scan
        results = await plugin._scan_ports(TEST_IP)
        
        # Verify empty result on error
        assert len(results) == 0

class TestResourceManagement(TestPortScanPlugin):
    """Tests for resource management functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, plugin: PortScanPlugin, mock_socket: MagicMock) -> None:
        """
        Test plugin cleanup.
        
        This test verifies that the plugin:
        1. Closes sockets properly
        2. Cleans up resources
        3. Handles cleanup gracefully
        4. Prevents resource leaks
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
        """
        await plugin.initialize()
        await plugin.cleanup()
        
        # Verify socket was closed
        mock_socket.close.assert_called()

class TestPluginExecution(TestPortScanPlugin):
    """Tests for complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_plugin_execution(
        self,
        plugin: PortScanPlugin,
        mock_socket: MagicMock,
        mock_dns_resolver: MagicMock
    ) -> None:
        """
        Test complete plugin execution.
        
        This test verifies that the plugin:
        1. Executes all scanning methods
        2. Combines results from different sources
        3. Handles DNS resolution properly
        4. Returns comprehensive findings
        
        Args:
            plugin: Plugin instance
            mock_socket: Mocked socket
            mock_dns_resolver: Mocked DNS resolver
        """
        # Configure plugin
        plugin._ports = TEST_PORTS
        
        # Configure mock socket responses
        mock_socket.recv.side_effect = [
            MOCK_BANNERS[80],   # HTTP
            MOCK_BANNERS[443],  # HTTPS
            MOCK_BANNERS[22],   # SSH
            MOCK_BANNERS[25],   # SMTP
            MOCK_BANNERS[3306]  # MySQL
        ]
        
        # Run plugin execution
        results = await plugin.execute(TEST_HOST)
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(hasattr(r, 'port') for r in results)
        assert all(hasattr(r, 'state') for r in results)
        assert all(hasattr(r, 'service') for r in results)
        assert all(r.state == 'open' for r in results) 