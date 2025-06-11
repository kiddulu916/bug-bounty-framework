"""
Unit tests for the PortScanPlugin.
"""

import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import aiohttp
import socket
from datetime import datetime

from bbf.plugins.recon.portscan import PortScanPlugin
from bbf.core.exceptions import PluginError

# Test data
TEST_HOST = "example.com"
TEST_PORTS = [80, 443, 22, 25]
TEST_OPEN_PORTS = {
    80: {
        'port': 80,
        'protocol': 'tcp',
        'state': 'open',
        'service': 'http',
        'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n'
    },
    443: {
        'port': 443,
        'protocol': 'tcp',
        'state': 'open',
        'service': 'https',
        'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n'
    }
}

@pytest.fixture
def plugin():
    """Create a plugin instance for testing."""
    return PortScanPlugin(config={'ports': TEST_PORTS})

@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock()
        mock.return_value.__aenter__.return_value = session
        yield session

@pytest.mark.asyncio
async def test_plugin_initialization(plugin):
    """Test plugin initialization."""
    assert plugin.name == "port_scan"
    assert plugin.description == "Scans ports and detects services"
    assert plugin.version == "1.0.0"
    assert plugin.enabled is True
    assert plugin.timeout == 300
    assert plugin.ports == TEST_PORTS
    assert plugin.scan_types == ["tcp", "udp"]

@pytest.mark.asyncio
async def test_plugin_initialization_with_default_ports():
    """Test plugin initialization with default ports."""
    plugin = PortScanPlugin()
    assert len(plugin.ports) > 0
    assert all(isinstance(port, int) for port in plugin.ports)

@pytest.mark.asyncio
async def test_tcp_port_scan(plugin):
    """Test TCP port scanning."""
    # Mock asyncio.open_connection
    mock_reader = AsyncMock()
    mock_writer = AsyncMock()
    
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
        # Simulate open ports
        mock_conn.side_effect = [
            (mock_reader, mock_writer),  # Port 80 open
            (mock_reader, mock_writer),  # Port 443 open
            asyncio.TimeoutError(),      # Port 22 closed
            ConnectionRefusedError()     # Port 25 closed
        ]
        
        open_ports = await plugin._tcp_scan(TEST_HOST)
        
        # Verify results
        assert len(open_ports) == 2
        assert all(port['protocol'] == 'tcp' for port in open_ports)
        assert all(port['state'] == 'open' for port in open_ports)
        assert {port['port'] for port in open_ports} == {80, 443}

@pytest.mark.asyncio
async def test_udp_port_scan(plugin):
    """Test UDP port scanning."""
    # Mock socket operations
    mock_socket = MagicMock()
    mock_socket.recvfrom.side_effect = [
        (b'response', ('127.0.0.1', 0)),  # Port 53 open
        socket.timeout(),                  # Port 123 closed
        (b'response', ('127.0.0.1', 0))   # Port 161 open
    ]
    
    with patch('socket.socket', return_value=mock_socket):
        open_ports = await plugin._udp_scan(TEST_HOST)
        
        # Verify results
        assert len(open_ports) > 0
        assert all(port['protocol'] == 'udp' for port in open_ports)
        assert all(port['state'] == 'open' for port in open_ports)

@pytest.mark.asyncio
async def test_service_detection(plugin):
    """Test service detection."""
    # Mock banner grabbing
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n'
    mock_writer = AsyncMock()
    
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_conn:
        mock_conn.return_value = (mock_reader, mock_writer)
        
        port_info = {
            'port': 22,
            'protocol': 'tcp',
            'state': 'open'
        }
        
        service_info = await plugin._detect_service(TEST_HOST, port_info)
        
        # Verify results
        assert service_info is not None
        assert service_info['service'] == 'ssh'
        assert 'banner' in service_info

@pytest.mark.asyncio
async def test_service_detection_without_banner(plugin):
    """Test service detection when banner grabbing fails."""
    # Mock connection timeout
    with patch('asyncio.open_connection', side_effect=asyncio.TimeoutError()):
        port_info = {
            'port': 80,
            'protocol': 'tcp',
            'state': 'open'
        }
        
        service_info = await plugin._detect_service(TEST_HOST, port_info)
        
        # Verify fallback to port-based detection
        assert service_info is not None
        assert service_info['service'] == 'http'

@pytest.mark.asyncio
async def test_execute_full_scan(plugin):
    """Test full plugin execution with all methods."""
    # Mock TCP and UDP scanning
    with patch.object(plugin, '_tcp_scan', return_value=[
        {'port': 80, 'protocol': 'tcp', 'state': 'open'},
        {'port': 443, 'protocol': 'tcp', 'state': 'open'}
    ]), patch.object(plugin, '_udp_scan', return_value=[
        {'port': 53, 'protocol': 'udp', 'state': 'open'}
    ]), patch.object(plugin, '_detect_service', return_value={
        'service': 'http',
        'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n'
    }):
        result = await plugin.execute(TEST_HOST)
        
        # Verify result structure
        assert result['success'] is True
        assert result['target'] == TEST_HOST
        assert 'timestamp' in result
        assert 'ports' in result
        assert len(result['ports']) == 3
        
        # Verify port information
        ports = result['ports']
        assert any(port['port'] == 80 and port['protocol'] == 'tcp' for port in ports)
        assert any(port['port'] == 443 and port['protocol'] == 'tcp' for port in ports)
        assert any(port['port'] == 53 and port['protocol'] == 'udp' for port in ports)

@pytest.mark.asyncio
async def test_execute_tcp_only(plugin):
    """Test plugin execution with TCP scanning only."""
    plugin.scan_types = ["tcp"]
    
    with patch.object(plugin, '_tcp_scan', return_value=[
        {'port': 80, 'protocol': 'tcp', 'state': 'open'},
        {'port': 443, 'protocol': 'tcp', 'state': 'open'}
    ]), patch.object(plugin, '_detect_service', return_value={
        'service': 'http',
        'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n'
    }):
        result = await plugin.execute(TEST_HOST)
        
        # Verify only TCP ports were scanned
        assert result['success'] is True
        assert all(port['protocol'] == 'tcp' for port in result['ports'])
        assert len(result['ports']) == 2

@pytest.mark.asyncio
async def test_error_handling(plugin):
    """Test error handling in plugin methods."""
    # Test TCP scan error
    with patch.object(plugin, '_tcp_scan', side_effect=Exception("Scan error")):
        result = await plugin.execute(TEST_HOST)
        assert result['success'] is True  # Plugin should still return success
        assert 'ports' in result
        assert len(result['ports']) == 0
    
    # Test service detection error
    with patch.object(plugin, '_tcp_scan', return_value=[
        {'port': 80, 'protocol': 'tcp', 'state': 'open'}
    ]), patch.object(plugin, '_detect_service', side_effect=Exception("Detection error")):
        result = await plugin.execute(TEST_HOST)
        assert result['success'] is True
        assert len(result['ports']) == 1
        assert 'service' not in result['ports'][0]

@pytest.mark.asyncio
async def test_cleanup(plugin):
    """Test plugin cleanup."""
    # Create a mock session
    plugin._session = AsyncMock()
    
    await plugin.cleanup()
    
    # Verify session was closed
    assert plugin._session is None
    plugin._session.close.assert_called_once()

@pytest.mark.asyncio
async def test_service_identification(plugin):
    """Test service identification from banners and ports."""
    # Test banner-based identification
    assert plugin._identify_service(80, "HTTP/1.1 200 OK") == "http"
    assert plugin._identify_service(22, "SSH-2.0-OpenSSH_8.2") == "ssh"
    assert plugin._identify_service(25, "220 mail.example.com ESMTP") == "smtp"
    
    # Test port-based identification
    assert plugin._identify_service_by_port(80, "tcp") == "http"
    assert plugin._identify_service_by_port(443, "tcp") == "https"
    assert plugin._identify_service_by_port(22, "tcp") == "ssh"
    assert plugin._identify_service_by_port(9999, "tcp") == "unknown" 