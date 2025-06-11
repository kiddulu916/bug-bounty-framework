"""
Test suite for the port scanning plugin.

This module tests:
- Plugin initialization and cleanup
- TCP SYN scan
- TCP Connect scan
- UDP scan
- Service detection
- OS fingerprinting
- Database integration
- Error handling
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

import aiohttp
import socket
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.inet import IP, TCP, UDP, ICMP

from bbf.plugins.recon.port_scan import PortScanPlugin, PortResult
from bbf.core.database.models import PortScanResult
from bbf.core.database.service import finding_service

# Test data
TEST_HOST = "example.com"
TEST_IP = "1.1.1.1"
TEST_PORTS = [21, 22, 80, 443, 3306]
TEST_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

@pytest.fixture
def plugin():
    """Create plugin instance."""
    return PortScanPlugin()

@pytest.fixture
def mock_socket():
    """Create mock socket."""
    with patch('socket.socket') as mock:
        sock = Mock()
        sock.connect_ex.return_value = 0
        sock.recv.return_value = TEST_BANNER.encode()
        mock.return_value = sock
        yield sock

@pytest.fixture
def mock_scapy():
    """Create mock Scapy responses."""
    with patch('scapy.all.sr1') as mock:
        def create_response(ip, port, protocol):
            if protocol == 'tcp':
                return IP(dst=ip)/TCP(dport=port, flags='SA', window=65535)
            elif protocol == 'udp':
                return IP(dst=ip)/UDP(dport=port)
            return None
        mock.side_effect = create_response
        yield mock

@pytest.mark.asyncio
async def test_plugin_initialization(plugin):
    """Test plugin initialization."""
    # Initialize plugin
    await plugin.initialize()
    
    # Verify session is created
    assert plugin.session is not None
    assert isinstance(plugin.session, aiohttp.ClientSession)
    
    # Clean up
    await plugin.cleanup()
    assert plugin.session is None

@pytest.mark.asyncio
async def test_syn_scan(plugin, mock_scapy):
    """Test TCP SYN scan."""
    # Run SYN scan
    results = await plugin._syn_scan(TEST_IP, set(TEST_PORTS), 1.0, 1)
    
    # Verify results
    assert len(results) == len(TEST_PORTS)
    for result in results:
        assert result.host == TEST_IP
        assert result.port in TEST_PORTS
        assert result.protocol == 'tcp'
        assert result.state == 'open'
        assert result.confidence == 1.0
        assert isinstance(result.timestamp, datetime)

@pytest.mark.asyncio
async def test_connect_scan(plugin, mock_socket):
    """Test TCP Connect scan."""
    # Run Connect scan
    results = await plugin._connect_scan(TEST_IP, set(TEST_PORTS), 1.0, 1)
    
    # Verify results
    assert len(results) == len(TEST_PORTS)
    for result in results:
        assert result.host == TEST_IP
        assert result.port in TEST_PORTS
        assert result.protocol == 'tcp'
        assert result.state == 'open'
        assert result.confidence == 1.0
        assert isinstance(result.timestamp, datetime)

@pytest.mark.asyncio
async def test_udp_scan(plugin, mock_scapy):
    """Test UDP scan."""
    # Run UDP scan
    results = await plugin._udp_scan(TEST_IP, set(TEST_PORTS), 1.0, 1)
    
    # Verify results
    assert len(results) == len(TEST_PORTS)
    for result in results:
        assert result.host == TEST_IP
        assert result.port in TEST_PORTS
        assert result.protocol == 'udp'
        assert result.state in ['open', 'open|filtered']
        assert result.confidence >= 0.7
        assert isinstance(result.timestamp, datetime)

@pytest.mark.asyncio
async def test_service_detection(plugin, mock_socket):
    """Test service detection."""
    # Test SSH service detection
    service_info = await plugin._detect_service(TEST_IP, 22, 'tcp')
    
    # Verify results
    assert service_info is not None
    assert service_info['service'] == 'ssh'
    assert 'OpenSSH' in service_info['version']
    assert TEST_BANNER in service_info['banner']
    
    # Test HTTP service detection
    mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
    service_info = await plugin._detect_service(TEST_IP, 80, 'tcp')
    
    # Verify results
    assert service_info is not None
    assert service_info['service'] == 'nginx'
    assert service_info['version'] == '1.18.0'

@pytest.mark.asyncio
async def test_os_detection(plugin, mock_scapy):
    """Test OS fingerprinting."""
    # Mock Linux response
    mock_scapy.return_value = IP(dst=TEST_IP)/TCP(dport=80, flags='SA', window=65535, options=[('MSS', 1460)])
    
    # Run OS detection
    os_info = await plugin._detect_os(TEST_IP)
    
    # Verify results
    assert os_info == "Linux"
    
    # Mock Windows response
    mock_scapy.return_value = IP(dst=TEST_IP)/TCP(dport=80, flags='SA', window=8192)
    
    # Run OS detection
    os_info = await plugin._detect_os(TEST_IP)
    
    # Verify results
    assert os_info == "Windows"

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_scapy, mock_socket):
    """Test complete plugin execution."""
    # Mock DNS resolution
    with patch('socket.gethostbyname', return_value=TEST_IP):
        # Mock database operations
        with patch.object(finding_service, 'add_port_scan_results') as mock_add_results:
            mock_add_results.return_value = [
                PortScanResult(
                    id=1,
                    plugin_result_id=1,
                    host=TEST_IP,
                    port=22,
                    protocol='tcp',
                    state='open',
                    service='ssh',
                    version='OpenSSH_8.2p1',
                    banner=TEST_BANNER,
                    os_info='Linux',
                    confidence=1.0,
                    timestamp=datetime.utcnow()
                )
            ]
            
            # Execute plugin
            plugin.current_plugin_result_id = 1
            results = await plugin.execute(TEST_HOST)
            
            # Verify results
            assert len(results) > 0
            assert results[0]['host'] == TEST_IP
            assert results[0]['port'] == 22
            assert results[0]['protocol'] == 'tcp'
            assert results[0]['state'] == 'open'
            
            # Verify database call
            mock_add_results.assert_called_once()

@pytest.mark.asyncio
async def test_plugin_error_handling(plugin, mock_scapy, mock_socket):
    """Test plugin error handling."""
    # Mock DNS resolution failure
    with patch('socket.gethostbyname', side_effect=socket.gaierror):
        results = await plugin.execute(TEST_HOST)
        assert len(results) == 0
        
    # Mock scan failure
    mock_scapy.side_effect = Exception("Scan failed")
    results = await plugin.execute(TEST_HOST)
    assert len(results) == 0
    
    # Mock service detection failure
    mock_socket.connect_ex.side_effect = Exception("Connection failed")
    results = await plugin.execute(TEST_HOST)
    assert len(results) == 0

@pytest.mark.asyncio
async def test_database_integration(plugin, mock_scapy, mock_socket):
    """Test database integration."""
    # Mock DNS resolution
    with patch('socket.gethostbyname', return_value=TEST_IP):
        # Mock database operations
        with patch.object(finding_service.port_scan_repo, 'get_session') as mock_get_session, \
             patch.object(finding_service, 'add_port_scan_results') as mock_add_results:
            
            # Mock database session
            mock_db_session = Mock()
            mock_get_session.return_value.__enter__.return_value = mock_db_session
            
            # Mock findings
            mock_findings = [
                PortScanResult(
                    id=1,
                    plugin_result_id=1,
                    host=TEST_IP,
                    port=22,
                    protocol='tcp',
                    state='open',
                    service='ssh',
                    version='OpenSSH_8.2p1',
                    banner=TEST_BANNER,
                    os_info='Linux',
                    confidence=1.0,
                    timestamp=datetime.utcnow()
                )
            ]
            mock_add_results.return_value = mock_findings
            
            # Execute plugin
            plugin.current_plugin_result_id = 1
            results = await plugin.execute(TEST_HOST)
            
            # Verify database operations
            mock_get_session.assert_called_once()
            mock_add_results.assert_called_once_with(
                mock_db_session,
                plugin_result_id=1,
                findings=mock.ANY
            )
            
            # Verify results
            assert len(results) == 1
            assert results[0]['host'] == TEST_IP
            assert results[0]['port'] == 22
            assert results[0]['protocol'] == 'tcp'
            assert results[0]['state'] == 'open'

@pytest.mark.asyncio
async def test_concurrent_execution(plugin, mock_scapy, mock_socket):
    """Test concurrent plugin execution."""
    # Mock DNS resolution
    with patch('socket.gethostbyname', return_value=TEST_IP):
        # Mock database operations
        with patch.object(finding_service, 'add_port_scan_results') as mock_add_results:
            mock_add_results.return_value = [
                PortScanResult(
                    id=1,
                    plugin_result_id=1,
                    host=TEST_IP,
                    port=22,
                    protocol='tcp',
                    state='open',
                    service='ssh',
                    version='OpenSSH_8.2p1',
                    banner=TEST_BANNER,
                    os_info='Linux',
                    confidence=1.0,
                    timestamp=datetime.utcnow()
                )
            ]
            
            # Execute plugin concurrently
            plugin.current_plugin_result_id = 1
            tasks = [
                plugin.execute(TEST_HOST),
                plugin.execute(TEST_HOST)
            ]
            results = await asyncio.gather(*tasks)
            
            # Verify results
            assert len(results) == 2
            for result in results:
                assert len(result) == 1
                assert result[0]['host'] == TEST_IP
                assert result[0]['port'] == 22
                
            # Verify database calls
            assert mock_add_results.call_count == 2 