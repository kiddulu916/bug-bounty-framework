"""
Integration tests for the ReconStage with its plugins.
"""

import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import aiohttp
import json
from datetime import datetime

from bbf.stages.recon import ReconStage
from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin
from bbf.plugins.recon.port_scan import PortScannerPlugin
from bbf.core.exceptions import PluginError, StageError

# Test data
TEST_DOMAIN = "example.com"
TEST_SUBDOMAINS = [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com"
]

TEST_OPEN_PORTS = {
    "www.example.com": [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
        },
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
        }
    ],
    "mail.example.com": [
        {
            "port": 25,
            "protocol": "tcp",
            "state": "open",
            "service": "smtp",
            "banner": "220 mail.example.com ESMTP Postfix\r\n"
        },
        {
            "port": 143,
            "protocol": "tcp",
            "state": "open",
            "service": "imap",
            "banner": "* OK [CAPABILITY IMAP4rev1] mail.example.com\r\n"
        }
    ]
}

@pytest.fixture
def stage():
    """Create a recon stage instance for testing."""
    config = {'timeout': 30, 'plugins': []}
    return ReconStage(config)

@pytest.fixture
def mock_env_vars():
    """Set up mock environment variables."""
    with patch.dict(os.environ, {
        'CERT_API_KEY': 'test_cert_key',
        'WAYBACK_API_KEY': 'test_wayback_key'
    }):
        yield

@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock()
        mock.return_value.__aenter__.return_value = session
        yield session

@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver responses."""
    with patch('dns.resolver.resolve') as mock:
        def mock_resolve(domain, record_type):
            mock_answer = MagicMock()
            if record_type == 'A':
                mock_answer.__str__.return_value = '93.184.216.34'
            elif record_type == 'AAAA':
                mock_answer.__str__.return_value = '2606:2800:220:1:248:1893:25c8:1946'
            elif record_type == 'CNAME':
                mock_answer.__str__.return_value = f'{domain}.'
            elif record_type == 'MX':
                mock_answer.__str__.return_value = f'mail.{domain}.'
            elif record_type == 'NS':
                mock_answer.__str__.return_value = f'ns1.{domain}.'
            elif record_type == 'TXT':
                mock_answer.__str__.return_value = f'v=spf1 include:_spf.{domain} ~all'
            elif record_type == 'PTR':
                mock_answer.__str__.return_value = f'{domain}.'
            return [mock_answer]
        mock.side_effect = mock_resolve
        yield mock

@pytest.mark.asyncio
async def test_stage_initialization(stage):
    """Test stage initialization."""
    assert stage.name == "recon"
    assert stage.description == "Reconnaissance stage for gathering information about targets"
    assert stage.enabled is True
    assert len(stage.plugins) > 0
    assert any(isinstance(p, SubdomainEnumPlugin) for p in stage.plugins)
    assert any(isinstance(p, PortScannerPlugin) for p in stage.plugins)

@pytest.mark.asyncio
async def test_stage_execution(stage, mock_session, mock_dns_resolver, mock_env_vars):
    """Test full stage execution with all plugins."""
    # Mock subdomain enumeration results
    mock_subdomain_results = {
        'success': True,
        'target': TEST_DOMAIN,
        'timestamp': datetime.utcnow().isoformat(),
        'subdomains': TEST_SUBDOMAINS,
        'dns_records': {
            'www.example.com': {
                'type': 'A',
                'data': '93.184.216.34',
                'timestamp': datetime.utcnow().isoformat()
            }
        }
    }
    
    # Mock port scan results
    mock_port_scan_results = {
        'success': True,
        'target': 'www.example.com',
        'timestamp': datetime.utcnow().isoformat(),
        'ports': TEST_OPEN_PORTS['www.example.com']
    }
    
    # Mock plugin execution
    with patch.object(SubdomainEnumPlugin, 'execute', return_value=mock_subdomain_results), \
         patch.object(PortScannerPlugin, 'execute', return_value=mock_port_scan_results):
        
        result = await stage.execute(TEST_DOMAIN)
        
        # Verify stage execution
        assert result['success'] is True
        assert result['target'] == TEST_DOMAIN
        assert 'timestamp' in result
        assert 'subdomains' in result
        assert 'ports' in result
        
        # Verify subdomain results
        assert len(result['subdomains']) == len(TEST_SUBDOMAINS)
        assert all(subdomain in result['subdomains'] for subdomain in TEST_SUBDOMAINS)
        
        # Verify port scan results
        assert len(result['ports']) > 0
        assert any(port['port'] == 80 and port['service'] == 'http' for port in result['ports'])
        assert any(port['port'] == 443 and port['service'] == 'https' for port in result['ports'])

@pytest.mark.asyncio
async def test_stage_execution_with_plugin_errors(stage, mock_session, mock_dns_resolver):
    """Test stage execution when plugins encounter errors."""
    # Mock plugin errors
    with patch.object(SubdomainEnumPlugin, 'execute', side_effect=PluginError("Subdomain enumeration failed")), \
         patch.object(PortScannerPlugin, 'execute', side_effect=PluginError("Port scan failed")):
        
        with pytest.raises(StageError) as exc_info:
            await stage.execute(TEST_DOMAIN)
        
        assert "Stage execution failed" in str(exc_info.value)

@pytest.mark.asyncio
async def test_stage_execution_with_partial_results(stage, mock_session, mock_dns_resolver, mock_env_vars):
    """Test stage execution when some plugins succeed and others fail."""
    # Mock mixed results
    mock_subdomain_results = {
        'success': True,
        'target': TEST_DOMAIN,
        'timestamp': datetime.utcnow().isoformat(),
        'subdomains': TEST_SUBDOMAINS,
        'dns_records': {}
    }
    
    with patch.object(SubdomainEnumPlugin, 'execute', return_value=mock_subdomain_results), \
         patch.object(PortScannerPlugin, 'execute', side_effect=PluginError("Port scan failed")):
        
        result = await stage.execute(TEST_DOMAIN)
        
        # Verify partial results
        assert result['success'] is True
        assert 'subdomains' in result
        assert len(result['subdomains']) == len(TEST_SUBDOMAINS)
        assert 'ports' not in result

@pytest.mark.asyncio
async def test_stage_cleanup(stage):
    """Test stage cleanup."""
    # Mock plugin cleanup
    with patch.object(SubdomainEnumPlugin, 'cleanup') as mock_subdomain_cleanup, \
         patch.object(PortScannerPlugin, 'cleanup') as mock_port_cleanup:
        
        await stage.cleanup()
        
        # Verify all plugins were cleaned up
        mock_subdomain_cleanup.assert_called_once()
        mock_port_cleanup.assert_called_once()

@pytest.mark.asyncio
async def test_stage_configuration(stage):
    """Test stage configuration handling."""
    # Test with custom configuration
    config = {
        'enabled': True,
        'timeout': 600,
        'plugins': {
            'subdomain_enum': {
                'enabled': True,
                'timeout': 300,
                'wordlist_path': 'custom_wordlist.txt'
            },
            'port_scan': {
                'enabled': True,
                'timeout': 300,
                'ports': [80, 443, 22, 25],
                'scan_types': ['tcp']
            }
        }
    }
    
    stage.configure(config)
    
    # Verify configuration was applied
    assert stage.timeout == 600
    
    # Verify plugin configurations
    subdomain_plugin = next(p for p in stage.plugins if isinstance(p, SubdomainEnumPlugin))
    port_plugin = next(p for p in stage.plugins if isinstance(p, PortScannerPlugin))
    
    assert subdomain_plugin.timeout == 300
    assert subdomain_plugin.wordlist_path == 'custom_wordlist.txt'
    assert port_plugin.timeout == 300
    assert port_plugin.ports == [80, 443, 22, 25]
    assert port_plugin.scan_types == ['tcp']

@pytest.mark.asyncio
async def test_stage_plugin_ordering(stage):
    """Test that plugins are executed in the correct order."""
    execution_order = []
    
    async def mock_subdomain_execute(*args, **kwargs):
        execution_order.append('subdomain_enum')
        return {
            'success': True,
            'target': TEST_DOMAIN,
            'subdomains': TEST_SUBDOMAINS
        }
    
    async def mock_port_scan_execute(*args, **kwargs):
        execution_order.append('port_scan')
        return {
            'success': True,
            'target': TEST_DOMAIN,
            'ports': []
        }
    
    with patch.object(SubdomainEnumPlugin, 'execute', side_effect=mock_subdomain_execute), \
         patch.object(PortScannerPlugin, 'execute', side_effect=mock_port_scan_execute):
        
        await stage.execute(TEST_DOMAIN)
        
        # Verify execution order
        assert execution_order == ['subdomain_enum', 'port_scan']

@pytest.mark.asyncio
async def test_stage_result_aggregation(stage, mock_session, mock_dns_resolver, mock_env_vars):
    """Test that stage properly aggregates results from all plugins."""
    # Mock plugin results
    mock_subdomain_results = {
        'success': True,
        'target': TEST_DOMAIN,
        'timestamp': datetime.utcnow().isoformat(),
        'subdomains': TEST_SUBDOMAINS,
        'dns_records': {
            'www.example.com': {
                'type': 'A',
                'data': '93.184.216.34'
            }
        }
    }
    
    mock_port_scan_results = {
        'success': True,
        'target': 'www.example.com',
        'timestamp': datetime.utcnow().isoformat(),
        'ports': TEST_OPEN_PORTS['www.example.com']
    }
    
    with patch.object(SubdomainEnumPlugin, 'execute', return_value=mock_subdomain_results), \
         patch.object(PortScannerPlugin, 'execute', return_value=mock_port_scan_results):
        
        result = await stage.execute(TEST_DOMAIN)
        
        # Verify result aggregation
        assert result['success'] is True
        assert result['target'] == TEST_DOMAIN
        assert 'timestamp' in result
        assert 'subdomains' in result
        assert 'ports' in result
        assert 'dns_records' in result
        
        # Verify all plugin results are included
        assert len(result['subdomains']) == len(TEST_SUBDOMAINS)
        assert len(result['ports']) == len(TEST_OPEN_PORTS['www.example.com'])
        assert 'www.example.com' in result['dns_records'] 