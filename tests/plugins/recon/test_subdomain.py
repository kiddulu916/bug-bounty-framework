"""
Unit tests for the SubdomainEnumPlugin.
"""

import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import aiohttp
import json
from datetime import datetime

from bbf.plugins.recon.subdomain import SubdomainEnumPlugin
from bbf.core.exceptions import PluginError

# Test data
TEST_DOMAIN = "example.com"
TEST_SUBDOMAINS = [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com"
]

# Mock DNS responses
MOCK_DNS_RESPONSES = {
    'A': ['93.184.216.34'],
    'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
    'CNAME': ['example.com.'],
    'MX': ['mail.example.com.'],
    'NS': ['ns1.example.com.', 'ns2.example.com.'],
    'TXT': ['v=spf1 include:_spf.example.com ~all'],
    'PTR': ['example.com.']
}

# Mock Certspotter API response
MOCK_CERTSPOTTER_RESPONSE = [
    {
        "dns_names": [
            "example.com",
            "www.example.com",
            "mail.example.com"
        ]
    },
    {
        "dns_names": [
            "api.example.com",
            "dev.example.com"
        ]
    }
]

# Mock Wayback Machine API response
MOCK_WAYBACK_RESPONSE = [
    ["urlkey", "timestamp", "original"],
    ["com,example)/", "20230101000000", "https://www.example.com/"],
    ["com,example,api)/", "20230101000000", "https://api.example.com/"],
    ["com,example,dev)/", "20230101000000", "https://dev.example.com/"]
]

@pytest.fixture
def plugin():
    """Create a plugin instance for testing."""
    return SubdomainEnumPlugin()

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
            mock_answer.__str__.return_value = MOCK_DNS_RESPONSES[record_type][0]
            return [mock_answer]
        mock.side_effect = mock_resolve
        yield mock

@pytest.mark.asyncio
async def test_plugin_initialization(plugin, mock_env_vars):
    """Test plugin initialization."""
    assert plugin.name == "subdomain_enum"
    assert plugin.description == "Enumerates subdomains using multiple techniques"
    assert plugin.version == "1.0.0"
    assert plugin.enabled is True
    assert plugin.timeout == 300
    assert plugin._cert_api_key == 'test_cert_key'
    assert plugin._wayback_api_key == 'test_wayback_key'

@pytest.mark.asyncio
async def test_plugin_initialization_without_api_keys(plugin):
    """Test plugin initialization without API keys."""
    assert plugin._cert_api_key is None
    assert plugin._wayback_api_key is None

@pytest.mark.asyncio
async def test_dns_enumeration(plugin, mock_dns_resolver):
    """Test DNS enumeration functionality."""
    subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
    
    # Verify DNS resolver was called for each record type
    assert mock_dns_resolver.call_count == len(plugin._dns_enumeration.__annotations__['record_types'])
    
    # Verify results
    assert len(subdomains) > 0
    assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)

@pytest.mark.asyncio
async def test_certificate_transparency(plugin, mock_session, mock_env_vars):
    """Test certificate transparency log checking."""
    # Mock API response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=MOCK_CERTSPOTTER_RESPONSE)
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    subdomains = await plugin._certificate_transparency(TEST_DOMAIN)
    
    # Verify API call
    mock_session.get.assert_called_once()
    assert 'Authorization' in mock_session.get.call_args[1]['headers']
    
    # Verify results
    assert len(subdomains) == 5  # Total unique subdomains from mock response
    assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)

@pytest.mark.asyncio
async def test_web_archive_search(plugin, mock_session, mock_env_vars):
    """Test web archive searching."""
    # Mock API response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=MOCK_WAYBACK_RESPONSE)
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    subdomains = await plugin._web_archive_search(TEST_DOMAIN)
    
    # Verify API call
    mock_session.get.assert_called_once()
    assert 'Authorization' in mock_session.get.call_args[1]['headers']
    
    # Verify results
    assert len(subdomains) == 3  # Total unique subdomains from mock response
    assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)

@pytest.mark.asyncio
async def test_subdomain_bruteforce(plugin):
    """Test subdomain bruteforcing."""
    # Create a temporary wordlist file
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "www\n",
            "mail\n",
            "api\n",
            "dev\n"
        ]
        
        subdomains = await plugin._subdomain_bruteforce(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) > 0
        assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)

@pytest.mark.asyncio
async def test_reverse_dns_lookup(plugin, mock_dns_resolver):
    """Test reverse DNS lookup."""
    # Set up some DNS records
    plugin._dns_records[TEST_DOMAIN] = {
        'type': 'A',
        'data': '93.184.216.34',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    await plugin._reverse_dns_lookup(TEST_DOMAIN)
    
    # Verify DNS resolver was called
    assert mock_dns_resolver.call_count > 0

@pytest.mark.asyncio
async def test_execute_full_scan(plugin, mock_session, mock_dns_resolver, mock_env_vars):
    """Test full plugin execution with all methods."""
    # Mock API responses
    mock_cert_response = AsyncMock()
    mock_cert_response.status = 200
    mock_cert_response.json = AsyncMock(return_value=MOCK_CERTSPOTTER_RESPONSE)
    
    mock_wayback_response = AsyncMock()
    mock_wayback_response.status = 200
    mock_wayback_response.json = AsyncMock(return_value=MOCK_WAYBACK_RESPONSE)
    
    mock_session.get.side_effect = [mock_cert_response, mock_wayback_response]
    
    # Mock wordlist file
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "www\n",
            "mail\n",
            "api\n",
            "dev\n"
        ]
        
        result = await plugin.execute(TEST_DOMAIN)
        
        # Verify result structure
        assert result['success'] is True
        assert result['target'] == TEST_DOMAIN
        assert 'timestamp' in result
        assert 'subdomains' in result
        assert 'dns_records' in result
        
        # Verify subdomains were found
        assert len(result['subdomains']) > 0
        assert all(domain.endswith(TEST_DOMAIN) for domain in result['subdomains'])

@pytest.mark.asyncio
async def test_execute_without_api_keys(plugin, mock_session, mock_dns_resolver):
    """Test plugin execution without API keys."""
    # Mock wordlist file
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "www\n",
            "mail\n",
            "api\n",
            "dev\n"
        ]
        
        result = await plugin.execute(TEST_DOMAIN)
        
        # Verify only DNS and bruteforce methods were used
        assert result['success'] is True
        assert len(result['subdomains']) > 0
        assert all(domain.endswith(TEST_DOMAIN) for domain in result['subdomains'])
        
        # Verify API calls were not made
        mock_session.get.assert_not_called()

@pytest.mark.asyncio
async def test_error_handling(plugin, mock_session):
    """Test error handling in plugin methods."""
    # Test DNS enumeration error
    with patch('dns.resolver.resolve', side_effect=Exception("DNS error")):
        subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
        assert len(subdomains) == 0
    
    # Test certificate transparency error
    mock_session.get.side_effect = aiohttp.ClientError("API error")
    subdomains = await plugin._certificate_transparency(TEST_DOMAIN)
    assert len(subdomains) == 0
    
    # Test web archive error
    subdomains = await plugin._web_archive_search(TEST_DOMAIN)
    assert len(subdomains) == 0
    
    # Test plugin execution with errors
    result = await plugin.execute(TEST_DOMAIN)
    assert result['success'] is True  # Plugin should still return success
    assert 'subdomains' in result
    assert 'dns_records' in result 