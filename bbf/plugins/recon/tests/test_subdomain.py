"""
Tests for the SubdomainEnumPlugin.

This module contains test cases for the subdomain enumeration plugin,
verifying its functionality for discovering subdomains using various techniques.
"""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import dns.resolver
from dns.resolver import Answer
from datetime import datetime

from bbf.plugins.recon.subdomain import SubdomainEnumPlugin
from bbf.core.exceptions import PluginError

# Test data
TEST_DOMAIN = "example.com"
TEST_SUBDOMAINS = [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com",
    "staging.example.com"
]
TEST_IP = "93.184.216.34"  # example.com's IP
TEST_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "nonexistent"
]

@pytest.fixture
def plugin():
    """Create a plugin instance for testing."""
    return SubdomainEnumPlugin()

@pytest.fixture
def mock_dns_resolver():
    """Create a mock DNS resolver."""
    with patch('dns.resolver.Resolver') as mock:
        resolver = mock.return_value
        resolver.resolve = AsyncMock()
        resolver.resolve_address = AsyncMock()
        yield resolver

@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = mock.return_value
        session.get = AsyncMock()
        session.close = AsyncMock()
        yield session

@pytest.fixture
def mock_wordlist(tmp_path):
    """Create a temporary wordlist file."""
    wordlist_path = tmp_path / "test_wordlist.txt"
    with open(wordlist_path, 'w') as f:
        f.write('\n'.join(TEST_WORDLIST))
    return str(wordlist_path)

@pytest.mark.asyncio
async def test_plugin_initialization(plugin, mock_wordlist):
    """Test plugin initialization."""
    # Configure plugin with test wordlist
    plugin.wordlist_path = mock_wordlist
    
    # Initialize plugin
    await plugin.initialize()
    
    # Verify initialization
    assert plugin._session is not None
    assert len(plugin._wordlist) == len(TEST_WORDLIST)
    assert plugin._dns_resolver is not None
    assert plugin._dns_resolver.timeout == 5.0
    assert plugin._dns_resolver.lifetime == 10.0

@pytest.mark.asyncio
async def test_plugin_initialization_missing_wordlist(plugin):
    """Test plugin initialization with missing wordlist."""
    plugin.wordlist_path = "nonexistent_wordlist.txt"
    
    # Verify initialization fails
    with pytest.raises(PluginError) as exc_info:
        await plugin.initialize()
    assert "Wordlist not found" in str(exc_info.value)

@pytest.mark.asyncio
async def test_dns_enumeration(plugin, mock_dns_resolver):
    """Test DNS enumeration functionality."""
    # Mock DNS resolver responses
    mock_answers = {
        'A': [Answer(TEST_DOMAIN, 'A', 'IN', TEST_IP)],
        'CNAME': [Answer(TEST_DOMAIN, 'CNAME', 'IN', 'www.example.com.')],
        'MX': [Answer(TEST_DOMAIN, 'MX', 'IN', 'mail.example.com.')],
        'NS': [Answer(TEST_DOMAIN, 'NS', 'IN', 'ns1.example.com.')],
        'TXT': [Answer(TEST_DOMAIN, 'TXT', 'IN', 'v=spf1 include:_spf.example.com')]
    }
    
    def mock_resolve(domain, record_type):
        if record_type in mock_answers:
            return mock_answers[record_type]
        raise dns.resolver.NoAnswer()
        
    mock_dns_resolver.resolve.side_effect = mock_resolve
    
    # Run DNS enumeration
    subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) > 0
    assert "www.example.com" in subdomains
    assert "mail.example.com" in subdomains
    assert "ns1.example.com" in subdomains

@pytest.mark.asyncio
async def test_certificate_transparency(plugin, mock_session):
    """Test certificate transparency check functionality."""
    # Mock API response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=[
        {
            'dns_names': [
                'www.example.com',
                'api.example.com',
                'mail.example.com'
            ]
        }
    ])
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Configure plugin with API key
    plugin.api_keys['certspotter'] = 'test_api_key'
    
    # Run certificate transparency check
    subdomains = await plugin._certificate_transparency(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 3
    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "mail.example.com" in subdomains

@pytest.mark.asyncio
async def test_web_archives(plugin, mock_session):
    """Test web archives search functionality."""
    # Mock API response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=[
        ['urlkey', 'timestamp', 'original'],
        ['www.example.com', '20230101', 'https://www.example.com/'],
        ['api.example.com', '20230101', 'https://api.example.com/'],
        ['mail.example.com', '20230101', 'https://mail.example.com/']
    ])
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    # Configure plugin with API key
    plugin.api_keys['wayback'] = 'test_api_key'
    
    # Run web archives search
    subdomains = await plugin._web_archives(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 3
    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "mail.example.com" in subdomains

@pytest.mark.asyncio
async def test_subdomain_bruteforce(plugin, mock_dns_resolver, mock_wordlist):
    """Test subdomain bruteforcing functionality."""
    # Configure plugin with test wordlist
    plugin.wordlist_path = mock_wordlist
    await plugin.initialize()
    
    # Mock DNS resolver responses
    def mock_resolve(domain, record_type):
        if domain in TEST_SUBDOMAINS:
            return [Answer(domain, 'A', 'IN', TEST_IP)]
        raise dns.resolver.NXDOMAIN()
        
    mock_dns_resolver.resolve.side_effect = mock_resolve
    
    # Run subdomain bruteforce
    subdomains = await plugin._subdomain_bruteforce(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 5
    assert all(subdomain in TEST_SUBDOMAINS for subdomain in subdomains)

@pytest.mark.asyncio
async def test_reverse_dns(plugin, mock_dns_resolver):
    """Test reverse DNS lookup functionality."""
    # Mock DNS resolver responses
    mock_dns_resolver.resolve.return_value = [Answer(TEST_DOMAIN, 'A', 'IN', TEST_IP)]
    mock_dns_resolver.resolve_address.return_value = [
        Answer(TEST_IP, 'PTR', 'IN', 'www.example.com.')
    ]
    
    # Run reverse DNS lookup
    subdomains = await plugin._reverse_dns(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 1
    assert "www.example.com" in subdomains

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_dns_resolver, mock_session, mock_wordlist):
    """Test complete plugin execution."""
    # Configure plugin
    plugin.wordlist_path = mock_wordlist
    plugin.api_keys = {
        'certspotter': 'test_cert_key',
        'wayback': 'test_wayback_key'
    }
    
    # Mock DNS resolver responses
    def mock_resolve(domain, record_type):
        if domain in TEST_SUBDOMAINS:
            return [Answer(domain, 'A', 'IN', TEST_IP)]
        raise dns.resolver.NXDOMAIN()
        
    mock_dns_resolver.resolve.side_effect = mock_resolve
    mock_dns_resolver.resolve_address.return_value = [
        Answer(TEST_IP, 'PTR', 'IN', 'www.example.com.')
    ]
    
    # Mock API responses
    mock_cert_response = MagicMock()
    mock_cert_response.status = 200
    mock_cert_response.json = AsyncMock(return_value=[
        {'dns_names': ['api.example.com', 'mail.example.com']}
    ])
    
    mock_wayback_response = MagicMock()
    mock_wayback_response.status = 200
    mock_wayback_response.json = AsyncMock(return_value=[
        ['urlkey', 'timestamp', 'original'],
        ['dev.example.com', '20230101', 'https://dev.example.com/']
    ])
    
    mock_session.get.side_effect = [
        mock_cert_response.__aenter__.return_value,
        mock_wayback_response.__aenter__.return_value
    ]
    
    # Initialize and run plugin
    await plugin.initialize()
    result = await plugin.execute(TEST_DOMAIN)
    
    # Verify results
    assert result['target'] == TEST_DOMAIN
    assert len(result['subdomains']) > 0
    assert result['count'] == len(result['subdomains'])
    assert isinstance(result['execution_time'], float)
    assert all(isinstance(v, bool) for v in result['techniques'].values())
    
    # Verify all techniques were attempted
    assert all(result['techniques'].values())

@pytest.mark.asyncio
async def test_plugin_cleanup(plugin, mock_session):
    """Test plugin cleanup."""
    # Initialize plugin
    await plugin.initialize()
    
    # Run cleanup
    await plugin.cleanup()
    
    # Verify cleanup
    assert plugin._session is None
    mock_session.close.assert_called_once()

@pytest.mark.asyncio
async def test_plugin_error_handling(plugin, mock_dns_resolver):
    """Test plugin error handling."""
    # Mock DNS resolver to raise an exception
    mock_dns_resolver.resolve.side_effect = Exception("DNS error")
    
    # Verify error handling in DNS enumeration
    with pytest.raises(PluginError) as exc_info:
        await plugin._dns_enumeration(TEST_DOMAIN)
    assert "DNS enumeration failed" in str(exc_info.value)
    
    # Verify error handling in plugin execution
    with pytest.raises(PluginError) as exc_info:
        await plugin.execute(TEST_DOMAIN)
    assert "Plugin execution failed" in str(exc_info.value) 