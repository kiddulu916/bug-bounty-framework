"""
Test suite for the subdomain enumeration plugin.

This module tests:
- Plugin initialization and cleanup
- DNS enumeration
- Certificate transparency checks
- Web scraping
- Search engine discovery
- DNS zone transfers
- Database integration
- Error handling
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

import aiohttp
import aiodns
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin, SubdomainResult
from bbf.core.database.models import SubdomainFinding
from bbf.core.database.service import finding_service

# Test data
TEST_DOMAIN = "example.com"
TEST_SUBDOMAINS = [
    "sub1.example.com",
    "sub2.example.com",
    "www.example.com",
    "mail.example.com"
]
TEST_IP = "1.1.1.1"

@pytest.fixture
def plugin():
    """Create plugin instance."""
    return SubdomainEnumPlugin()

@pytest.fixture
def mock_dns_resolver():
    """Create mock DNS resolver."""
    with patch('aiodns.DNSResolver') as mock:
        resolver = AsyncMock()
        resolver.query = AsyncMock()
        mock.return_value = resolver
        yield resolver

@pytest.fixture
def mock_session():
    """Create mock aiohttp session."""
    with patch('aiohttp.ClientSession') as mock:
        session = AsyncMock()
        mock.return_value = session
        yield session

@pytest.fixture
def mock_cert():
    """Create mock SSL certificate."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, TEST_DOMAIN)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow()
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(subdomain) for subdomain in TEST_SUBDOMAINS
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    return cert

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
async def test_dns_enumeration(plugin, mock_dns_resolver):
    """Test DNS enumeration."""
    # Mock DNS responses
    mock_dns_resolver.query.side_effect = [
        [Mock(host=TEST_SUBDOMAINS[0])],  # A record
        [Mock(host=TEST_SUBDOMAINS[1])],  # AAAA record
        [Mock(host=TEST_SUBDOMAINS[2])],  # CNAME record
        [Mock(host=TEST_SUBDOMAINS[3])],  # MX record
        [],  # NS record
        []   # TXT record
    ]
    
    # Run DNS enumeration
    subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 4
    for subdomain in subdomains:
        assert subdomain['name'] in TEST_SUBDOMAINS
        assert subdomain['source'] == 'dns_enumeration'
        assert subdomain['confidence'] == 0.9
        assert isinstance(subdomain['timestamp'], datetime)

@pytest.mark.asyncio
async def test_certificate_transparency(plugin, mock_session, mock_cert):
    """Test certificate transparency checks."""
    # Mock CT log responses
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value=[
        {
            'certificate': mock_cert.public_bytes(Encoding.PEM).decode()
        }
    ])
    
    # Run CT check
    subdomains = await plugin._certificate_transparency(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == len(TEST_SUBDOMAINS)
    for subdomain in subdomains:
        assert subdomain['name'] in TEST_SUBDOMAINS
        assert subdomain['source'] == 'certificate_transparency'
        assert subdomain['confidence'] == 0.95
        assert isinstance(subdomain['timestamp'], datetime)

@pytest.mark.asyncio
async def test_web_scraping(plugin, mock_session):
    """Test web scraping."""
    # Mock web responses
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value=f"""
        <html>
            <body>
                <a href="https://{TEST_SUBDOMAINS[0]}">Link 1</a>
                <a href="https://{TEST_SUBDOMAINS[1]}">Link 2</a>
                <a href="https://other.com">Link 3</a>
            </body>
        </html>
    """)
    
    # Run web scraping
    subdomains = await plugin._web_scraping(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 2
    for subdomain in subdomains:
        assert subdomain['name'] in TEST_SUBDOMAINS[:2]
        assert subdomain['source'] == 'web_scraping'
        assert subdomain['confidence'] == 0.8
        assert isinstance(subdomain['timestamp'], datetime)

@pytest.mark.asyncio
async def test_search_engine_discovery(plugin, mock_session):
    """Test search engine discovery."""
    # Mock search engine responses
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value=f"""
        <html>
            <body>
                <a href="https://{TEST_SUBDOMAINS[0]}">Result 1</a>
                <a href="https://{TEST_SUBDOMAINS[1]}">Result 2</a>
                <a href="https://other.com">Result 3</a>
            </body>
        </html>
    """)
    
    # Run search engine discovery
    subdomains = await plugin._search_engine_discovery(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 2
    for subdomain in subdomains:
        assert subdomain['name'] in TEST_SUBDOMAINS[:2]
        assert subdomain['source'] == 'search_engine'
        assert subdomain['confidence'] == 0.7
        assert isinstance(subdomain['timestamp'], datetime)

@pytest.mark.asyncio
async def test_dns_zone_transfer(plugin, mock_dns_resolver, mock_session):
    """Test DNS zone transfer."""
    # Mock nameserver response
    mock_dns_resolver.query.return_value = [Mock(host='ns1.example.com')]
    
    # Mock zone transfer response
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value={
        'records': [
            {'name': TEST_SUBDOMAINS[0]},
            {'name': TEST_SUBDOMAINS[1]}
        ]
    })
    
    # Run zone transfer
    subdomains = await plugin._dns_zone_transfer(TEST_DOMAIN)
    
    # Verify results
    assert len(subdomains) == 2
    for subdomain in subdomains:
        assert subdomain['name'] in TEST_SUBDOMAINS[:2]
        assert subdomain['source'] == 'zone_transfer'
        assert subdomain['confidence'] == 1.0
        assert isinstance(subdomain['timestamp'], datetime)

@pytest.mark.asyncio
async def test_plugin_execution(plugin, mock_dns_resolver, mock_session, mock_cert):
    """Test complete plugin execution."""
    # Mock all responses
    mock_dns_resolver.query.side_effect = [
        [Mock(host=TEST_SUBDOMAINS[0])],  # DNS enumeration
        [Mock(host='ns1.example.com')],   # Zone transfer
        [Mock(host=TEST_IP)]              # IP resolution
    ]
    
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value=[
        {'certificate': mock_cert.public_bytes(Encoding.PEM).decode()}
    ])
    mock_session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value="<html></html>")
    
    # Mock database operations
    with patch.object(finding_service, 'add_subdomain_findings') as mock_add_findings:
        mock_add_findings.return_value = [
            SubdomainFinding(
                id=1,
                plugin_result_id=1,
                name=TEST_SUBDOMAINS[0],
                ip_address=TEST_IP,
                source='dns_enumeration',
                confidence=0.9,
                timestamp=datetime.utcnow()
            )
        ]
        
        # Execute plugin
        plugin.current_plugin_result_id = 1
        results = await plugin.execute(TEST_DOMAIN)
        
        # Verify results
        assert len(results) == 1
        assert results[0]['name'] == TEST_SUBDOMAINS[0]
        assert results[0]['ip_address'] == TEST_IP
        
        # Verify database call
        mock_add_findings.assert_called_once()

@pytest.mark.asyncio
async def test_plugin_error_handling(plugin, mock_dns_resolver, mock_session):
    """Test plugin error handling."""
    # Mock DNS resolver to raise exception
    mock_dns_resolver.query.side_effect = Exception("DNS error")
    
    # Mock session to raise exception
    mock_session.get.side_effect = Exception("HTTP error")
    
    # Execute plugin
    results = await plugin.execute(TEST_DOMAIN)
    
    # Verify no results on error
    assert len(results) == 0

@pytest.mark.asyncio
async def test_database_integration(plugin, mock_dns_resolver, mock_session):
    """Test database integration."""
    # Mock DNS response
    mock_dns_resolver.query.return_value = [Mock(host=TEST_SUBDOMAINS[0])]
    
    # Mock session response
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value="<html></html>")
    
    # Mock database operations
    with patch.object(finding_service.subdomain_repo, 'get_session') as mock_get_session, \
         patch.object(finding_service, 'add_subdomain_findings') as mock_add_findings:
        
        # Mock database session
        mock_db_session = Mock()
        mock_get_session.return_value.__enter__.return_value = mock_db_session
        
        # Mock findings
        mock_findings = [
            SubdomainFinding(
                id=1,
                plugin_result_id=1,
                name=TEST_SUBDOMAINS[0],
                ip_address=TEST_IP,
                source='dns_enumeration',
                confidence=0.9,
                timestamp=datetime.utcnow()
            )
        ]
        mock_add_findings.return_value = mock_findings
        
        # Execute plugin
        plugin.current_plugin_result_id = 1
        results = await plugin.execute(TEST_DOMAIN)
        
        # Verify database operations
        mock_get_session.assert_called_once()
        mock_add_findings.assert_called_once_with(
            mock_db_session,
            plugin_result_id=1,
            findings=mock.ANY
        )
        
        # Verify results
        assert len(results) == 1
        assert results[0]['name'] == TEST_SUBDOMAINS[0]
        assert results[0]['ip_address'] == TEST_IP

@pytest.mark.asyncio
async def test_concurrent_execution(plugin, mock_dns_resolver, mock_session):
    """Test concurrent plugin execution."""
    # Mock responses
    mock_dns_resolver.query.return_value = [Mock(host=TEST_SUBDOMAINS[0])]
    mock_session.get.return_value.__aenter__.return_value.status = 200
    mock_session.get.return_value.__aenter__.return_value.text = AsyncMock(return_value="<html></html>")
    
    # Mock database operations
    with patch.object(finding_service, 'add_subdomain_findings') as mock_add_findings:
        mock_add_findings.return_value = [
            SubdomainFinding(
                id=1,
                plugin_result_id=1,
                name=TEST_SUBDOMAINS[0],
                ip_address=TEST_IP,
                source='dns_enumeration',
                confidence=0.9,
                timestamp=datetime.utcnow()
            )
        ]
        
        # Execute plugin concurrently
        plugin.current_plugin_result_id = 1
        tasks = [
            plugin.execute(TEST_DOMAIN),
            plugin.execute(TEST_DOMAIN)
        ]
        results = await asyncio.gather(*tasks)
        
        # Verify results
        assert len(results) == 2
        for result in results:
            assert len(result) == 1
            assert result[0]['name'] == TEST_SUBDOMAINS[0]
            
        # Verify database calls
        assert mock_add_findings.call_count == 2 