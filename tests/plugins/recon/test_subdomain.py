"""
Tests for the SubdomainEnumPlugin.

This module contains comprehensive test cases for the subdomain enumeration plugin,
verifying its functionality for discovering subdomains using various techniques.

Test Categories:
- Basic Functionality: Core plugin initialization and execution
- DNS Enumeration: DNS record type queries and resolution
- Certificate Transparency: SSL/TLS certificate analysis
- Web Archives: Historical subdomain discovery
- Bruteforce: Wordlist-based subdomain discovery
- Reverse DNS: IP to domain mapping
- Error Handling: Plugin behavior during failures
- API Integration: External service interaction
- Resource Management: Session and resource cleanup
- Performance: Concurrent scanning and rate limiting

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: Plugin lifecycle and configuration
2. DNS Enumeration: Various DNS record types and resolution
3. Certificate Transparency: SSL/TLS certificate analysis
4. Web Archives: Historical data analysis
5. Bruteforce: Wordlist-based discovery
6. Reverse DNS: IP to domain mapping
7. Error Handling: Failure scenarios and recovery
8. API Integration: External service interaction
9. Resource Management: Resource cleanup and management
10. Performance: Concurrent scanning and resource limits
"""

import asyncio
import os
import pytest
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
import dns.resolver
from dns.resolver import Answer
from datetime import datetime
import aiohttp
import json

from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin
from bbf.core.exceptions import PluginError

# Test Configuration
TEST_DOMAIN = "example.com"
TEST_IP = "93.184.216.34"  # example.com's IP
TEST_CONCURRENT_CONNECTIONS = 50
TEST_DNS_TIMEOUT = 5.0
TEST_DNS_LIFETIME = 10.0
TEST_MAX_RETRIES = 3

# Test Data
TEST_SUBDOMAINS = [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com",
    "staging.example.com"
]

TEST_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "nonexistent"
]

# Expected Results
EXPECTED_SUBDOMAINS = {
    'dns': [
        "www.example.com",
        "mail.example.com",
        "ns1.example.com",
        "ns2.example.com"
    ],
    'cert': [
        "www.example.com",
        "mail.example.com",
        "api.example.com",
        "dev.example.com"
    ],
    'wayback': [
        "www.example.com",
        "api.example.com",
        "dev.example.com"
    ],
    'bruteforce': [
        "www.example.com",
        "mail.example.com",
        "api.example.com",
        "dev.example.com",
        "staging.example.com"
    ]
}

# Mock DNS Responses
MOCK_DNS_RESPONSES = {
    'A': ['93.184.216.34'],
    'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
    'CNAME': ['example.com.'],
    'MX': ['mail.example.com.'],
    'NS': ['ns1.example.com.', 'ns2.example.com.'],
    'TXT': ['v=spf1 include:_spf.example.com ~all'],
    'PTR': ['example.com.']
}

# Mock API Responses
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

MOCK_WAYBACK_RESPONSE = [
    ["urlkey", "timestamp", "original"],
    ["com,example)/", "20230101000000", "https://www.example.com/"],
    ["com,example,api)/", "20230101000000", "https://api.example.com/"],
    ["com,example,dev)/", "20230101000000", "https://dev.example.com/"]
]

class TestSubdomainEnumPlugin:
    """
    Test suite for SubdomainEnumPlugin.
    
    This class implements comprehensive tests for the subdomain enumeration plugin,
    covering all aspects of its functionality from basic initialization to
    advanced discovery techniques.
    
    The test suite is organized into logical categories, each focusing on a specific
    aspect of the plugin's functionality. This organization helps maintain clarity
    and makes it easier to identify and fix issues.
    """
    
    @pytest.fixture
    def plugin(self) -> SubdomainEnumPlugin:
        """
        Create a plugin instance for testing.
        
        Returns:
            SubdomainEnumPlugin: Plugin instance configured for testing
        """
        return SubdomainEnumPlugin()
    
    @pytest.fixture
    def mock_env_vars(self) -> AsyncGenerator[None, None]:
        """
        Set up mock environment variables for API keys.
        
        This fixture provides a context manager that sets up mock environment
        variables for external API access. It ensures that tests can run
        without actual API credentials.
        
        Yields:
            None: Context manager for environment variables
        """
        with patch.dict(os.environ, {
            'CERT_API_KEY': 'test_cert_key',
            'WAYBACK_API_KEY': 'test_wayback_key'
        }):
            yield
    
    @pytest.fixture
    def mock_dns_resolver(self) -> AsyncGenerator[MagicMock, None]:
        """
        Create a mock DNS resolver for testing.
        
        This fixture provides a mock DNS resolver that simulates DNS queries
        and responses. It allows testing DNS-related functionality without
        making actual network requests.
        
        Yields:
            MagicMock: Mocked DNS resolver with predefined responses
        """
        with patch('dns.resolver.Resolver') as mock:
            resolver = mock.return_value
            resolver.resolve = AsyncMock()
            resolver.resolve_address = AsyncMock()
            
            def mock_resolve(domain: str, record_type: str) -> List[Answer]:
                """
                Mock DNS resolution function.
                
                Args:
                    domain: Domain to resolve
                    record_type: Type of DNS record to query
                    
                Returns:
                    List[Answer]: List of mock DNS answers
                    
                Raises:
                    dns.resolver.NoAnswer: If no records found
                """
                if record_type in MOCK_DNS_RESPONSES:
                    mock_answer = MagicMock()
                    mock_answer.__str__.return_value = MOCK_DNS_RESPONSES[record_type][0]
                    return [mock_answer]
                raise dns.resolver.NoAnswer()
            
            resolver.resolve.side_effect = mock_resolve
            yield resolver
    
    @pytest.fixture
    def mock_session(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Create a mock HTTP session for testing.
        
        This fixture provides a mock aiohttp session that simulates HTTP
        requests and responses. It allows testing HTTP-related functionality
        without making actual network requests.
        
        Yields:
            AsyncMock: Mocked HTTP session with predefined responses
        """
        with patch('aiohttp.ClientSession') as mock:
            session = AsyncMock()
            mock.return_value.__aenter__.return_value = session
            yield session
    
    @pytest.fixture
    def mock_wordlist(self, tmp_path: Any) -> str:
        """
        Create a temporary wordlist file for testing.
        
        This fixture creates a temporary file containing test subdomain
        prefixes. It ensures that tests can run without requiring an
        actual wordlist file.
        
        Args:
            tmp_path: Temporary directory path provided by pytest
            
        Returns:
            str: Path to the temporary wordlist file
        """
        wordlist_path = tmp_path / "test_wordlist.txt"
        with open(wordlist_path, 'w') as f:
            f.write('\n'.join(TEST_WORDLIST))
        return str(wordlist_path)

class TestBasicFunctionality(TestSubdomainEnumPlugin):
    """Tests for basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin: SubdomainEnumPlugin, mock_wordlist: str) -> None:
        """
        Test plugin initialization.
        
        This test verifies that the plugin:
        1. Initializes with correct configuration
        2. Loads wordlist successfully
        3. Sets up DNS resolver with proper timeouts
        4. Creates HTTP session
        
        Args:
            plugin: Plugin instance
            mock_wordlist: Path to wordlist file
        """
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
    async def test_plugin_initialization_missing_wordlist(self, plugin: SubdomainEnumPlugin) -> None:
        """
        Test plugin initialization with missing wordlist.
        
        This test verifies that the plugin:
        1. Handles missing wordlist gracefully
        2. Raises appropriate error
        3. Provides clear error message
        
        Args:
            plugin: Plugin instance
        """
        plugin.wordlist_path = "nonexistent_wordlist.txt"
        
        # Verify initialization fails
        with pytest.raises(PluginError) as exc_info:
            await plugin.initialize()
        assert "Wordlist not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, plugin: SubdomainEnumPlugin, mock_session: AsyncMock) -> None:
        """
        Test plugin cleanup.
        
        This test verifies that the plugin:
        1. Closes HTTP session properly
        2. Cleans up resources
        3. Handles cleanup gracefully
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        await plugin.cleanup()
        
        # Verify session was closed
        mock_session.close.assert_called_once()

class TestDNSEnumeration(TestSubdomainEnumPlugin):
    """Tests for DNS enumeration functionality."""
    
    @pytest.mark.asyncio
    async def test_dns_enumeration(self, plugin: SubdomainEnumPlugin, mock_dns_resolver: MagicMock) -> None:
        """
        Test DNS enumeration functionality.
        
        This test verifies that the plugin:
        1. Queries various DNS record types
        2. Resolves subdomains correctly
        3. Handles DNS responses properly
        4. Returns unique subdomains
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
        # Run DNS enumeration
        subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) > 0
        assert "www.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert "ns1.example.com" in subdomains
    
    @pytest.mark.asyncio
    async def test_reverse_dns(self, plugin: SubdomainEnumPlugin, mock_dns_resolver: MagicMock) -> None:
        """
        Test reverse DNS lookup functionality.
        
        This test verifies that the plugin:
        1. Performs reverse DNS lookups
        2. Maps IPs to domains correctly
        3. Handles PTR records properly
        4. Returns valid subdomains
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
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

class TestCertificateTransparency(TestSubdomainEnumPlugin):
    """Tests for certificate transparency functionality."""
    
    @pytest.mark.asyncio
    async def test_certificate_transparency(
        self,
        plugin: SubdomainEnumPlugin,
        mock_session: AsyncMock,
        mock_env_vars: AsyncGenerator[None, None]
    ) -> None:
        """
        Test certificate transparency check functionality.
        
        This test verifies that the plugin:
        1. Queries certificate transparency logs
        2. Extracts subdomains from certificates
        3. Handles API responses properly
        4. Returns unique subdomains
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_env_vars: Mocked environment variables
        """
        # Mock API response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=MOCK_CERTSPOTTER_RESPONSE)
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run certificate transparency check
        subdomains = await plugin._certificate_transparency(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) == 5  # Total unique subdomains from mock response
        assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert "mail.example.com" in subdomains

class TestWebArchives(TestSubdomainEnumPlugin):
    """Tests for web archives functionality."""
    
    @pytest.mark.asyncio
    async def test_web_archives(
        self,
        plugin: SubdomainEnumPlugin,
        mock_session: AsyncMock,
        mock_env_vars: AsyncGenerator[None, None]
    ) -> None:
        """
        Test web archives search functionality.
        
        This test verifies that the plugin:
        1. Queries web archives
        2. Extracts subdomains from historical data
        3. Handles API responses properly
        4. Returns unique subdomains
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_env_vars: Mocked environment variables
        """
        # Mock API response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=MOCK_WAYBACK_RESPONSE)
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run web archives search
        subdomains = await plugin._web_archives(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) == 3
        assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert "dev.example.com" in subdomains

class TestBruteforce(TestSubdomainEnumPlugin):
    """Tests for bruteforce functionality."""
    
    @pytest.mark.asyncio
    async def test_subdomain_bruteforce(
        self,
        plugin: SubdomainEnumPlugin,
        mock_dns_resolver: MagicMock,
        mock_wordlist: str
    ) -> None:
        """
        Test subdomain bruteforcing functionality.
        
        This test verifies that the plugin:
        1. Uses wordlist for bruteforcing
        2. Performs DNS queries efficiently
        3. Handles DNS responses properly
        4. Returns valid subdomains
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
            mock_wordlist: Path to wordlist file
        """
        # Configure plugin with test wordlist
        plugin.wordlist_path = mock_wordlist
        await plugin.initialize()
        
        # Run subdomain bruteforce
        subdomains = await plugin._subdomain_bruteforce(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) > 0
        assert all(subdomain.endswith(TEST_DOMAIN) for subdomain in subdomains)

class TestErrorHandling(TestSubdomainEnumPlugin):
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_error_handling(
        self,
        plugin: SubdomainEnumPlugin,
        mock_dns_resolver: MagicMock
    ) -> None:
        """
        Test plugin error handling.
        
        This test verifies that the plugin:
        1. Handles DNS errors gracefully
        2. Returns empty results on failure
        3. Continues execution after errors
        4. Maintains stability during failures
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
        # Mock DNS resolver to raise an exception
        mock_dns_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        
        # Run DNS enumeration
        subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
        
        # Verify empty result on error
        assert len(subdomains) == 0

class TestAPIIntegration(TestSubdomainEnumPlugin):
    """Tests for API integration functionality."""
    
    @pytest.mark.asyncio
    async def test_execute_without_api_keys(
        self,
        plugin: SubdomainEnumPlugin,
        mock_session: AsyncMock,
        mock_dns_resolver: MagicMock,
        mock_wordlist: str
    ) -> None:
        """
        Test plugin execution without API keys.
        
        This test verifies that the plugin:
        1. Works without API keys
        2. Falls back to DNS-based discovery
        3. Maintains functionality
        4. Returns valid results
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_dns_resolver: Mocked DNS resolver
            mock_wordlist: Path to wordlist file
        """
        # Configure plugin
        plugin.wordlist_path = mock_wordlist
        await plugin.initialize()
        
        # Clear API keys
        plugin.api_keys = {}
        
        # Run plugin execution
        results = await plugin.execute(TEST_DOMAIN)
        
        # Verify results still include DNS-based findings
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(hasattr(r, 'subdomain') for r in results)
        assert all(r.subdomain.endswith(TEST_DOMAIN) for r in results)

class TestPluginExecution(TestSubdomainEnumPlugin):
    """Tests for complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_plugin_execution(
        self,
        plugin: SubdomainEnumPlugin,
        mock_dns_resolver: MagicMock,
        mock_session: AsyncMock,
        mock_wordlist: str,
        mock_env_vars: AsyncGenerator[None, None]
    ) -> None:
        """
        Test complete plugin execution.
        
        This test verifies that the plugin:
        1. Executes all discovery methods
        2. Combines results from different sources
        3. Handles API responses properly
        4. Returns comprehensive findings
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
            mock_session: Mocked HTTP session
            mock_wordlist: Path to wordlist file
            mock_env_vars: Mocked environment variables
        """
        # Configure plugin
        plugin.wordlist_path = mock_wordlist
        await plugin.initialize()
        
        # Mock API responses
        mock_cert_response = AsyncMock()
        mock_cert_response.status = 200
        mock_cert_response.json = AsyncMock(return_value=MOCK_CERTSPOTTER_RESPONSE)
        
        mock_wayback_response = AsyncMock()
        mock_wayback_response.status = 200
        mock_wayback_response.json = AsyncMock(return_value=MOCK_WAYBACK_RESPONSE)
        
        mock_session.get.side_effect = [mock_cert_response, mock_wayback_response]
        
        # Run plugin execution
        results = await plugin.execute(TEST_DOMAIN)
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(hasattr(r, 'subdomain') for r in results)
        assert all(r.subdomain.endswith(TEST_DOMAIN) for r in results)

class TestPerformance(TestSubdomainEnumPlugin):
    """Tests for performance and concurrency functionality."""
    
    @pytest.mark.asyncio
    async def test_concurrent_dns_queries(
        self,
        plugin: SubdomainEnumPlugin,
        mock_dns_resolver: MagicMock
    ) -> None:
        """
        Test concurrent DNS query performance.
        
        This test verifies that the plugin:
        1. Handles concurrent DNS queries efficiently
        2. Respects connection limits
        3. Maintains stability under load
        4. Processes all queries correctly
        
        Args:
            plugin: Plugin instance
            mock_dns_resolver: Mocked DNS resolver
        """
        # Configure plugin for high concurrency
        plugin._concurrent_connections = TEST_CONCURRENT_CONNECTIONS
        await plugin.initialize()
        
        # Run DNS enumeration with many subdomains
        subdomains = await plugin._dns_enumeration(TEST_DOMAIN)
        
        # Verify results
        assert len(subdomains) > 0
        assert all(domain.endswith(TEST_DOMAIN) for domain in subdomains)
        
        # Verify DNS resolver was called efficiently
        assert mock_dns_resolver.resolve.call_count > 0
        assert mock_dns_resolver.resolve.call_count <= len(TEST_SUBDOMAINS) * len(MOCK_DNS_RESPONSES) 