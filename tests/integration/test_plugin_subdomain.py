"""
Integration tests for the Subdomain Enumeration Plugin.

This module contains comprehensive test cases for the Subdomain Enumeration Plugin,
verifying its functionality for discovering and validating subdomains through various techniques.

Test Categories:
- Basic Functionality: Core subdomain enumeration features
- Wordlist Enumeration: Subdomain discovery using wordlists
- Error Handling: Plugin behavior during failures
- Performance: Execution time and resource usage
- Concurrent Execution: Multi-target scanning
- Data Management: Finding updates and metadata handling

Each test category focuses on specific aspects of the plugin:
1. Basic Functionality: DNS queries and record validation
2. Wordlist Enumeration: Subdomain discovery using wordlists
3. Error Handling: DNS failures and error recovery
4. Performance: Execution time and resource usage
5. Concurrent Execution: Multi-target scanning efficiency
6. Data Management: Finding updates and metadata merging
"""

import pytest
from typing import Dict, Any, List, Optional
from unittest.mock import AsyncMock, patch

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin
from bbf.core.database.models import Finding, FindingStatus

# Test Configuration
TEST_DOMAIN = "example.com"
TEST_IP = "93.184.216.34"
TEST_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"
TEST_NAMESERVERS = ["ns1.example.com", "ns2.example.com"]
TEST_MAIL_SERVERS = ["mail.example.com"]
TEST_SUBDOMAIN = "test.example.com"
TEST_SUBDOMAIN_IP = "93.184.216.35"
TEST_SUBDOMAIN_IPV6 = "2606:2800:220:1:248:1893:25c8:1947"

# Test Data
TEST_WORDLIST = ["test", "dev", "staging", "prod"]
TEST_PERF_WORDLIST = [f"sub{i}" for i in range(100)]  # 100 subdomains
TEST_CONCURRENT_DOMAINS = [f"domain{i}.com" for i in range(5)]  # 5 domains

class TestSubdomainEnumPlugin(PluginIntegrationTest):
    """
    Test suite for Subdomain Enumeration Plugin integration.
    
    This class implements comprehensive tests for the Subdomain Enumeration Plugin,
    covering all aspects of its functionality from basic enumeration to advanced features.
    
    Attributes:
        plugin_name (str): Name of the plugin being tested
        dns_mock (AsyncMock): Mocked DNS resolver
    """
    
    @property
    def plugin_name(self) -> str:
        """
        Return the name of the plugin being tested.
        
        Returns:
            str: Plugin name
        """
        return "subdomain"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self) -> None:
        """
        Set up mock responses for DNS queries.
        
        This fixture initializes mock DNS responses for various test scenarios,
        including basic queries, wordlist enumeration, and error conditions.
        """
        super().setup_mocks()
        self.dns_mock.query.side_effect = self._mock_dns_query
    
    async def _mock_dns_query(self, qname: str, qtype: str) -> Dict[str, Any]:
        """
        Mock DNS query responses.
        
        Args:
            qname: Domain name to query
            qtype: DNS record type (A, AAAA, NS, MX)
        
        Returns:
            Dict[str, Any]: Mock DNS response
        """
        if qname == TEST_DOMAIN:
            if qtype == "A":
                return {"A": [TEST_IP]}
            elif qtype == "AAAA":
                return {"AAAA": [TEST_IPV6]}
            elif qtype == "NS":
                return {"NS": TEST_NAMESERVERS}
            elif qtype == "MX":
                return {"MX": TEST_MAIL_SERVERS}
        elif qname == TEST_SUBDOMAIN:
            if qtype == "A":
                return {"A": [TEST_SUBDOMAIN_IP]}
            elif qtype == "AAAA":
                return {"AAAA": [TEST_SUBDOMAIN_IPV6]}
        return {"A": [], "AAAA": [], "NS": [], "MX": []}

class TestBasicFunctionality(TestSubdomainEnumPlugin):
    """Tests for basic subdomain enumeration functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_subdomain_enumeration(self) -> None:
        """
        Test basic subdomain enumeration functionality.
        
        This test verifies that the plugin can:
        1. Discover subdomains through DNS queries
        2. Collect and validate DNS records
        3. Store findings with correct metadata
        """
        expected_findings = [
            {
                "subdomain": TEST_SUBDOMAIN,
                "source": "subdomain_enum",
                "confidence": 0.9,
                "metadata": {
                    "ip": TEST_SUBDOMAIN_IP,
                    "ipv6": TEST_SUBDOMAIN_IPV6,
                    "nameservers": TEST_NAMESERVERS,
                    "mail_servers": TEST_MAIL_SERVERS,
                    "techniques": ["dns_enum"]
                }
            }
        ]
        
        await self.assert_plugin_findings(TEST_DOMAIN, expected_findings)

class TestWordlistEnumeration(TestSubdomainEnumPlugin):
    """Tests for wordlist-based subdomain enumeration."""
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_with_wordlist(self) -> None:
        """
        Test subdomain enumeration with wordlist.
        
        This test verifies that the plugin can:
        1. Process a wordlist for subdomain discovery
        2. Handle multiple subdomains efficiently
        3. Store findings with appropriate metadata
        """
        # Mock DNS responses for wordlist subdomains
        async def mock_wordlist_query(qname: str, qtype: str) -> Dict[str, Any]:
            if qname in [f"{w}.{TEST_DOMAIN}" for w in TEST_WORDLIST]:
                return {"A": [TEST_IP]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_wordlist_query
        
        expected_findings = [
            {
                "subdomain": f"{subdomain}.{TEST_DOMAIN}",
                "source": "subdomain_enum",
                "confidence": 0.9,
                "metadata": {
                    "ip": TEST_IP,
                    "techniques": ["wordlist"]
                }
            }
            for subdomain in TEST_WORDLIST
        ]
        
        await self.assert_plugin_findings(TEST_DOMAIN, expected_findings)

class TestErrorHandling(TestSubdomainEnumPlugin):
    """Tests for error handling during subdomain enumeration."""
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_error_handling(self) -> None:
        """
        Test error handling during subdomain enumeration.
        
        This test verifies that the plugin:
        1. Handles DNS query failures gracefully
        2. Reports errors appropriately
        3. Maintains data integrity during failures
        """
        # Mock DNS query to raise an exception
        self.dns_mock.query.side_effect = Exception("DNS query failed")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(TEST_DOMAIN)
        assert results["status"] == "error"
        assert "error" in results
        assert "DNS query failed" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(
            TEST_DOMAIN,
            source="subdomain_enum",
            expected_count=0
        )

class TestPerformance(TestSubdomainEnumPlugin):
    """Tests for subdomain enumeration performance."""
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_performance(self) -> None:
        """
        Test subdomain enumeration performance.
        
        This test verifies that the plugin:
        1. Handles large wordlists efficiently
        2. Completes within acceptable time limits
        3. Maintains performance under load
        """
        # Mock DNS responses for performance testing
        async def mock_perf_query(qname: str, qtype: str) -> Dict[str, Any]:
            if qname in [f"{w}.{TEST_DOMAIN}" for w in TEST_PERF_WORDLIST]:
                return {"A": [TEST_IP]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_perf_query
        
        # Test performance with 100 subdomains
        await self.assert_performance(
            self.execute_plugin,
            TEST_DOMAIN,
            max_time=5.0  # Should complete within 5 seconds
        )
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_concurrent(self) -> None:
        """
        Test concurrent subdomain enumeration.
        
        This test verifies that the plugin:
        1. Handles multiple targets efficiently
        2. Respects concurrency limits
        3. Maintains performance under concurrent load
        """
        # Mock DNS responses for concurrent testing
        async def mock_concurrent_query(qname: str, qtype: str) -> Dict[str, Any]:
            domain = qname.split(".")[-2]
            if domain in [t.split(".")[0] for t in TEST_CONCURRENT_DOMAINS]:
                return {"A": [TEST_IP]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_concurrent_query
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in TEST_CONCURRENT_DOMAINS],
            max_time=10.0,  # Should complete within 10 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )

class TestDataManagement(TestSubdomainEnumPlugin):
    """Tests for finding updates and metadata management."""
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_metadata_merging(self) -> None:
        """
        Test metadata merging for subdomain findings.
        
        This test verifies that the plugin:
        1. Updates findings with new information
        2. Preserves existing metadata
        3. Merges techniques correctly
        4. Maintains data integrity during updates
        """
        # First scan
        await self.execute_plugin(TEST_DOMAIN)
        finding = await self.assert_finding_exists(
            TEST_DOMAIN,
            TEST_SUBDOMAIN,
            "subdomain_enum"
        )
        
        # Update with new metadata
        new_metadata = {
            "ip": "93.184.216.36",  # New IP
            "techniques": ["dns_enum", "certificate"]  # Additional technique
        }
        
        # Second scan with new metadata
        self.dns_mock.query.side_effect = lambda qname, qtype: {
            "A": ["93.184.216.36"] if qtype == "A" else []
        }
        
        await self.execute_plugin(TEST_DOMAIN)
        updated = await self.assert_finding_exists(
            TEST_DOMAIN,
            TEST_SUBDOMAIN,
            "subdomain_enum"
        )
        
        # Verify metadata merging
        assert updated.metadata["ip"] == "93.184.216.36"  # New value
        assert "certificate" in updated.metadata["techniques"]  # Additional technique
        assert "dns_enum" in updated.metadata["techniques"]  # Preserved technique
        assert "nameservers" in updated.metadata  # Preserved metadata
        assert "mail_servers" in updated.metadata  # Preserved metadata 