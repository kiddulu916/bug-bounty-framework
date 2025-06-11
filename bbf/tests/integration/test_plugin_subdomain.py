"""Integration tests for the Subdomain Enumeration Plugin."""

import pytest
from typing import Dict, Any
from unittest.mock import AsyncMock

from bbf.tests.integration import PluginIntegrationTest
from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin

class TestSubdomainEnumPlugin(PluginIntegrationTest):
    """Test suite for Subdomain Enumeration Plugin integration."""
    
    @property
    def plugin_name(self) -> str:
        return "subdomain"
    
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Set up mock responses for DNS queries."""
        super().setup_mocks()
        
        # Mock DNS responses
        self.dns_mock.query.side_effect = self._mock_dns_query
    
    async def _mock_dns_query(self, qname: str, qtype: str) -> Dict[str, Any]:
        """Mock DNS query responses."""
        if qname == "example.com":
            if qtype == "A":
                return {"A": ["93.184.216.34"]}
            elif qtype == "AAAA":
                return {"AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]}
            elif qtype == "NS":
                return {"NS": ["ns1.example.com", "ns2.example.com"]}
            elif qtype == "MX":
                return {"MX": ["mail.example.com"]}
        elif qname == "test.example.com":
            if qtype == "A":
                return {"A": ["93.184.216.35"]}
            elif qtype == "AAAA":
                return {"AAAA": ["2606:2800:220:1:248:1893:25c8:1947"]}
        return {"A": [], "AAAA": [], "NS": [], "MX": []}
    
    @pytest.mark.asyncio
    async def test_basic_subdomain_enumeration(self):
        """Test basic subdomain enumeration functionality."""
        target = "example.com"
        expected_findings = [
            {
                "subdomain": "test.example.com",
                "source": "subdomain_enum",
                "confidence": 0.9,
                "metadata": {
                    "ip": "93.184.216.35",
                    "ipv6": "2606:2800:220:1:248:1893:25c8:1947",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "mail_servers": ["mail.example.com"],
                    "techniques": ["dns_enum"]
                }
            }
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_with_wordlist(self):
        """Test subdomain enumeration with wordlist."""
        target = "example.com"
        wordlist = ["test", "dev", "staging", "prod"]
        
        # Mock DNS responses for wordlist subdomains
        async def mock_wordlist_query(qname: str, qtype: str) -> Dict[str, Any]:
            if qname in [f"{w}.example.com" for w in wordlist]:
                return {"A": ["93.184.216.34"]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_wordlist_query
        
        expected_findings = [
            {
                "subdomain": f"{subdomain}.example.com",
                "source": "subdomain_enum",
                "confidence": 0.9,
                "metadata": {
                    "ip": "93.184.216.34",
                    "techniques": ["wordlist"]
                }
            }
            for subdomain in wordlist
        ]
        
        await self.assert_plugin_findings(target, expected_findings)
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_error_handling(self):
        """Test error handling during subdomain enumeration."""
        target = "example.com"
        
        # Mock DNS query to raise an exception
        self.dns_mock.query.side_effect = Exception("DNS query failed")
        
        # Plugin should handle the error and return empty results
        results = await self.execute_plugin(target)
        assert results["status"] == "error"
        assert "error" in results
        assert "DNS query failed" in str(results["error"])
        
        # No findings should be stored
        await self.assert_findings_count(target, source="subdomain_enum", expected_count=0)
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_performance(self):
        """Test subdomain enumeration performance."""
        target = "example.com"
        wordlist = [f"sub{i}" for i in range(100)]  # 100 subdomains
        
        # Mock DNS responses for performance testing
        async def mock_perf_query(qname: str, qtype: str) -> Dict[str, Any]:
            if qname in [f"{w}.example.com" for w in wordlist]:
                return {"A": ["93.184.216.34"]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_perf_query
        
        # Test performance with 100 subdomains
        await self.assert_performance(
            self.execute_plugin,
            target,
            max_time=5.0  # Should complete within 5 seconds
        )
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_concurrent(self):
        """Test concurrent subdomain enumeration."""
        targets = [f"domain{i}.com" for i in range(5)]  # 5 domains
        
        # Mock DNS responses for concurrent testing
        async def mock_concurrent_query(qname: str, qtype: str) -> Dict[str, Any]:
            domain = qname.split(".")[-2]
            if domain in [t.split(".")[0] for t in targets]:
                return {"A": ["93.184.216.34"]}
            return await self._mock_dns_query(qname, qtype)
        
        self.dns_mock.query.side_effect = mock_concurrent_query
        
        # Test concurrent execution
        await self.measure_concurrent_performance(
            self.execute_plugin,
            [(target,) for target in targets],
            max_time=10.0,  # Should complete within 10 seconds
            max_concurrent=3  # Maximum 3 concurrent scans
        )
    
    @pytest.mark.asyncio
    async def test_subdomain_enumeration_metadata_merging(self):
        """Test metadata merging for subdomain findings."""
        target = "example.com"
        
        # First scan
        await self.execute_plugin(target)
        finding = await self.assert_finding_exists(
            target,
            "test.example.com",
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
        
        await self.execute_plugin(target)
        updated = await self.assert_finding_exists(
            target,
            "test.example.com",
            "subdomain_enum"
        )
        
        # Verify metadata merging
        assert updated.metadata["ip"] == "93.184.216.36"  # New value
        assert "certificate" in updated.metadata["techniques"]  # Additional technique
        assert "dns_enum" in updated.metadata["techniques"]  # Preserved technique
        assert "nameservers" in updated.metadata  # Preserved metadata
        assert "mail_servers" in updated.metadata  # Preserved metadata 