"""Base test classes for integration testing."""

import asyncio
import pytest
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.core.session import Session
from bbf.plugins.base import BasePlugin

class BaseIntegrationTest:
    """Base class for all integration tests."""
    
    @pytest.fixture(autouse=True)
    def setup(self, test_session: Session, mock_finding_service: Any):
        """Set up test environment."""
        self.session = test_session
        self.finding_service = mock_finding_service
        self.setup_mocks()
    
    def setup_mocks(self):
        """Set up mock objects for testing."""
        self.http_mock = AsyncMock()
        self.dns_mock = AsyncMock()
        self.rate_limit_mock = AsyncMock()
        
        # Patch common external dependencies
        self.patches = [
            patch("aiohttp.ClientSession", return_value=self.http_mock),
            patch("aiodns.DNSResolver", return_value=self.dns_mock),
            patch("bbf.core.rate_limit.RateLimiter", return_value=self.rate_limit_mock)
        ]
        
        for p in self.patches:
            p.start()
    
    def teardown_method(self, method):
        """Clean up after each test method."""
        for p in self.patches:
            p.stop()
    
    async def assert_finding_exists(
        self,
        root_domain: str,
        subdomain: str,
        source: str,
        **kwargs
    ) -> Finding:
        """Assert that a finding exists in the database."""
        finding = await self.finding_service.get_finding(
            root_domain=root_domain,
            subdomain=subdomain,
            source=source
        )
        assert finding is not None, f"Finding not found: {root_domain}/{subdomain}/{source}"
        
        for key, value in kwargs.items():
            assert getattr(finding, key) == value, \
                f"Finding {key} mismatch: expected {value}, got {getattr(finding, key)}"
        
        return finding
    
    async def assert_findings_count(
        self,
        root_domain: str,
        source: Optional[str] = None,
        expected_count: int = 1
    ):
        """Assert the number of findings for a domain and source."""
        findings = await self.finding_service.get_findings(
            root_domain=root_domain,
            source=source
        )
        assert len(findings) == expected_count, \
            f"Expected {expected_count} findings, got {len(findings)}"
    
    async def assert_metadata_contains(
        self,
        finding: Finding,
        key: str,
        value: Any
    ):
        """Assert that finding metadata contains a key-value pair."""
        assert finding.metadata is not None, "Finding metadata is None"
        assert key in finding.metadata, f"Metadata key {key} not found"
        assert finding.metadata[key] == value, \
            f"Metadata value mismatch for {key}: expected {value}, got {finding.metadata[key]}"

class PluginIntegrationTest(BaseIntegrationTest):
    """Base class for plugin integration tests."""
    
    @pytest.fixture(autouse=True)
    def setup_plugin(self, plugins: Dict[str, BasePlugin]):
        """Set up plugin for testing."""
        self.plugin = plugins[self.plugin_name]
    
    @property
    def plugin_name(self) -> str:
        """Return the name of the plugin being tested."""
        raise NotImplementedError("Subclasses must implement plugin_name")
    
    async def execute_plugin(
        self,
        target: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute the plugin and return results."""
        return await self.plugin.execute(target, **kwargs)
    
    async def assert_plugin_findings(
        self,
        target: str,
        expected_findings: List[Dict[str, Any]]
    ):
        """Assert that plugin execution created expected findings."""
        await self.execute_plugin(target)
        
        for finding_data in expected_findings:
            await self.assert_finding_exists(
                root_domain=target,
                **finding_data
            )

class StageIntegrationTest(BaseIntegrationTest):
    """Base class for stage integration tests."""
    
    @pytest.fixture(autouse=True)
    def setup_stage(self, plugins: Dict[str, BasePlugin]):
        """Set up stage and plugins for testing."""
        self.plugins = plugins
    
    async def execute_stage(
        self,
        target: str,
        plugin_order: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute stage with plugins in specified order."""
        if plugin_order is None:
            plugin_order = list(self.plugins.keys())
        
        results = {}
        for plugin_name in plugin_order:
            plugin = self.plugins[plugin_name]
            results[plugin_name] = await plugin.execute(target, **kwargs)
        
        return results
    
    async def assert_stage_findings(
        self,
        target: str,
        expected_findings: Dict[str, List[Dict[str, Any]]]
    ):
        """Assert that stage execution created expected findings for each plugin."""
        await self.execute_stage(target)
        
        for plugin_name, findings in expected_findings.items():
            for finding_data in findings:
                await self.assert_finding_exists(
                    root_domain=target,
                    source=plugin_name,
                    **finding_data
                )

class DatabaseIntegrationTest(BaseIntegrationTest):
    """Base class for database integration tests."""
    
    async def create_test_finding(
        self,
        root_domain: str,
        subdomain: str,
        source: str,
        **kwargs
    ) -> Finding:
        """Create a test finding in the database."""
        finding_data = {
            "root_domain": root_domain,
            "subdomain": subdomain,
            "source": source,
            "confidence": 0.9,
            "stage": "recon",
            "status": "active",
            **kwargs
        }
        
        return await self.finding_service.add_or_update_finding(**finding_data)
    
    async def assert_finding_preserved(
        self,
        finding: Finding,
        update_data: Dict[str, Any]
    ):
        """Assert that finding data is preserved during updates."""
        original_data = {
            "root_domain": finding.root_domain,
            "subdomain": finding.subdomain,
            "source": finding.source,
            "confidence": finding.confidence,
            "metadata": finding.metadata.copy() if finding.metadata else None
        }
        
        await self.finding_service.add_or_update_finding(
            **{**original_data, **update_data}
        )
        
        updated = await self.finding_service.get_finding(
            root_domain=finding.root_domain,
            subdomain=finding.subdomain,
            source=finding.source
        )
        
        assert updated is not None
        assert updated.root_domain == original_data["root_domain"]
        assert updated.subdomain == original_data["subdomain"]
        assert updated.source == original_data["source"]
        assert updated.confidence == original_data["confidence"]
        
        if original_data["metadata"]:
            for key, value in original_data["metadata"].items():
                assert key in updated.metadata
                assert updated.metadata[key] == value

class PerformanceTest(BaseIntegrationTest):
    """Base class for performance tests."""
    
    async def measure_execution_time(
        self,
        coro,
        *args,
        **kwargs
    ) -> float:
        """Measure execution time of a coroutine."""
        start = asyncio.get_event_loop().time()
        await coro(*args, **kwargs)
        end = asyncio.get_event_loop().time()
        return end - start
    
    async def assert_performance(
        self,
        coro,
        *args,
        max_time: float,
        **kwargs
    ):
        """Assert that coroutine execution time is within limits."""
        execution_time = await self.measure_execution_time(coro, *args, **kwargs)
        assert execution_time <= max_time, \
            f"Execution time {execution_time:.2f}s exceeded limit {max_time:.2f}s"
    
    async def measure_concurrent_performance(
        self,
        coro,
        args_list: List[tuple],
        max_time: float,
        max_concurrent: int = 10
    ):
        """Measure performance of concurrent coroutine execution."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_coro(*args):
            async with semaphore:
                return await coro(*args)
        
        start = asyncio.get_event_loop().time()
        await asyncio.gather(*(bounded_coro(*args) for args in args_list))
        end = asyncio.get_event_loop().time()
        
        execution_time = end - start
        assert execution_time <= max_time, \
            f"Concurrent execution time {execution_time:.2f}s exceeded limit {max_time:.2f}s" 