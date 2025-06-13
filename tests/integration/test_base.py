"""
Base test classes for integration testing.

This module provides base classes and utilities for integration testing across the framework.
Tests are organized into categories: basic integration, plugin integration, stage integration,
database integration, and performance testing.

Test Categories:
- Basic Integration: Core integration test functionality and common utilities
- Plugin Integration: Plugin-specific test functionality and assertions
- Stage Integration: Stage execution and multi-plugin testing
- Database Integration: Database operations and data persistence
- Performance Testing: Execution time and resource usage testing

Each test category focuses on specific aspects of integration testing:
1. Basic Integration: Common setup, teardown, and assertion utilities
2. Plugin Integration: Plugin execution and finding validation
3. Stage Integration: Multi-plugin execution and stage management
4. Database Integration: Data persistence and integrity
5. Performance Testing: Resource usage and execution time validation
"""

import asyncio
import pytest
from typing import Any, Dict, List, Optional, Type, TypeVar
from unittest.mock import AsyncMock, MagicMock, patch

from bbf.core.database.models import Finding, FindingStatus
from bbf.core.database.service import finding_service
from bbf.core.session import Session
from bbf.plugins.base import BasePlugin

# Type Variables
T = TypeVar('T', bound='BaseIntegrationTest')

# Test Configuration
DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_CONCURRENT_TASKS = 10
DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_DELAY = 1.0  # seconds

class BaseIntegrationTest:
    """
    Base class for all integration tests.
    
    This class provides common functionality for integration testing:
    - Test environment setup and teardown
    - Mock management for external dependencies
    - Common assertion utilities
    - Resource cleanup
    
    Attributes:
        session (Session): Test session instance
        finding_service (Any): Mocked finding service
        http_mock (AsyncMock): Mocked HTTP client
        dns_mock (AsyncMock): Mocked DNS resolver
        rate_limit_mock (AsyncMock): Mocked rate limiter
    """
    
    @pytest.fixture(autouse=True)
    def setup(self, test_session: Session, mock_finding_service: Any) -> None:
        """
        Set up test environment.
        
        Args:
            test_session: Test database session
            mock_finding_service: Mocked finding service instance
        """
        self.session = test_session
        self.finding_service = mock_finding_service
        self.setup_mocks()
    
    def setup_mocks(self) -> None:
        """
        Set up mock objects for testing.
        
        This method initializes and patches common external dependencies:
        - HTTP client (aiohttp.ClientSession)
        - DNS resolver (aiodns.DNSResolver)
        - Rate limiter (bbf.core.rate_limit.RateLimiter)
        """
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
    
    def teardown_method(self, method: Any) -> None:
        """
        Clean up after each test method.
        
        Args:
            method: The test method that was executed
        """
        for p in self.patches:
            p.stop()
    
    async def assert_finding_exists(
        self,
        root_domain: str,
        subdomain: str,
        source: str,
        **kwargs: Any
    ) -> Finding:
        """
        Assert that a finding exists in the database.
        
        Args:
            root_domain: Root domain of the finding
            subdomain: Subdomain of the finding
            source: Source plugin of the finding
            **kwargs: Additional finding attributes to verify
        
        Returns:
            Finding: The found finding instance
        
        Raises:
            AssertionError: If finding doesn't exist or attributes don't match
        """
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
    ) -> None:
        """
        Assert the number of findings for a domain and source.
        
        Args:
            root_domain: Root domain to check
            source: Optional source plugin to filter by
            expected_count: Expected number of findings
        
        Raises:
            AssertionError: If finding count doesn't match expected
        """
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
    ) -> None:
        """
        Assert that finding metadata contains a key-value pair.
        
        Args:
            finding: Finding to check
            key: Metadata key to verify
            value: Expected metadata value
        
        Raises:
            AssertionError: If metadata doesn't contain key or value doesn't match
        """
        assert finding.metadata is not None, "Finding metadata is None"
        assert key in finding.metadata, f"Metadata key {key} not found"
        assert finding.metadata[key] == value, \
            f"Metadata value mismatch for {key}: expected {value}, got {finding.metadata[key]}"

class PluginIntegrationTest(BaseIntegrationTest):
    """
    Base class for plugin integration tests.
    
    This class provides functionality for testing individual plugins:
    - Plugin setup and configuration
    - Plugin execution and result validation
    - Finding creation and verification
    
    Attributes:
        plugin (BasePlugin): The plugin instance being tested
    """
    
    @pytest.fixture(autouse=True)
    def setup_plugin(self, plugins: Dict[str, BasePlugin]) -> None:
        """
        Set up plugin for testing.
        
        Args:
            plugins: Dictionary of available plugins
        """
        self.plugin = plugins[self.plugin_name]
    
    @property
    def plugin_name(self) -> str:
        """
        Return the name of the plugin being tested.
        
        Returns:
            str: Plugin name
        
        Raises:
            NotImplementedError: If not implemented by subclass
        """
        raise NotImplementedError("Subclasses must implement plugin_name")
    
    async def execute_plugin(
        self,
        target: str,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Execute the plugin and return results.
        
        Args:
            target: Target to scan
            **kwargs: Additional plugin execution parameters
        
        Returns:
            Dict[str, Any]: Plugin execution results
        """
        return await self.plugin.execute(target, **kwargs)
    
    async def assert_plugin_findings(
        self,
        target: str,
        expected_findings: List[Dict[str, Any]]
    ) -> None:
        """
        Assert that plugin execution created expected findings.
        
        Args:
            target: Target that was scanned
            expected_findings: List of expected finding data
        
        Raises:
            AssertionError: If findings don't match expectations
        """
        await self.execute_plugin(target)
        
        for finding_data in expected_findings:
            await self.assert_finding_exists(
                root_domain=target,
                **finding_data
            )

class StageIntegrationTest(BaseIntegrationTest):
    """
    Base class for stage integration tests.
    
    This class provides functionality for testing stages with multiple plugins:
    - Stage setup and plugin management
    - Multi-plugin execution
    - Stage-level finding validation
    
    Attributes:
        plugins (Dict[str, BasePlugin]): Dictionary of available plugins
    """
    
    @pytest.fixture(autouse=True)
    def setup_stage(self, plugins: Dict[str, BasePlugin]) -> None:
        """
        Set up stage and plugins for testing.
        
        Args:
            plugins: Dictionary of available plugins
        """
        self.plugins = plugins
    
    async def execute_stage(
        self,
        target: str,
        plugin_order: Optional[List[str]] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Execute stage with plugins in specified order.
        
        Args:
            target: Target to scan
            plugin_order: Optional list of plugin names in execution order
            **kwargs: Additional execution parameters
        
        Returns:
            Dict[str, Any]: Results from each plugin execution
        """
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
    ) -> None:
        """
        Assert that stage execution created expected findings for each plugin.
        
        Args:
            target: Target that was scanned
            expected_findings: Dictionary mapping plugin names to expected findings
        
        Raises:
            AssertionError: If findings don't match expectations
        """
        await self.execute_stage(target)
        
        for plugin_name, findings in expected_findings.items():
            for finding_data in findings:
                await self.assert_finding_exists(
                    root_domain=target,
                    source=plugin_name,
                    **finding_data
                )

class DatabaseIntegrationTest(BaseIntegrationTest):
    """
    Base class for database integration tests.
    
    This class provides functionality for testing database operations:
    - Finding creation and updates
    - Data persistence verification
    - Database constraint validation
    
    Attributes:
        session (Session): Database session for testing
    """
    
    async def create_test_finding(
        self,
        root_domain: str,
        subdomain: str,
        source: str,
        **kwargs: Any
    ) -> Finding:
        """
        Create a test finding in the database.
        
        Args:
            root_domain: Root domain for the finding
            subdomain: Subdomain for the finding
            source: Source plugin for the finding
            **kwargs: Additional finding attributes
        
        Returns:
            Finding: Created finding instance
        """
        finding_data = {
            "root_domain": root_domain,
            "subdomain": subdomain,
            "source": source,
            "confidence": 0.9,
            "stage": "recon",
            "status": FindingStatus.ACTIVE,
            **kwargs
        }
        
        return await self.finding_service.add_or_update_finding(**finding_data)
    
    async def assert_finding_preserved(
        self,
        finding: Finding,
        update_data: Dict[str, Any]
    ) -> None:
        """
        Assert that finding data is preserved during updates.
        
        Args:
            finding: Finding to update
            update_data: Data to update finding with
        
        Raises:
            AssertionError: If finding data is not preserved correctly
        """
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
    """
    Base class for performance tests.
    
    This class provides functionality for testing performance:
    - Execution time measurement
    - Concurrent execution testing
    - Resource usage validation
    
    Attributes:
        default_timeout (float): Default timeout for performance tests
        default_concurrent_tasks (int): Default number of concurrent tasks
    """
    
    def __init__(self) -> None:
        """Initialize performance test settings."""
        self.default_timeout = DEFAULT_TIMEOUT
        self.default_concurrent_tasks = DEFAULT_CONCURRENT_TASKS
    
    async def measure_execution_time(
        self,
        coro: Any,
        *args: Any,
        **kwargs: Any
    ) -> float:
        """
        Measure execution time of a coroutine.
        
        Args:
            coro: Coroutine to measure
            *args: Positional arguments for coroutine
            **kwargs: Keyword arguments for coroutine
        
        Returns:
            float: Execution time in seconds
        """
        start = asyncio.get_event_loop().time()
        await coro(*args, **kwargs)
        end = asyncio.get_event_loop().time()
        return end - start
    
    async def assert_performance(
        self,
        coro: Any,
        *args: Any,
        max_time: float,
        **kwargs: Any
    ) -> None:
        """
        Assert that coroutine execution time is within limits.
        
        Args:
            coro: Coroutine to test
            *args: Positional arguments for coroutine
            max_time: Maximum allowed execution time
            **kwargs: Keyword arguments for coroutine
        
        Raises:
            AssertionError: If execution time exceeds limit
        """
        execution_time = await self.measure_execution_time(coro, *args, **kwargs)
        assert execution_time <= max_time, \
            f"Execution time {execution_time:.2f}s exceeded limit {max_time:.2f}s"
    
    async def measure_concurrent_performance(
        self,
        coro: Any,
        args_list: List[tuple],
        max_time: float,
        max_concurrent: int = DEFAULT_CONCURRENT_TASKS
    ) -> float:
        """
        Measure performance of concurrent coroutine execution.
        
        Args:
            coro: Coroutine to execute
            args_list: List of argument tuples for each execution
            max_time: Maximum allowed total execution time
            max_concurrent: Maximum number of concurrent executions
        
        Returns:
            float: Total execution time in seconds
        
        Raises:
            AssertionError: If execution time exceeds limit
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_coro(*args: Any) -> Any:
            async with semaphore:
                return await coro(*args)
        
        start = asyncio.get_event_loop().time()
        tasks = [bounded_coro(*args) for args in args_list]
        await asyncio.gather(*tasks)
        end = asyncio.get_event_loop().time()
        
        total_time = end - start
        assert total_time <= max_time, \
            f"Concurrent execution time {total_time:.2f}s exceeded limit {max_time:.2f}s"
        
        return total_time 