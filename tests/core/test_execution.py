"""
Tests for the execution engine module.

This module contains comprehensive test cases for the ExecutionEngine class,
verifying the orchestration of plugin execution, stage management, and
concurrent task handling. Tests are organized into categories: basic
functionality, error handling, performance, resource management, and
integration tests.

Test Categories:
- Basic Functionality: Engine initialization, plugin execution, stage management
- Error Handling: Timeouts, retries, error recovery
- Performance: Concurrent execution, scheduling, prioritization
- Resource Management: Resource monitoring, cleanup, state management
- Integration: Plugin dependencies, stage composition, lifecycle management
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio
import time
from datetime import datetime
from typing import List, Dict, Optional, Set

from bbf.core.execution import ExecutionEngine
from bbf.core.exceptions import ExecutionError, PluginError
from bbf.core.plugin import BasePlugin
from bbf.core.stage import BaseStage

# Test Configuration
TEST_CONFIG = {
    'max_concurrent_tasks': 5,
    'timeout': 30,
    'retry_count': 3,
    'retry_delay': 1
}

# Test Plugin Implementations
class TestPlugin(BasePlugin):
    """Base test plugin implementation."""
    
    def __init__(self, name: str, delay: float = 0, should_fail: bool = False):
        super().__init__()
        self.name = name
        self.delay = delay
        self.should_fail = should_fail
        self.execution_count = 0
    
    async def initialize(self):
        """Initialize the plugin."""
        await super().initialize()
        self._initialized = True
    
    async def execute(self, target: str) -> List[Dict]:
        """Execute the plugin with optional delay and failure simulation."""
        if not self._initialized:
            raise PluginError("Plugin not initialized")
        
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        
        self.execution_count += 1
        
        if self.should_fail:
            raise PluginError(f"Plugin {self.name} failed")
        
        return [{
            'type': 'test',
            'plugin': self.name,
            'target': target,
            'timestamp': datetime.now().isoformat()
        }]
    
    async def cleanup(self):
        """Clean up plugin resources."""
        await super().cleanup()
        self._initialized = False

class TestStage(BaseStage):
    """Test stage implementation."""
    
    def __init__(self, name: str, plugins: Optional[List[BasePlugin]] = None):
        super().__init__(name)
        self.plugins = plugins or []
    
    async def initialize(self):
        """Initialize the stage and its plugins."""
        await super().initialize()
        for plugin in self.plugins:
            await plugin.initialize()
    
    async def execute(self, target: str) -> List[Dict]:
        """Execute all plugins in the stage."""
        if not self._initialized:
            raise ExecutionError("Stage not initialized")
        
        results = []
        for plugin in self.plugins:
            try:
                plugin_results = await plugin.execute(target)
                results.extend(plugin_results)
            except PluginError as e:
                self.logger.error(f"Plugin {plugin.name} failed: {str(e)}")
        
        return results
    
    async def cleanup(self):
        """Clean up stage and plugin resources."""
        for plugin in self.plugins:
            await plugin.cleanup()
        await super().cleanup()

# Test Fixtures
@pytest.fixture
async def execution_engine():
    """
    Create and initialize an ExecutionEngine instance for testing.
    
    This fixture ensures proper setup and cleanup of the execution engine
    for each test case. It also verifies that the engine is properly
    initialized before use and cleaned up after use.
    """
    engine = ExecutionEngine(TEST_CONFIG)
    await engine.initialize()
    yield engine
    await engine.cleanup()

@pytest.fixture
async def test_plugins():
    """
    Create and initialize test plugins for testing.
    
    Returns a list of plugins with different behaviors:
    - plugin_1: Basic plugin
    - plugin_2: Plugin with delay
    - plugin_3: Plugin that fails
    - plugin_4: Plugin with longer delay
    """
    plugins = [
        TestPlugin('plugin_1'),
        TestPlugin('plugin_2', delay=0.1),
        TestPlugin('plugin_3', should_fail=True),
        TestPlugin('plugin_4', delay=0.2)
    ]
    for plugin in plugins:
        await plugin.initialize()
    yield plugins
    for plugin in plugins:
        await plugin.cleanup()

@pytest.fixture
async def test_stage(test_plugins):
    """
    Create and initialize a test stage with plugins.
    
    The stage is initialized with all test plugins and properly
    cleaned up after use.
    """
    stage = TestStage('test_stage', test_plugins)
    await stage.initialize()
    yield stage
    await stage.cleanup()

# Basic Functionality Tests
class TestBasicFunctionality:
    """Tests for basic execution engine functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, execution_engine):
        """Test execution engine initialization and configuration."""
        assert execution_engine._initialized
        assert execution_engine._running_tasks == set()
        assert execution_engine._task_results == {}
        assert execution_engine._max_concurrent_tasks == TEST_CONFIG['max_concurrent_tasks']
        assert execution_engine._timeout == TEST_CONFIG['timeout']
    
    @pytest.mark.asyncio
    async def test_plugin_execution(self, execution_engine, test_plugins):
        """Test individual plugin execution with various scenarios."""
        # Test successful plugin
        results = await execution_engine.execute_plugin(test_plugins[0], 'test_target')
        assert len(results) == 1
        assert results[0]['type'] == 'test'
        assert results[0]['plugin'] == 'plugin_1'
        
        # Test plugin with delay
        start_time = time.time()
        results = await execution_engine.execute_plugin(test_plugins[1], 'test_target')
        end_time = time.time()
        assert len(results) == 1
        assert end_time - start_time >= 0.1
        
        # Test failing plugin
        with pytest.raises(PluginError):
            await execution_engine.execute_plugin(test_plugins[2], 'test_target')
    
    @pytest.mark.asyncio
    async def test_stage_execution(self, execution_engine, test_stage):
        """Test stage execution with multiple plugins."""
        results = await execution_engine.execute_stage(test_stage, 'test_target')
        
        # Verify results
        assert len(results) == 3  # One plugin fails
        plugin_names = {r['plugin'] for r in results}
        assert plugin_names == {'plugin_1', 'plugin_2', 'plugin_4'}
        
        # Verify execution counts
        for plugin in test_stage.plugins:
            assert plugin.execution_count == 1

# Error Handling Tests
class TestErrorHandling:
    """Tests for error handling and recovery."""
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, execution_engine):
        """Test execution timeout handling."""
        plugin = TestPlugin('timeout_plugin', delay=TEST_CONFIG['timeout'] + 1)
        await plugin.initialize()
        
        with pytest.raises(ExecutionError) as exc_info:
            await execution_engine.execute_plugin(plugin, 'test_target')
        assert 'timeout' in str(exc_info.value).lower()
        
        await plugin.cleanup()
    
    @pytest.mark.asyncio
    async def test_retry_handling(self, execution_engine):
        """Test execution retry mechanism."""
        class RetryPlugin(TestPlugin):
            def __init__(self):
                super().__init__('retry_plugin')
                self.attempts = 0
            
            async def execute(self, target):
                self.attempts += 1
                if self.attempts < 3:
                    raise PluginError("Temporary failure")
                return await super().execute(target)
        
        plugin = RetryPlugin()
        await plugin.initialize()
        
        results = await execution_engine.execute_plugin(plugin, 'test_target')
        assert len(results) == 1
        assert plugin.attempts == 3
        
        await plugin.cleanup()
    
    @pytest.mark.asyncio
    async def test_error_recovery(self, execution_engine):
        """Test error recovery and state preservation."""
        class RecoverablePlugin(TestPlugin):
            def __init__(self):
                super().__init__('recoverable_plugin')
                self.state = 0
            
            async def execute(self, target):
                if self.state == 0:
                    self.state = 1
                    raise PluginError("Recoverable error")
                return await super().execute(target)
        
        plugin = RecoverablePlugin()
        await plugin.initialize()
        
        # First execution fails
        with pytest.raises(PluginError):
            await execution_engine.execute_plugin(plugin, 'test_target')
        
        # Second execution succeeds
        results = await execution_engine.execute_plugin(plugin, 'test_target')
        assert len(results) == 1
        assert plugin.state == 1
        
        await plugin.cleanup()

# Performance Tests
class TestPerformance:
    """Tests for execution performance and concurrency."""
    
    @pytest.mark.asyncio
    async def test_concurrent_execution(self, execution_engine, test_plugins):
        """Test concurrent plugin execution."""
        tasks = [
            execution_engine.execute_plugin(plugin, f'target_{i}')
            for i, plugin in enumerate(test_plugins)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == 3  # One plugin fails
        
        # Verify execution order
        timestamps = [
            datetime.fromisoformat(r[0]['timestamp'])
            for r in successful_results
        ]
        assert timestamps[0] < timestamps[1] < timestamps[2]
    
    @pytest.mark.asyncio
    async def test_execution_scheduling(self, execution_engine):
        """Test execution scheduling and prioritization."""
        class PrioritizedPlugin(TestPlugin):
            def __init__(self, name: str, priority: int = 0):
                super().__init__(name)
                self.priority = priority
            
            async def execute(self, target):
                await asyncio.sleep(0.1)  # Simulate work
                return await super().execute(target)
        
        plugins = [
            PrioritizedPlugin('high_priority', priority=2),
            PrioritizedPlugin('medium_priority', priority=1),
            PrioritizedPlugin('low_priority', priority=0)
        ]
        
        for plugin in plugins:
            await plugin.initialize()
        
        # Execute plugins concurrently
        tasks = [
            execution_engine.execute_plugin(plugin, 'test_target')
            for plugin in plugins
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify execution order based on priority
        timestamps = [
            datetime.fromisoformat(r[0]['timestamp'])
            for r in results
        ]
        assert timestamps[0] <= timestamps[1] <= timestamps[2]
        
        for plugin in plugins:
            await plugin.cleanup()

# Resource Management Tests
class TestResourceManagement:
    """Tests for resource management and monitoring."""
    
    @pytest.mark.asyncio
    async def test_resource_cleanup(self, execution_engine):
        """Test proper resource cleanup after execution."""
        class ResourceIntensivePlugin(TestPlugin):
            def __init__(self):
                super().__init__('resource_plugin')
                self.resources = set()
            
            async def execute(self, target):
                # Simulate resource acquisition
                self.resources.add('resource1')
                self.resources.add('resource2')
                return await super().execute(target)
            
            async def cleanup(self):
                # Verify resources are cleaned up
                assert len(self.resources) > 0
                self.resources.clear()
                await super().cleanup()
        
        plugin = ResourceIntensivePlugin()
        await plugin.initialize()
        
        await execution_engine.execute_plugin(plugin, 'test_target')
        await plugin.cleanup()
        
        assert len(plugin.resources) == 0
    
    @pytest.mark.asyncio
    async def test_resource_monitoring(self, execution_engine):
        """Test resource usage monitoring during execution."""
        class MonitoredPlugin(TestPlugin):
            async def execute(self, target):
                # Simulate resource usage
                start_memory = 100
                end_memory = 200
                execution_time = 0.1
                
                await asyncio.sleep(execution_time)
                return [{
                    'type': 'test',
                    'plugin': self.name,
                    'target': target,
                    'memory_usage': end_memory - start_memory,
                    'execution_time': execution_time
                }]
        
        plugin = MonitoredPlugin('monitored_plugin')
        await plugin.initialize()
        
        results = await execution_engine.execute_plugin(plugin, 'test_target')
        
        assert len(results) == 1
        assert 'memory_usage' in results[0]
        assert 'execution_time' in results[0]
        assert results[0]['execution_time'] >= 0.1
        
        await plugin.cleanup()

# Integration Tests
class TestIntegration:
    """Tests for integration with other components."""
    
    @pytest.mark.asyncio
    async def test_plugin_dependencies(self, execution_engine):
        """Test execution with plugin dependencies."""
        class DependentPlugin(TestPlugin):
            def __init__(self, name: str, dependencies: Optional[List[str]] = None):
                super().__init__(name)
                self.dependencies = dependencies or []
            
            async def execute(self, target):
                # Verify dependencies are executed first
                for dep in self.dependencies:
                    assert dep in self.execution_order
                self.execution_order.append(self.name)
                return await super().execute(target)
        
        # Create plugins with dependencies
        plugin_a = DependentPlugin('plugin_a')
        plugin_b = DependentPlugin('plugin_b', ['plugin_a'])
        plugin_c = DependentPlugin('plugin_c', ['plugin_a', 'plugin_b'])
        
        plugins = [plugin_a, plugin_b, plugin_c]
        for plugin in plugins:
            plugin.execution_order = []
            await plugin.initialize()
        
        # Execute plugins
        for plugin in plugins:
            await execution_engine.execute_plugin(plugin, 'test_target')
        
        # Verify execution order
        for plugin in plugins:
            assert plugin.name in plugin.execution_order
            for dep in plugin.dependencies:
                assert plugin.execution_order.index(dep) < plugin.execution_order.index(plugin.name)
        
        for plugin in plugins:
            await plugin.cleanup()
    
    @pytest.mark.asyncio
    async def test_stage_composition(self, execution_engine):
        """Test execution with composed stages."""
        # Create stages with different plugins
        stage1_plugins = [TestPlugin('stage1_plugin1'), TestPlugin('stage1_plugin2')]
        stage2_plugins = [TestPlugin('stage2_plugin1'), TestPlugin('stage2_plugin2')]
        
        stage1 = TestStage('stage1', stage1_plugins)
        stage2 = TestStage('stage2', stage2_plugins)
        
        await stage1.initialize()
        await stage2.initialize()
        
        # Execute stages in sequence
        results1 = await execution_engine.execute_stage(stage1, 'test_target')
        results2 = await execution_engine.execute_stage(stage2, 'test_target')
        
        # Verify results
        assert len(results1) == 2
        assert len(results2) == 2
        assert all(r['plugin'].startswith('stage1_') for r in results1)
        assert all(r['plugin'].startswith('stage2_') for r in results2)
        
        await stage1.cleanup()
        await stage2.cleanup()
    
    @pytest.mark.asyncio
    async def test_lifecycle_management(self, execution_engine, test_stage):
        """Test complete execution lifecycle."""
        # Initialize
        assert execution_engine._initialized
        assert test_stage._initialized
        for plugin in test_stage.plugins:
            assert plugin._initialized
        
        # Execute
        results = await execution_engine.execute_stage(test_stage, 'test_target')
        assert len(results) == 3
        
        # Verify plugin states
        for plugin in test_stage.plugins:
            assert plugin.execution_count == 1
        
        # Cleanup
        await test_stage.cleanup()
        assert not test_stage._initialized
        for plugin in test_stage.plugins:
            assert not plugin._initialized 