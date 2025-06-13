"""
Tests for the framework module.

This module contains test cases for the core framework functionality,
verifying the orchestration of stages, plugins, and execution flow.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime
import json

from bbf.core.framework import BugBountyFramework
from bbf.core.exceptions import FrameworkError, StageError, PluginError
from bbf.core.database.models import Target, Stage, Plugin, Finding
from bbf.core.database.service import target_service, stage_service, plugin_service

# Test data
TEST_CONFIG = {
    'name': 'test_framework',
    'version': '1.0.0',
    'description': 'Test framework instance',
    'settings': {
        'max_concurrent_stages': 2,
        'max_concurrent_plugins': 5,
        'timeout': 3600,
        'retry_attempts': 3
    }
}

TEST_TARGET = {
    'url': 'https://example.com',
    'scope': 'example.com',
    'status': 'active'
}

@pytest.fixture
async def framework():
    """Create a framework instance for testing."""
    framework = BugBountyFramework(TEST_CONFIG)
    await framework.initialize()
    yield framework
    await framework.cleanup()

@pytest.fixture
async def test_target(framework):
    """Create a test target."""
    target = await target_service.create(
        framework._db_session,
        **TEST_TARGET
    )
    return target

@pytest.mark.asyncio
async def test_framework_initialization(framework):
    """Test framework initialization."""
    # Verify initialization
    assert framework._initialized
    assert framework._db_session is not None
    assert framework._config == TEST_CONFIG
    assert framework._stages == {}
    assert framework._plugins == {}
    assert framework._targets == {}
    
    # Test cleanup
    await framework.cleanup()
    assert not framework._initialized
    assert framework._db_session is None

@pytest.mark.asyncio
async def test_framework_target_management(framework, test_target):
    """Test target management functionality."""
    # Test target registration
    await framework.register_target(test_target)
    assert test_target.id in framework._targets
    assert framework._targets[test_target.id] == test_target
    
    # Test target retrieval
    retrieved = await framework.get_target(test_target.id)
    assert retrieved.id == test_target.id
    assert retrieved.url == test_target.url
    
    # Test target listing
    targets = await framework.list_targets()
    assert len(targets) == 1
    assert targets[0].id == test_target.id
    
    # Test target update
    update_data = {'status': 'completed'}
    updated = await framework.update_target(test_target.id, **update_data)
    assert updated.status == 'completed'
    
    # Test target deletion
    await framework.delete_target(test_target.id)
    assert test_target.id not in framework._targets
    with pytest.raises(FrameworkError):
        await framework.get_target(test_target.id)

@pytest.mark.asyncio
async def test_framework_stage_management(framework, test_target):
    """Test stage management functionality."""
    # Test stage registration
    stage = await framework.register_stage(
        test_target.id,
        'recon',
        {'timeout': 1800}
    )
    assert stage.id in framework._stages
    assert framework._stages[stage.id] == stage
    
    # Test stage retrieval
    retrieved = await framework.get_stage(stage.id)
    assert retrieved.id == stage.id
    assert retrieved.name == 'recon'
    
    # Test stage listing
    stages = await framework.list_stages(test_target.id)
    assert len(stages) == 1
    assert stages[0].id == stage.id
    
    # Test stage update
    update_data = {'status': 'running', 'progress': 0.5}
    updated = await framework.update_stage(stage.id, **update_data)
    assert updated.status == 'running'
    assert updated.progress == 0.5
    
    # Test stage deletion
    await framework.delete_stage(stage.id)
    assert stage.id not in framework._stages
    with pytest.raises(FrameworkError):
        await framework.get_stage(stage.id)

@pytest.mark.asyncio
async def test_framework_plugin_management(framework, test_target):
    """Test plugin management functionality."""
    # Create a stage first
    stage = await framework.register_stage(
        test_target.id,
        'recon',
        {'timeout': 1800}
    )
    
    # Test plugin registration
    plugin = await framework.register_plugin(
        stage.id,
        'subdomain_enum',
        {'version': '1.0.0'}
    )
    assert plugin.id in framework._plugins
    assert framework._plugins[plugin.id] == plugin
    
    # Test plugin retrieval
    retrieved = await framework.get_plugin(plugin.id)
    assert retrieved.id == plugin.id
    assert retrieved.name == 'subdomain_enum'
    
    # Test plugin listing
    plugins = await framework.list_plugins(stage.id)
    assert len(plugins) == 1
    assert plugins[0].id == plugin.id
    
    # Test plugin update
    update_data = {'status': 'running', 'progress': 0.5}
    updated = await framework.update_plugin(plugin.id, **update_data)
    assert updated.status == 'running'
    assert updated.progress == 0.5
    
    # Test plugin deletion
    await framework.delete_plugin(plugin.id)
    assert plugin.id not in framework._plugins
    with pytest.raises(FrameworkError):
        await framework.get_plugin(plugin.id)

@pytest.mark.asyncio
async def test_framework_execution(framework, test_target):
    """Test framework execution flow."""
    # Register stages and plugins
    recon_stage = await framework.register_stage(
        test_target.id,
        'recon',
        {'timeout': 1800}
    )
    
    vuln_stage = await framework.register_stage(
        test_target.id,
        'vulnerability',
        {'timeout': 3600}
    )
    
    # Register plugins for recon stage
    subdomain_plugin = await framework.register_plugin(
        recon_stage.id,
        'subdomain_enum',
        {'version': '1.0.0'}
    )
    
    port_scan_plugin = await framework.register_plugin(
        recon_stage.id,
        'port_scan',
        {'version': '1.0.0'}
    )
    
    # Register plugins for vuln stage
    xss_plugin = await framework.register_plugin(
        vuln_stage.id,
        'xss_scan',
        {'version': '1.0.0'}
    )
    
    # Mock plugin execution
    async def mock_plugin_execute(target):
        return [{
            'type': 'test',
            'severity': 'low',
            'confidence': 0.8,
            'description': 'Test finding'
        }]
    
    with patch('bbf.core.plugin.BasePlugin.execute',
              new_callable=AsyncMock) as mock_execute:
        mock_execute.side_effect = mock_plugin_execute
        
        # Test stage execution
        await framework.execute_stage(recon_stage.id)
        recon_stage = await framework.get_stage(recon_stage.id)
        assert recon_stage.status == 'completed'
        assert recon_stage.progress == 1.0
        
        # Test full framework execution
        await framework.execute_target(test_target.id)
        test_target = await framework.get_target(test_target.id)
        assert test_target.status == 'completed'
        
        # Verify findings were created
        findings = await framework.list_findings(test_target.id)
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)

@pytest.mark.asyncio
async def test_framework_error_handling(framework):
    """Test framework error handling."""
    # Test invalid target
    with pytest.raises(FrameworkError):
        await framework.get_target(999999)
    
    with pytest.raises(FrameworkError):
        await framework.update_target(999999, status='completed')
    
    with pytest.raises(FrameworkError):
        await framework.delete_target(999999)
    
    # Test invalid stage
    with pytest.raises(FrameworkError):
        await framework.get_stage(999999)
    
    with pytest.raises(FrameworkError):
        await framework.update_stage(999999, status='running')
    
    with pytest.raises(FrameworkError):
        await framework.delete_stage(999999)
    
    # Test invalid plugin
    with pytest.raises(FrameworkError):
        await framework.get_plugin(999999)
    
    with pytest.raises(FrameworkError):
        await framework.update_plugin(999999, status='running')
    
    with pytest.raises(FrameworkError):
        await framework.delete_plugin(999999)
    
    # Test execution errors
    with pytest.raises(FrameworkError):
        await framework.execute_stage(999999)
    
    with pytest.raises(FrameworkError):
        await framework.execute_target(999999)
    
    # Test service not initialized
    await framework.cleanup()
    with pytest.raises(FrameworkError):
        await framework.register_target(TEST_TARGET)
    
    with pytest.raises(FrameworkError):
        await framework.execute_target(1)

@pytest.mark.asyncio
async def test_framework_concurrent_execution(framework, test_target):
    """Test concurrent execution handling."""
    # Register multiple stages
    stages = []
    for i in range(3):
        stage = await framework.register_stage(
            test_target.id,
            f'stage_{i}',
            {'timeout': 1800}
        )
        stages.append(stage)
    
    # Mock plugin execution with delay
    async def mock_plugin_execute(target):
        await asyncio.sleep(0.1)
        return [{
            'type': 'test',
            'severity': 'low',
            'confidence': 0.8,
            'description': 'Test finding'
        }]
    
    with patch('bbf.core.plugin.BasePlugin.execute',
              new_callable=AsyncMock) as mock_execute:
        mock_execute.side_effect = mock_plugin_execute
        
        # Test concurrent stage execution
        start_time = datetime.now()
        await framework.execute_stages(stages)
        end_time = datetime.now()
        
        # Verify execution time (should be less than sequential execution)
        execution_time = (end_time - start_time).total_seconds()
        assert execution_time < 0.4  # 3 stages * 0.1s = 0.3s sequential
        
        # Verify all stages completed
        for stage in stages:
            updated = await framework.get_stage(stage.id)
            assert updated.status == 'completed'
            assert updated.progress == 1.0

@pytest.mark.asyncio
async def test_framework_state_management(framework, test_target):
    """Test framework state management."""
    # Test state persistence
    stage = await framework.register_stage(
        test_target.id,
        'recon',
        {'timeout': 1800}
    )
    
    plugin = await framework.register_plugin(
        stage.id,
        'subdomain_enum',
        {'version': '1.0.0'}
    )
    
    # Update state
    await framework.update_stage(stage.id, status='running', progress=0.5)
    await framework.update_plugin(plugin.id, status='running', progress=0.5)
    
    # Create new framework instance
    new_framework = BugBountyFramework(TEST_CONFIG)
    await new_framework.initialize()
    
    # Verify state was persisted
    retrieved_stage = await new_framework.get_stage(stage.id)
    assert retrieved_stage.status == 'running'
    assert retrieved_stage.progress == 0.5
    
    retrieved_plugin = await new_framework.get_plugin(plugin.id)
    assert retrieved_plugin.status == 'running'
    assert retrieved_plugin.progress == 0.5
    
    await new_framework.cleanup()

@pytest.mark.asyncio
async def test_framework_state_persistence(execution_engine, test_stage):
    """Test framework state persistence across instances."""
    # Initialize first instance
    framework1 = BugBountyFramework(TEST_CONFIG)
    await framework1.initialize()
    
    # Register target and stage
    target = await framework1.register_target(TEST_TARGET)
    await framework1.register_stage(test_stage)
    
    # Execute and update state
    await framework1.execute_stage(test_stage, target)
    target.status = 'completed'
    await framework1.update_target(target)
    
    # Create second instance
    framework2 = BugBountyFramework(TEST_CONFIG)
    await framework2.initialize()
    
    # Verify state persistence
    retrieved_target = await framework2.get_target(target.id)
    assert retrieved_target.status == 'completed'
    assert retrieved_target.findings == target.findings
    
    # Cleanup
    await framework1.cleanup()
    await framework2.cleanup()

@pytest.mark.asyncio
async def test_framework_plugin_dependencies(execution_engine):
    """Test framework handling of plugin dependencies."""
    await execution_engine.initialize()
    
    # Create plugins with dependencies
    plugin_a = TestPlugin('plugin_a')
    plugin_b = TestPlugin('plugin_b')
    plugin_c = TestPlugin('plugin_c')
    
    # Set up dependencies
    plugin_b.dependencies = {'required': ['plugin_a']}
    plugin_c.dependencies = {'required': ['plugin_b'], 'optional': ['plugin_d']}
    
    # Register plugins
    framework = BugBountyFramework(TEST_CONFIG)
    await framework.initialize()
    await framework.register_plugin('plugin_a', plugin_a, TEST_PLUGIN_CONFIG)
    await framework.register_plugin('plugin_b', plugin_b, TEST_PLUGIN_CONFIG)
    await framework.register_plugin('plugin_c', plugin_c, TEST_PLUGIN_CONFIG)
    
    # Test dependency validation
    assert await framework.validate_plugin_dependencies('plugin_b')
    assert await framework.validate_plugin_dependencies('plugin_c')
    
    # Test missing required dependency
    plugin_d = TestPlugin('plugin_d')
    plugin_d.dependencies = {'required': ['nonexistent_plugin']}
    with pytest.raises(PluginError):
        await framework.register_plugin('plugin_d', plugin_d, TEST_PLUGIN_CONFIG)
    
    # Test dependency resolution
    resolved = await framework.resolve_plugin_dependencies('plugin_c')
    assert 'plugin_a' in resolved
    assert 'plugin_b' in resolved
    assert len(resolved) == 2  # plugin_d is optional
    
    # Test execution order
    stage = TestStage('test_stage', [plugin_c, plugin_b, plugin_a])
    await framework.register_stage(stage)
    execution_order = []
    
    async def track_execution(plugin, target):
        execution_order.append(plugin.name)
        return await plugin.execute(target)
    
    # Override execute method to track order
    stage.execute = track_execution
    await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify correct execution order (dependencies first)
    assert execution_order.index('plugin_a') < execution_order.index('plugin_b')
    assert execution_order.index('plugin_b') < execution_order.index('plugin_c')
    
    await framework.cleanup()

@pytest.mark.asyncio
async def test_framework_error_recovery(execution_engine, test_stage):
    """Test framework error recovery and retry mechanisms."""
    await execution_engine.initialize()
    
    # Create plugin with controlled failures
    class FailingPlugin(TestPlugin):
        def __init__(self, name, fail_count=2):
            super().__init__(name)
            self.fail_count = fail_count
            self.attempts = 0
        
        async def execute(self, target):
            self.attempts += 1
            if self.attempts <= self.fail_count:
                raise PluginError(f"Plugin {self.name} failed attempt {self.attempts}")
            return await super().execute(target)
    
    # Create stage with failing and normal plugins
    failing_plugin = FailingPlugin('failing_plugin')
    normal_plugin = TestPlugin('normal_plugin')
    stage = TestStage('recovery_stage', [failing_plugin, normal_plugin])
    
    # Configure framework for retries
    config = TEST_CONFIG.copy()
    config['max_retries'] = 3
    config['retry_delay'] = 0.1
    framework = BugBountyFramework(config)
    await framework.initialize()
    await framework.register_stage(stage)
    
    # Execute stage
    results = await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify recovery
    assert failing_plugin.attempts == 3  # Initial + 2 retries
    assert len(results) == 1  # Only normal plugin result
    assert results[0]['plugin'] == 'normal_plugin'
    
    # Test partial recovery
    failing_plugin.fail_count = 4  # Will exceed max retries
    with pytest.raises(PluginError):
        await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify state after failure
    target = await framework.get_target(TEST_TARGET.id)
    assert target.status == 'failed'
    assert len(target.findings) == 1  # Only normal plugin findings
    
    await framework.cleanup()

@pytest.mark.asyncio
async def test_framework_concurrent_stage_execution(execution_engine):
    """Test framework handling of concurrent stage execution."""
    await execution_engine.initialize()
    
    # Create multiple stages
    stages = [
        TestStage(f'stage_{i}', [TestPlugin(f'plugin_{i}_{j}') for j in range(3)])
        for i in range(3)
    ]
    
    # Configure framework for concurrent execution
    config = TEST_CONFIG.copy()
    config['max_concurrent_stages'] = 2
    framework = BugBountyFramework(config)
    await framework.initialize()
    
    # Register stages
    for stage in stages:
        await framework.register_stage(stage)
    
    # Create multiple targets
    targets = [
        await framework.register_target({
            'url': f'https://example{i}.com',
            'scope': 'in-scope'
        })
        for i in range(3)
    ]
    
    # Execute stages concurrently
    tasks = [
        framework.execute_stage(stage, target)
        for stage, target in zip(stages, targets)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Verify execution
    successful_results = [r for r in results if not isinstance(r, Exception)]
    assert len(successful_results) == 3
    
    # Verify target states
    for target in targets:
        updated_target = await framework.get_target(target.id)
        assert updated_target.status == 'completed'
        assert len(updated_target.findings) == 3  # One finding per plugin
    
    # Test resource limits
    config['max_concurrent_stages'] = 1
    framework = BugBountyFramework(config)
    await framework.initialize()
    
    for stage in stages:
        await framework.register_stage(stage)
    
    # Execute stages with limited concurrency
    start_time = datetime.now()
    tasks = [
        framework.execute_stage(stage, target)
        for stage, target in zip(stages, targets)
    ]
    
    results = await asyncio.gather(*tasks)
    end_time = datetime.now()
    
    # Verify sequential execution
    assert (end_time - start_time).total_seconds() >= 0.3  # Each stage takes ~0.1s
    
    await framework.cleanup()

@pytest.mark.asyncio
async def test_framework_plugin_lifecycle_management(execution_engine):
    """Test framework management of plugin lifecycles."""
    await execution_engine.initialize()
    
    # Create plugin with lifecycle tracking
    class LifecyclePlugin(TestPlugin):
        def __init__(self, name):
            super().__init__(name)
            self.lifecycle_events = []
        
        async def initialize(self):
            self.lifecycle_events.append('initialize')
            await super().initialize()
        
        async def execute(self, target):
            self.lifecycle_events.append('execute')
            return await super().execute(target)
        
        async def cleanup(self):
            self.lifecycle_events.append('cleanup')
            await super().cleanup()
    
    # Create stage with lifecycle plugins
    plugins = [LifecyclePlugin(f'plugin_{i}') for i in range(3)]
    stage = TestStage('lifecycle_stage', plugins)
    
    framework = BugBountyFramework(TEST_CONFIG)
    await framework.initialize()
    await framework.register_stage(stage)
    
    # Execute stage
    await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify plugin lifecycles
    for plugin in plugins:
        assert plugin.lifecycle_events == ['initialize', 'execute', 'cleanup']
    
    # Test plugin reuse
    await framework.execute_stage(stage, TEST_TARGET)
    for plugin in plugins:
        assert plugin.lifecycle_events == [
            'initialize', 'execute', 'cleanup',
            'initialize', 'execute', 'cleanup'
        ]
    
    # Test stage cleanup
    await framework.cleanup_stage(stage)
    for plugin in plugins:
        assert plugin.lifecycle_events[-1] == 'cleanup'
    
    await framework.cleanup()

@pytest.mark.asyncio
async def test_framework_error_propagation(execution_engine):
    """Test framework error propagation and handling."""
    await execution_engine.initialize()
    
    # Create plugin that raises different types of errors
    class ErrorPlugin(TestPlugin):
        def __init__(self, name, error_type):
            super().__init__(name)
            self.error_type = error_type
        
        async def execute(self, target):
            if self.error_type == 'plugin':
                raise PluginError("Plugin error")
            elif self.error_type == 'validation':
                raise ValidationError("Validation error")
            elif self.error_type == 'security':
                raise SecurityError("Security error")
            else:
                raise Exception("Unexpected error")
    
    # Create stage with error plugins
    plugins = [
        ErrorPlugin('plugin_1', 'plugin'),
        ErrorPlugin('plugin_2', 'validation'),
        ErrorPlugin('plugin_3', 'security'),
        ErrorPlugin('plugin_4', 'unexpected')
    ]
    stage = TestStage('error_stage', plugins)
    
    framework = BugBountyFramework(TEST_CONFIG)
    await framework.initialize()
    await framework.register_stage(stage)
    
    # Test error propagation
    with pytest.raises(PluginError):
        await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify error handling
    target = await framework.get_target(TEST_TARGET.id)
    assert target.status == 'failed'
    assert len(target.errors) == 4
    
    # Verify error types
    error_types = [e['type'] for e in target.errors]
    assert 'PluginError' in error_types
    assert 'ValidationError' in error_types
    assert 'SecurityError' in error_types
    assert 'Exception' in error_types
    
    # Test error recovery
    target.status = 'pending'
    await framework.update_target(target)
    
    # Replace error plugins with normal plugins
    stage.plugins = [TestPlugin(f'normal_plugin_{i}') for i in range(4)]
    results = await framework.execute_stage(stage, TEST_TARGET)
    
    # Verify recovery
    assert len(results) == 4
    target = await framework.get_target(TEST_TARGET.id)
    assert target.status == 'completed'
    assert len(target.errors) == 0
    
    await framework.cleanup() 