"""
Tests for the plugin manager module.

This module contains test cases for the plugin manager functionality,
verifying plugin discovery, loading, and management.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import os
import json
import importlib
from pathlib import Path
from datetime import datetime

from bbf.core.plugin_manager import PluginManager
from bbf.core.exceptions import PluginManagerError, PluginError
from bbf.core.plugin import BasePlugin

# Test data
TEST_PLUGIN_DIR = Path(__file__).parent / 'test_plugins'
TEST_PLUGIN_CONFIG = {
    'name': 'test_plugin',
    'version': '1.0.0',
    'description': 'Test plugin for unit testing',
    'author': 'Test Author',
    'tags': ['test', 'unit'],
    'settings': {
        'timeout': 30,
        'max_retries': 3,
        'concurrent_tasks': 5
    }
}

class TestPlugin(BasePlugin):
    """Test plugin implementation."""
    
    async def initialize(self):
        """Initialize the test plugin."""
        await super().initialize()
        self._initialized = True
    
    async def execute(self, target):
        """Execute the test plugin."""
        if not self._initialized:
            raise PluginError("Plugin not initialized")
        return [{'type': 'test', 'severity': 'low', 'confidence': 0.8}]
    
    async def cleanup(self):
        """Cleanup the test plugin."""
        await super().cleanup()
        self._initialized = False

@pytest.fixture
def plugin_manager():
    """Create a plugin manager instance for testing."""
    return PluginManager()

@pytest.fixture
def test_plugin_dir(tmp_path):
    """Create a temporary plugin directory for testing."""
    plugin_dir = tmp_path / 'test_plugins'
    plugin_dir.mkdir()
    
    # Create test plugin files
    plugin_file = plugin_dir / 'test_plugin.py'
    plugin_file.write_text("""
from bbf.core.plugin import BasePlugin

class TestPlugin(BasePlugin):
    async def initialize(self):
        await super().initialize()
        self._initialized = True
    
    async def execute(self, target):
        if not self._initialized:
            raise Exception("Plugin not initialized")
        return [{'type': 'test', 'severity': 'low', 'confidence': 0.8}]
    
    async def cleanup(self):
        await super().cleanup()
        self._initialized = False
    """)
    
    config_file = plugin_dir / 'test_plugin.json'
    config_file.write_text(json.dumps(TEST_PLUGIN_CONFIG))
    
    return plugin_dir

@pytest.mark.asyncio
async def test_plugin_manager_initialization(plugin_manager):
    """Test plugin manager initialization."""
    await plugin_manager.initialize()
    
    # Verify initialization
    assert plugin_manager._initialized
    assert plugin_manager._plugins == {}
    assert plugin_manager._plugin_configs == {}
    
    # Test cleanup
    await plugin_manager.cleanup()
    assert not plugin_manager._initialized

@pytest.mark.asyncio
async def test_plugin_discovery(plugin_manager, test_plugin_dir):
    """Test plugin discovery functionality."""
    await plugin_manager.initialize()
    
    # Test plugin discovery
    plugins = await plugin_manager.discover_plugins(test_plugin_dir)
    
    # Verify discovery
    assert len(plugins) == 1
    assert 'test_plugin' in plugins
    assert plugins['test_plugin']['module'] == 'test_plugin'
    assert plugins['test_plugin']['config'] == TEST_PLUGIN_CONFIG
    
    # Test invalid plugin directory
    with pytest.raises(PluginManagerError):
        await plugin_manager.discover_plugins('/nonexistent/directory')

@pytest.mark.asyncio
async def test_plugin_loading(plugin_manager, test_plugin_dir):
    """Test plugin loading functionality."""
    await plugin_manager.initialize()
    
    # Discover plugins first
    plugins = await plugin_manager.discover_plugins(test_plugin_dir)
    
    # Test plugin loading
    plugin = await plugin_manager.load_plugin('test_plugin', test_plugin_dir)
    
    # Verify loading
    assert plugin is not None
    assert isinstance(plugin, BasePlugin)
    assert plugin._initialized
    
    # Test plugin execution
    results = await plugin.execute('test_target')
    assert len(results) == 1
    assert results[0]['type'] == 'test'
    
    # Test plugin cleanup
    await plugin.cleanup()
    assert not plugin._initialized
    
    # Test invalid plugin
    with pytest.raises(PluginManagerError):
        await plugin_manager.load_plugin('nonexistent_plugin', test_plugin_dir)

@pytest.mark.asyncio
async def test_plugin_registration(plugin_manager):
    """Test plugin registration functionality."""
    await plugin_manager.initialize()
    
    # Create test plugin
    plugin = TestPlugin()
    await plugin.initialize()
    
    # Test plugin registration
    await plugin_manager.register_plugin('test_plugin', plugin, TEST_PLUGIN_CONFIG)
    
    # Verify registration
    assert 'test_plugin' in plugin_manager._plugins
    assert plugin_manager._plugins['test_plugin'] == plugin
    assert plugin_manager._plugin_configs['test_plugin'] == TEST_PLUGIN_CONFIG
    
    # Test duplicate registration
    with pytest.raises(PluginManagerError):
        await plugin_manager.register_plugin('test_plugin', plugin, TEST_PLUGIN_CONFIG)
    
    # Test plugin retrieval
    retrieved = await plugin_manager.get_plugin('test_plugin')
    assert retrieved == plugin
    
    # Test plugin listing
    plugins = await plugin_manager.list_plugins()
    assert len(plugins) == 1
    assert 'test_plugin' in plugins
    
    # Test plugin unregistration
    await plugin_manager.unregister_plugin('test_plugin')
    assert 'test_plugin' not in plugin_manager._plugins
    assert 'test_plugin' not in plugin_manager._plugin_configs

@pytest.mark.asyncio
async def test_plugin_validation(plugin_manager, test_plugin_dir):
    """Test plugin validation functionality."""
    await plugin_manager.initialize()
    
    # Test valid plugin
    plugins = await plugin_manager.discover_plugins(test_plugin_dir)
    plugin = await plugin_manager.load_plugin('test_plugin', test_plugin_dir)
    validation = await plugin_manager.validate_plugin(plugin, TEST_PLUGIN_CONFIG)
    assert validation['valid']
    assert len(validation['errors']) == 0
    
    # Test invalid plugin (missing required method)
    class InvalidPlugin(BasePlugin):
        pass
    
    invalid_plugin = InvalidPlugin()
    validation = await plugin_manager.validate_plugin(invalid_plugin, TEST_PLUGIN_CONFIG)
    assert not validation['valid']
    assert len(validation['errors']) > 0
    
    # Test invalid config
    invalid_config = TEST_PLUGIN_CONFIG.copy()
    del invalid_config['name']
    validation = await plugin_manager.validate_plugin(plugin, invalid_config)
    assert not validation['valid']
    assert len(validation['errors']) > 0

@pytest.mark.asyncio
async def test_plugin_dependencies(plugin_manager, test_plugin_dir):
    """Test plugin dependency management."""
    await plugin_manager.initialize()
    
    # Create plugin with dependencies
    plugin_config = TEST_PLUGIN_CONFIG.copy()
    plugin_config['dependencies'] = {
        'required': ['plugin_a', 'plugin_b'],
        'optional': ['plugin_c']
    }
    
    # Test dependency validation
    validation = await plugin_manager.validate_dependencies(
        'test_plugin',
        plugin_config['dependencies']
    )
    assert not validation['valid']
    assert len(validation['missing']) == 2
    
    # Register required plugins
    plugin_a = TestPlugin()
    plugin_b = TestPlugin()
    await plugin_manager.register_plugin('plugin_a', plugin_a, TEST_PLUGIN_CONFIG)
    await plugin_manager.register_plugin('plugin_b', plugin_b, TEST_PLUGIN_CONFIG)
    
    # Test dependency validation again
    validation = await plugin_manager.validate_dependencies(
        'test_plugin',
        plugin_config['dependencies']
    )
    assert validation['valid']
    assert len(validation['missing']) == 0

@pytest.mark.asyncio
async def test_plugin_error_handling(plugin_manager):
    """Test plugin error handling."""
    # Test service not initialized
    with pytest.raises(PluginManagerError):
        await plugin_manager.discover_plugins('/test/directory')
    
    with pytest.raises(PluginManagerError):
        await plugin_manager.load_plugin('test_plugin', '/test/directory')
    
    with pytest.raises(PluginManagerError):
        await plugin_manager.register_plugin('test_plugin', TestPlugin(), TEST_PLUGIN_CONFIG)
    
    # Initialize service
    await plugin_manager.initialize()
    
    # Test invalid plugin directory
    with pytest.raises(PluginManagerError):
        await plugin_manager.discover_plugins('/nonexistent/directory')
    
    # Test invalid plugin
    with pytest.raises(PluginManagerError):
        await plugin_manager.load_plugin('nonexistent_plugin', '/test/directory')
    
    # Test invalid plugin registration
    with pytest.raises(PluginManagerError):
        await plugin_manager.register_plugin('test_plugin', None, TEST_PLUGIN_CONFIG)
    
    with pytest.raises(PluginManagerError):
        await plugin_manager.register_plugin('test_plugin', TestPlugin(), None)
    
    # Test invalid plugin retrieval
    with pytest.raises(PluginManagerError):
        await plugin_manager.get_plugin('nonexistent_plugin')
    
    # Test invalid plugin unregistration
    with pytest.raises(PluginManagerError):
        await plugin_manager.unregister_plugin('nonexistent_plugin')

@pytest.mark.asyncio
async def test_plugin_lifecycle(plugin_manager, test_plugin_dir):
    """Test complete plugin lifecycle."""
    await plugin_manager.initialize()
    
    # Discover and load plugin
    plugins = await plugin_manager.discover_plugins(test_plugin_dir)
    plugin = await plugin_manager.load_plugin('test_plugin', test_plugin_dir)
    
    # Register plugin
    await plugin_manager.register_plugin('test_plugin', plugin, TEST_PLUGIN_CONFIG)
    
    # Verify plugin state
    assert plugin._initialized
    assert 'test_plugin' in plugin_manager._plugins
    
    # Execute plugin
    results = await plugin.execute('test_target')
    assert len(results) == 1
    assert results[0]['type'] == 'test'
    
    # Unregister and cleanup
    await plugin_manager.unregister_plugin('test_plugin')
    await plugin.cleanup()
    
    # Verify cleanup
    assert not plugin._initialized
    assert 'test_plugin' not in plugin_manager._plugins
    
    # Test plugin manager cleanup
    await plugin_manager.cleanup()
    assert not plugin_manager._initialized 

@pytest.mark.asyncio
async def test_plugin_versioning(plugin_manager):
    """Test plugin version management and compatibility."""
    await plugin_manager.initialize()
    
    # Create plugins with different versions
    plugin_v1 = TestPlugin('test_plugin')
    plugin_v1.version = '1.0.0'
    
    plugin_v2 = TestPlugin('test_plugin')
    plugin_v2.version = '2.0.0'
    
    plugin_v1_1 = TestPlugin('test_plugin')
    plugin_v1_1.version = '1.1.0'
    
    # Register initial version
    await plugin_manager.register_plugin('test_plugin', plugin_v1, TEST_PLUGIN_CONFIG)
    
    # Test version upgrade
    await plugin_manager.register_plugin('test_plugin', plugin_v2, TEST_PLUGIN_CONFIG)
    current = await plugin_manager.get_plugin('test_plugin')
    assert current.version == '2.0.0'
    
    # Test version downgrade (should fail)
    with pytest.raises(PluginManagerError):
        await plugin_manager.register_plugin('test_plugin', plugin_v1, TEST_PLUGIN_CONFIG)
    
    # Test version compatibility
    assert await plugin_manager.check_version_compatibility('2.0.0', '1.0.0')
    assert not await plugin_manager.check_version_compatibility('1.0.0', '2.0.0')
    
    # Test version requirements
    plugin_config = TEST_PLUGIN_CONFIG.copy()
    plugin_config['version_requirements'] = {
        'min_version': '1.0.0',
        'max_version': '2.0.0'
    }
    
    assert await plugin_manager.validate_version_requirements('1.1.0', plugin_config)
    assert not await plugin_manager.validate_version_requirements('2.1.0', plugin_config)
    
    await plugin_manager.cleanup()

@pytest.mark.asyncio
async def test_plugin_configuration_management(plugin_manager):
    """Test plugin configuration management and validation."""
    await plugin_manager.initialize()
    
    # Create plugin with configuration
    class ConfigurablePlugin(TestPlugin):
        def __init__(self, name):
            super().__init__(name)
            self.config = None
        
        async def configure(self, config):
            self.config = config
            if config.get('invalid'):
                raise PluginError("Invalid configuration")
    
    plugin = ConfigurablePlugin('config_plugin')
    
    # Test configuration validation
    valid_config = {
        'name': 'config_plugin',
        'version': '1.0.0',
        'settings': {
            'timeout': 30,
            'retries': 3,
            'enabled': True
        }
    }
    
    assert await plugin_manager.validate_plugin_config(plugin, valid_config)
    
    # Test invalid configuration
    invalid_config = valid_config.copy()
    invalid_config['settings']['timeout'] = -1
    
    with pytest.raises(PluginManagerError):
        await plugin_manager.validate_plugin_config(plugin, invalid_config)
    
    # Test configuration application
    await plugin_manager.register_plugin('config_plugin', plugin, valid_config)
    await plugin_manager.configure_plugin('config_plugin', valid_config)
    
    assert plugin.config == valid_config
    
    # Test configuration update
    updated_config = valid_config.copy()
    updated_config['settings']['timeout'] = 60
    
    await plugin_manager.update_plugin_config('config_plugin', updated_config)
    assert plugin.config == updated_config
    
    # Test configuration inheritance
    base_config = {
        'name': 'base_plugin',
        'version': '1.0.0',
        'settings': {
            'timeout': 30,
            'retries': 3
        }
    }
    
    child_config = {
        'name': 'child_plugin',
        'version': '1.0.0',
        'settings': {
            'timeout': 60
        }
    }
    
    await plugin_manager.register_base_config('base_plugin', base_config)
    merged_config = await plugin_manager.merge_configs('child_plugin', child_config)
    
    assert merged_config['settings']['timeout'] == 60
    assert merged_config['settings']['retries'] == 3
    
    await plugin_manager.cleanup()

@pytest.mark.asyncio
async def test_plugin_isolation(plugin_manager):
    """Test plugin isolation and resource management."""
    await plugin_manager.initialize()
    
    # Create plugin with resource tracking
    class ResourcePlugin(TestPlugin):
        def __init__(self, name):
            super().__init__(name)
            self.resources = set()
        
        async def initialize(self):
            await super().initialize()
            self.resources.add('initialized')
        
        async def execute(self, target):
            self.resources.add('executing')
            return await super().execute(target)
        
        async def cleanup(self):
            self.resources.clear()
            await super().cleanup()
    
    # Create multiple plugin instances
    plugins = [ResourcePlugin(f'plugin_{i}') for i in range(3)]
    
    # Register plugins
    for plugin in plugins:
        await plugin_manager.register_plugin(plugin.name, plugin, TEST_PLUGIN_CONFIG)
    
    # Test resource isolation
    for plugin in plugins:
        await plugin_manager.initialize_plugin(plugin.name)
        assert plugin.resources == {'initialized'}
    
    # Test execution isolation
    for plugin in plugins:
        await plugin_manager.execute_plugin(plugin.name, 'test_target')
        assert plugin.resources == {'initialized', 'executing'}
    
    # Test cleanup isolation
    for plugin in plugins:
        await plugin_manager.cleanup_plugin(plugin.name)
        assert plugin.resources == set()
    
    # Test plugin sandboxing
    class SandboxedPlugin(TestPlugin):
        async def execute(self, target):
            # Attempt to access global state
            global_state = globals()
            # Attempt to modify system
            import os
            os.system('echo "test"')
            return await super().execute(target)
    
    sandboxed = SandboxedPlugin('sandboxed_plugin')
    await plugin_manager.register_plugin('sandboxed_plugin', sandboxed, TEST_PLUGIN_CONFIG)
    
    # Verify sandboxing
    with pytest.raises(PluginError):
        await plugin_manager.execute_plugin('sandboxed_plugin', 'test_target')
    
    await plugin_manager.cleanup()

@pytest.mark.asyncio
async def test_plugin_event_handling(plugin_manager):
    """Test plugin event handling and notification system."""
    await plugin_manager.initialize()
    
    # Create plugin with event tracking
    class EventPlugin(TestPlugin):
        def __init__(self, name):
            super().__init__(name)
            self.events = []
        
        async def handle_event(self, event_type, data):
            self.events.append((event_type, data))
    
    # Create plugins
    plugins = [EventPlugin(f'plugin_{i}') for i in range(3)]
    
    # Register plugins and event handlers
    for plugin in plugins:
        await plugin_manager.register_plugin(plugin.name, plugin, TEST_PLUGIN_CONFIG)
        await plugin_manager.register_event_handler(
            plugin.name,
            ['plugin_started', 'plugin_completed', 'plugin_error'],
            plugin.handle_event
        )
    
    # Test event propagation
    await plugin_manager.notify_event('plugin_started', {'target': 'test_target'})
    for plugin in plugins:
        assert len(plugin.events) == 1
        assert plugin.events[0][0] == 'plugin_started'
    
    # Test selective event handling
    await plugin_manager.register_event_handler(
        'plugin_0',
        ['custom_event'],
        plugins[0].handle_event
    )
    
    await plugin_manager.notify_event('custom_event', {'data': 'test'})
    assert len(plugins[0].events) == 2
    assert len(plugins[1].events) == 1
    assert len(plugins[2].events) == 1
    
    # Test event error handling
    class ErrorPlugin(TestPlugin):
        async def handle_event(self, event_type, data):
            raise Exception("Event handling error")
    
    error_plugin = ErrorPlugin('error_plugin')
    await plugin_manager.register_plugin('error_plugin', error_plugin, TEST_PLUGIN_CONFIG)
    await plugin_manager.register_event_handler(
        'error_plugin',
        ['test_event'],
        error_plugin.handle_event
    )
    
    # Verify error handling
    await plugin_manager.notify_event('test_event', {'data': 'test'})
    # Other plugins should still receive events
    for plugin in plugins:
        assert len(plugin.events) > 0
    
    await plugin_manager.cleanup()

@pytest.mark.asyncio
async def test_plugin_metrics_collection(plugin_manager):
    """Test plugin metrics collection and monitoring."""
    await plugin_manager.initialize()
    
    # Create plugin with metrics
    class MetricsPlugin(TestPlugin):
        def __init__(self, name):
            super().__init__(name)
            self.execution_count = 0
            self.execution_time = 0
        
        async def execute(self, target):
            start_time = datetime.now()
            self.execution_count += 1
            result = await super().execute(target)
            self.execution_time += (datetime.now() - start_time).total_seconds()
            return result
    
    # Create plugins
    plugins = [MetricsPlugin(f'plugin_{i}') for i in range(3)]
    
    # Register plugins
    for plugin in plugins:
        await plugin_manager.register_plugin(plugin.name, plugin, TEST_PLUGIN_CONFIG)
    
    # Execute plugins multiple times
    for _ in range(3):
        for plugin in plugins:
            await plugin_manager.execute_plugin(plugin.name, 'test_target')
    
    # Test metrics collection
    metrics = await plugin_manager.collect_plugin_metrics()
    
    for plugin in plugins:
        plugin_metrics = metrics[plugin.name]
        assert plugin_metrics['execution_count'] == 3
        assert plugin_metrics['execution_time'] > 0
        assert plugin_metrics['status'] == 'active'
    
    # Test metrics aggregation
    aggregated = await plugin_manager.aggregate_plugin_metrics()
    assert aggregated['total_executions'] == 9
    assert aggregated['average_execution_time'] > 0
    assert aggregated['active_plugins'] == 3
    
    # Test metrics history
    history = await plugin_manager.get_plugin_metrics_history('plugin_0')
    assert len(history) == 3
    for entry in history:
        assert 'timestamp' in entry
        assert 'execution_count' in entry
        assert 'execution_time' in entry
    
    # Test metrics cleanup
    await plugin_manager.cleanup_plugin_metrics()
    metrics = await plugin_manager.collect_plugin_metrics()
    for plugin_metrics in metrics.values():
        assert plugin_metrics['execution_count'] == 0
        assert plugin_metrics['execution_time'] == 0
    
    await plugin_manager.cleanup() 