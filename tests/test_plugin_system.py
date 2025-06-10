"""
Tests for the plugin system in the Bug Bounty Framework.
"""

import asyncio
import importlib
import inspect
import logging
import os
import pytest
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Set

import pytest_asyncio

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('test_plugin_system.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from bbf.core.plugin import (
    BasePlugin, 
    plugin, 
    get_plugin, 
    get_available_plugins, 
    clear_plugin_registry,
    PluginRegistry
)
from bbf.core.plugin_manager import PluginManager
from bbf.core.exceptions import PluginError, PluginValidationError, PluginDependencyError

# Fixture to clear plugin registry before each test
@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the plugin registry before each test."""
    logger.debug("Clearing plugin registry before test")
    clear_plugin_registry()
    assert len(get_available_plugins()) == 0, "Plugin registry should be empty after clear"
    yield
    logger.debug("Test completed, clearing plugin registry")
    clear_plugin_registry()

# Test plugins for registration
@plugin
class TestPluginA(BasePlugin):
    """Test plugin A for unit testing."""
    name = "test_plugin_a"
    description = "Test plugin A"
    version = "1.0.0"
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        # Call execute with the target from args or kwargs
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {"status": "success", "plugin": self.name, "target": target}

@plugin
class TestPluginB(BasePlugin):
    """Test plugin B for unit testing with dependencies."""
    name = "test_plugin_b"
    description = "Test plugin B with dependencies"
    version = "1.0.0"
    depends_on = ["test_plugin_a"]
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with dependencies."""
        # Call execute with the target from args or kwargs
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {"status": "success", "plugin": self.name, "dependencies": self.depends_on}

class TestBasePlugin:
    """Test cases for the BasePlugin class."""
    
    @pytest.fixture
    def plugin_config(self):
        """Fixture providing a sample plugin configuration."""
        return {"option1": "value1", "option2": 42}
    
    @pytest.fixture
    def test_plugin(self, plugin_config):
        """Fixture providing a test plugin instance."""
        return TestPluginA(plugin_config)
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, test_plugin, plugin_config):
        """Test plugin initialization with configuration."""
        assert test_plugin.name == "test_plugin_a"
        assert test_plugin.config == plugin_config
        assert test_plugin.enabled is True
    
    @pytest.mark.asyncio
    async def test_plugin_execute(self, test_plugin):
        """Test plugin execution."""
        result = await test_plugin.execute("example.com")
        assert result["status"] == "success"
        assert result["plugin"] == "test_plugin_a"
        assert result["target"] == "example.com"
    
    @pytest.mark.asyncio
    async def test_plugin_results(self, test_plugin):
        """Test adding and retrieving results."""
        test_plugin.add_result("key1", "value1")
        test_plugin.add_result("key2", 123)
        
        results = test_plugin.results
        assert results["key1"] == "value1"
        assert results["key2"] == 123
    
    @pytest.mark.asyncio
    async def test_plugin_errors(self, test_plugin):
        """Test error handling."""
        test_plugin.add_error("Test error")
        
        errors = test_plugin.errors
        assert len(errors) == 1
        assert "Test error" in errors[0]["error"]
        assert test_plugin.metrics["error_count"] == 1


class TestPluginRegistration:
    """Test cases for plugin registration."""
    
    def setup_method(self):
        """Clear the plugin registry before each test."""
        clear_plugin_registry()
    
    def test_register_plugin(self):
        """Test registering a plugin with the @plugin decorator."""
        # The TestPluginA class is already registered by the decorator
        plugins = get_available_plugins()
        assert "test_plugin_a" in plugins
        assert plugins["test_plugin_a"] is TestPluginA
    
    def test_get_plugin_class(self):
        """Test getting a plugin class by name."""
        plugin_class = get_plugin("test_plugin_a")
        assert plugin_class is TestPluginA
        assert plugin_class.name == "test_plugin_a"
    
    def test_get_nonexistent_plugin(self):
        """Test getting a non-existent plugin raises KeyError."""
        with pytest.raises(KeyError):
            get_plugin("nonexistent_plugin")
    
    def test_duplicate_plugin_name(self):
        """Test that duplicate plugin names raise an error."""
        with pytest.raises(PluginValidationError):
            @plugin
            class DuplicatePlugin(BasePlugin):
                name = "test_plugin_a"  # Duplicate name
                description = "Duplicate plugin"
                version = "1.0.0"
                
                async def run(self, *args, **kwargs) -> Dict[str, Any]:
                    target = args[0] if args else kwargs.get('target', '')
                    return await self.execute(target, **kwargs)
                    
                async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
                    return {"status": "success"}
    
    def test_invalid_plugin_missing_name(self):
        """Test that plugins without a name raise an error."""
        with pytest.raises(PluginValidationError):
            @plugin
            class InvalidPlugin(BasePlugin):
                # Missing name attribute
                description = "Invalid plugin"
                version = "1.0.0"
                
                async def run(self, *args, **kwargs) -> Dict[str, Any]:
                    return {}
    
    def test_invalid_plugin_missing_execute_method(self):
        """Test that plugins without an execute method raise an error."""
        with pytest.raises(PluginValidationError):
            @plugin
            class InvalidPlugin(BasePlugin):
                name = "invalid_plugin"
                description = "Invalid plugin"
                version = "1.0.0"
                
                async def run(self, *args, **kwargs) -> Dict[str, Any]:
                    return {"status": "success"}
                
                # Missing execute method


class TestPluginManager:
    """Test cases for the PluginManager class."""
    
    @pytest.fixture
    def plugin_manager(self, tmp_path):
        """Fixture providing a PluginManager instance with a temporary directory."""
        # Create a temporary directory for plugin discovery
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        
        # Create a simple plugin file
        plugin_file = plugins_dir / "test_plugin_c.py"
        plugin_code = '''
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginC(BasePlugin):
    name = "test_plugin_c"
    description = "Test plugin C loaded from file"
    version = "1.0.0"
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        # Call execute with the target from args or kwargs
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {"status": "success", "plugin": self.name, "target": target}
'''
        plugin_file.write_text(plugin_code)
        
        # Create a plugin manager with the temporary directory
        return PluginManager(plugin_dirs=[str(plugins_dir)])
    
    @pytest.mark.asyncio
    async def test_discover_plugins(self, plugin_manager):
        """Test discovering plugins from a directory."""
        # Initialize the plugin manager
        await plugin_manager.initialize()
        
        # Check that plugins were discovered
        plugins = await plugin_manager.get_available_plugins()
        assert "test_plugin_c" in plugins
        assert "test_plugin_a" in plugins  # From the test_plugin_a module
        assert "test_plugin_b" in plugins  # From the test_plugin_b module
    
    @pytest.mark.asyncio
    async def test_get_plugin_instance(self, plugin_manager):
        """Test getting a plugin instance by name."""
        await plugin_manager.initialize()
        
        # Get an instance of test_plugin_a
        plugin = await plugin_manager.get_plugin("test_plugin_a")
        assert plugin is not None
        assert plugin.name == "test_plugin_a"
        
        # Execute the plugin
        result = await plugin.execute("example.com")
        assert result["status"] == "success"
        assert result["plugin"] == "test_plugin_a"
    
    @pytest.mark.asyncio
    async def test_plugin_dependencies(self, plugin_manager):
        """Test plugin dependency checking."""
        await plugin_manager.initialize()
        
        # Test that test_plugin_b has a dependency on test_plugin_a
        plugin_b = await plugin_manager.get_plugin("test_plugin_b")
        assert plugin_b.depends_on == ["test_plugin_a"]
        
        # Check that dependencies are met
        available_plugins = await plugin_manager.get_available_plugins()
        await plugin_b.check_dependencies(available_plugins)
        assert plugin_b._dependencies_met is True
    
    @pytest.mark.asyncio
    async def test_missing_dependencies(self, plugin_manager):
        """Test handling of missing dependencies."""
        await plugin_manager.initialize()
        
        # Create a plugin with a non-existent dependency
        @plugin
        class PluginWithMissingDeps(BasePlugin):
            name = "plugin_with_missing_deps"
            description = "Plugin with missing dependencies"
            version = "1.0.0"
            depends_on = ["nonexistent_plugin"]
            
            async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
                return {"status": "success"}
        
        # Get the plugin instance
        plugin_inst = await plugin_manager.get_plugin("plugin_with_missing_deps")
        
        # Check that dependency checking fails
        with pytest.raises(PluginDependencyError):
            available_plugins = await plugin_manager.get_available_plugins()
            await plugin_inst.check_dependencies(available_plugins)
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, plugin_manager):
        """Test plugin cleanup."""
        await plugin_manager.initialize()
        
        # Get a plugin instance
        plugin = await plugin_manager.get_plugin("test_plugin_a")
        
        # Clean up the plugin
        await plugin.cleanup()
        
        # Check that cleanup was performed
        assert plugin._status == "cleaned_up"
        assert plugin._end_time is not None
    
    @pytest.mark.asyncio
    async def test_plugin_manager_cleanup(self, plugin_manager):
        """Test plugin manager cleanup."""
        await plugin_manager.initialize()
        
        # Get a plugin instance
        await plugin_manager.get_plugin("test_plugin_a")
        
        # Clean up the plugin manager
        await plugin_manager.close()
        
        # Check that plugins were cleaned up
        assert len(plugin_manager._loaded_plugins) == 0


class TestPluginUtils:
    """Test cases for plugin utility functions."""
    
    @pytest.fixture
    def temp_plugin_dir(self, tmp_path):
        """Create a temporary directory with a test plugin."""
        # Create a test plugin file
        plugin_file = tmp_path / "test_plugin_d.py"
        plugin_code = '''
import sys
from typing import Dict, Any
from bbf.core.plugin import BasePlugin, plugin

@plugin
class TestPluginD(BasePlugin):
    """Test plugin D for unit testing."""
    name = "test_plugin_d"
    description = "Test plugin D"
    version = "1.0.0"

    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality."""
        target = args[0] if args else kwargs.get('target', '')
        return await self.execute(target, **kwargs)

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality with target parameter."""
        return {'status': 'success', 'plugin': self.name, 'target': target}
'''
        
        # Write the plugin code to the file
        plugin_file.write_text(plugin_code)
        
        # Verify the file was created and has content
        assert plugin_file.exists(), f"Plugin file was not created at {plugin_file}"
        file_content = plugin_file.read_text()
        assert file_content.strip(), f"Plugin file is empty: {plugin_file}"
        
        # Print debug information
        separator = '=' * 80
        print(f"\n{separator}")
        print(f"Created test plugin at: {plugin_file}")
        print("Plugin file contents:")
        print("-" * 40)
        print(file_content)
        print("-" * 40)
        print(f"File size: {len(file_content)} bytes")
        print(f"{separator}\n")
        
        return tmp_path
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file(self, temp_plugin_dir):
        """Test loading a plugin from a file."""
        from bbf.utils.plugin_utils import load_plugin_from_file
        
        plugin_file = temp_plugin_dir / "test_plugin_d.py"
        plugin_class = load_plugin_from_file(plugin_file, BasePlugin)
        
        assert plugin_class is not None
        assert plugin_class.name == "test_plugin_d"
        
        # Create an instance and execute it
        plugin = plugin_class({})
        result = await plugin.execute("example.com")
        assert result["status"] == "success"
        assert result["plugin"] == "test_plugin_d"
    
    @pytest.mark.asyncio
    async def test_discover_plugins_in_directory(self, temp_plugin_dir, capsys):
        """Test discovering plugins in a directory."""
        # Verify the plugin file was created
        plugin_file = temp_plugin_dir / "test_plugin_d.py"
        assert plugin_file.exists(), f"Plugin file not found at {plugin_file}"
        
        # List files in the directory for debugging
        from bbf.utils.plugin_utils import discover_plugins_in_directory
        
        logger.info(f"Testing plugin discovery in directory: {temp_plugin_dir}")
        logger.info(f"Directory contents: {list(temp_plugin_dir.glob('*'))}")
        
        # Verify the plugin file exists and has content
        plugin_file = temp_plugin_dir / "test_plugin_d.py"
        assert plugin_file.exists(), f"Plugin file not found at {plugin_file}"
        
        logger.info(f"Plugin file content:\n{plugin_file.read_text()}")
        
        # Print current Python path for debugging
        logger.info(f"Python path: {sys.path}")
        
        # Test discovering plugins in the temporary directory
        logger.info("Discovering plugins...")
        from bbf.core.plugin import BasePlugin
        plugins = discover_plugins_in_directory(str(temp_plugin_dir), base_class=BasePlugin)
        logger.info(f"Discovered plugins: {plugins}")
        
        # Print plugin registry state
        logger.info(f"Plugin registry state: {PluginRegistry._plugins}")
        
        # Check that the test plugin was discovered
        assert "test_plugin_d" in plugins, (
            f"Plugin 'test_plugin_d' not found in {plugins}. "
            f"Available plugins: {list(plugins.keys())}"
        )
        
        plugin_class = plugins["test_plugin_d"]
        assert plugin_class.__name__ == "TestPluginD", \
            f"Unexpected plugin class name: {plugin_class.__name__}"
            
        # Verify the plugin can be instantiated
        try:
            instance = plugin_class({})
            assert instance is not None
            logger.info(f"Successfully created instance of {plugin_class.__name__}")
        except Exception as e:
            logger.error(f"Failed to create plugin instance: {e}")
            raise
        
        # Check stdout for debug output
        captured = capsys.readouterr()
        debug_output = captured.out + captured.err
        logger.info(f"Captured output:\n{debug_output}")
        
        assert "Found plugin class: TestPluginD" in debug_output, \
            "Expected debug output not found"
    
    @pytest.mark.asyncio
    async def test_discover_plugins_in_package(self):
        """Test discovering plugins in a Python package."""
        from bbf.plugins import example_plugins
        from bbf.core.plugin import get_available_plugins
        
        # Get all available plugins
        plugins = get_available_plugins()
        
        # Check that the SubdomainEnumerationPlugin was found
        assert "subdomain_enumeration" in plugins
        plugin_class = plugins["subdomain_enumeration"]
        
        # Test that the plugin can be instantiated
        plugin = plugin_class({})
        assert plugin.name == "subdomain_enumeration"
        
        # Note: We don't execute this plugin in tests as it performs actual network operations
