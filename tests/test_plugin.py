"""
Unit tests for the plugin system in the Bug Bounty Framework.
"""

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from bbf.core.plugin import BasePlugin, plugin

# Test plugin for testing
@plugin
class TestPlugin(BasePlugin):
    """Test plugin for unit testing."""
    
    name = "test_plugin"
    description = "A test plugin"
    version = "1.0.0"
    
    def __init__(self, config=None):
        super().__init__(config or {})
        self.setup_called = False
        self.cleanup_called = False
    
    async def setup(self):
        self.setup_called = True
    
    async def cleanup(self):
        self.cleanup_called = True
    
    async def execute(self, target, **kwargs):
        return {"target": target, "status": "success"}

class TestBasePlugin:
    """Test cases for the BasePlugin class."""
    
    @pytest.fixture
    def test_plugin(self):
        """Fixture to create a test plugin instance."""
        return TestPlugin()
    
    @pytest.mark.asyncio
    async def test_plugin_setup(self, test_plugin):
        """Test plugin setup method is called."""
        assert not test_plugin.setup_called
        await test_plugin.setup()
        assert test_plugin.setup_called
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(self, test_plugin):
        """Test plugin cleanup method is called."""
        assert not test_plugin.cleanup_called
        await test_plugin.cleanup()
        assert test_plugin.cleanup_called
    
    @pytest.mark.asyncio
    async def test_plugin_execute(self, test_plugin):
        """Test plugin execute method returns expected result."""
        result = await test_plugin.execute("test_target")
        assert result == {"target": "test_target", "status": "success"}
    
    def test_plugin_registration(self):
        """Test that plugins are properly registered with the decorator."""
        from bbf.core.plugin import get_plugins
        assert "test_plugin" in get_plugins()
        assert get_plugins()["test_plugin"] == TestPlugin

class TestPluginLifecycle:
    """Test the complete plugin lifecycle."""
    
    @pytest.mark.asyncio
    async def test_plugin_lifecycle(self):
        """Test the complete plugin lifecycle (setup -> execute -> cleanup)."""
        plugin = TestPlugin()
        
        # Setup
        assert not plugin.setup_called
        await plugin.setup()
        assert plugin.setup_called
        
        # Execute
        result = await plugin.execute("test_target")
        assert result == {"target": "test_target", "status": "success"}
        
        # Cleanup
        assert not plugin.cleanup_called
        await plugin.cleanup()
        assert plugin.cleanup_called

class TestPluginErrorHandling:
    """Test error handling in plugins."""
    
    @pytest.mark.asyncio
    async def test_plugin_execute_error(self):
        """Test error handling in plugin execution."""
        class ErrorPlugin(BasePlugin):
            name = "error_plugin"
            
            async def execute(self, target, **kwargs):
                raise ValueError("Test error")
        
        plugin = ErrorPlugin()
        
        with pytest.raises(ValueError, match="Test error"):
            await plugin.execute("test_target")
    
    @pytest.mark.asyncio
    async def test_plugin_setup_error(self):
        """Test error handling in plugin setup."""
        class SetupErrorPlugin(BasePlugin):
            name = "setup_error_plugin"
            
            async def setup(self):
                raise RuntimeError("Setup failed")
            
            async def execute(self, target, **kwargs):
                return {"status": "should not reach here"}
        
        plugin = SetupErrorPlugin()
        
        with pytest.raises(RuntimeError, match="Setup failed"):
            await plugin.setup()
        
        # Execute should fail if setup failed
        with pytest.raises(RuntimeError, match="Plugin not initialized"):
            await plugin.execute("test_target")
