"""
Base plugin system for the Bug Bounty Framework.

This module defines the BasePlugin class that all plugins must inherit from,
and provides the plugin registration mechanism.
"""

import abc
import inspect
import logging
from typing import Dict, List, Optional, Any, Type, Set

logger = logging.getLogger(__name__)

class BasePlugin(metaclass=abc.ABCMeta):
    """
    Base class for all plugins in the Bug Bounty Framework.
    
    All plugins must inherit from this class and implement the required methods.
    """
    
    # Plugin metadata
    name: str = "base_plugin"
    description: str = "Base plugin class. Should be overridden by subclasses."
    version: str = "0.1.0"
    
    # Plugin configuration
    enabled: bool = True
    required_ports: List[int] = []
    required_protocols: List[str] = []
    
    # Dependencies (plugin names that must run before this one)
    depends_on: List[str] = []
    
    # Timeout in seconds (0 for no timeout)
    timeout: int = 300  # 5 minutes default
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the plugin with optional configuration.
        
        Args:
            config: Dictionary containing plugin configuration
        """
        self.config = config or {}
        self._state = {}
        self._results = {}
        self._errors = []
        
        # Set up logger for this plugin instance
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abc.abstractmethod
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for the plugin's functionality.
        
        This method must be implemented by all plugins. It should contain
        the core logic of the plugin.
        
        Returns:
            Dictionary containing the results of the plugin's execution
        """
        raise NotImplementedError("Plugin must implement the run() method")
    
    async def setup(self) -> None:
        """
        Perform any setup required before the plugin runs.
        
        This method can be overridden by plugins that need to perform
        initialization steps before the main execution.
        """
        pass
    
    async def cleanup(self) -> None:
        """
        Perform any cleanup after the plugin has finished running.
        
        This method can be overridden by plugins that need to perform
        cleanup operations after execution.
        """
        pass
    
    def validate_config(self) -> bool:
        """
        Validate the plugin's configuration.
        
        Returns:
            bool: True if the configuration is valid, False otherwise
        """
        return True
    
    def add_result(self, key: str, value: Any) -> None:
        """
        Add a result to the plugin's result dictionary.
        
        Args:
            key: The key under which to store the result
            value: The result value to store
        """
        self._results[key] = value
    
    def add_error(self, error: Exception) -> None:
        """
        Add an error to the plugin's error list.
        
        Args:
            error: The exception that occurred
        """
        self._errors.append(error)
        self.log.error(f"Error in plugin {self.name}: {str(error)}", exc_info=True)
    
    @property
    def results(self) -> Dict[str, Any]:
        """Get the plugin's results."""
        return self._results
    
    @property
    def errors(self) -> List[Exception]:
        """Get the plugin's errors."""
        return self._errors
    
    @property
    def state(self) -> Dict[str, Any]:
        """Get the plugin's state."""
        return self._state
    
    @state.setter
    def state(self, value: Dict[str, Any]) -> None:
        """Set the plugin's state."""
        self._state = value
    
    def __str__(self) -> str:
        """String representation of the plugin."""
        return f"{self.name} (v{self.version}): {self.description}"


class PluginRegistry:
    """Registry for managing plugin classes."""
    
    _instance = None
    _plugins: Dict[str, Type[BasePlugin]] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PluginRegistry, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def register(cls, plugin_class: Type[BasePlugin]) -> Type[BasePlugin]:
        """
        Decorator to register a plugin class.
        
        Args:
            plugin_class: The plugin class to register
            
        Returns:
            The registered plugin class
            
        Raises:
            ValueError: If a plugin with the same name is already registered
        """
        if not inspect.isclass(plugin_class) or not issubclass(plugin_class, BasePlugin):
            raise ValueError("Only subclasses of BasePlugin can be registered")
        
        plugin_name = plugin_class.name
        if plugin_name in cls._plugins:
            raise ValueError(f"Plugin with name '{plugin_name}' is already registered")
        
        cls._plugins[plugin_name] = plugin_class
        return plugin_class
    
    @classmethod
    def get_plugin_class(cls, name: str) -> Type[BasePlugin]:
        """
        Get a plugin class by name.
        
        Args:
            name: The name of the plugin to retrieve
            
        Returns:
            The plugin class
            
        Raises:
            KeyError: If no plugin with the given name is found
        """
        if name not in cls._plugins:
            raise KeyError(f"No plugin named '{name}' found")
        return cls._plugins[name]
    
    @classmethod
    def get_available_plugins(cls) -> Dict[str, Type[BasePlugin]]:
        """
        Get all registered plugins.
        
        Returns:
            Dictionary mapping plugin names to plugin classes
        """
        return cls._plugins.copy()
    
    @classmethod
    def clear_registry(cls) -> None:
        """Clear all registered plugins (for testing purposes)."""
        cls._plugins = {}


def plugin(plugin_class: Type[BasePlugin]) -> Type[BasePlugin]:
    """
    Decorator to register a plugin class.
    
    This is a convenience wrapper around PluginRegistry.register().
    
    Example:
        @plugin
        class MyPlugin(BasePlugin):
            name = "my_plugin"
            # ...
    """
    return PluginRegistry.register(plugin_class)
