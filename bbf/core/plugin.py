"""
Base plugin system for the Bug Bounty Framework.

This module defines the BasePlugin class that all plugins must inherit from,
and provides the plugin registration mechanism.
"""

import abc
import inspect
import logging
import time
import sys
from typing import Dict, List, Optional, Any, Type, Set, Callable, Awaitable, Union
from datetime import datetime

from bbf.core.exceptions import (
    PluginError,
    PluginValidationError,
    PluginDependencyError
)

logger = logging.getLogger(__name__)

# Type alias for plugin methods that can be wrapped with timing and error handling
PluginMethod = Callable[..., Awaitable[Any]]


def plugin_method(method: PluginMethod) -> PluginMethod:
    """
    Decorator for plugin methods that adds timing, error handling, and logging.
    
    This decorator should be applied to all public plugin methods that perform operations.
    It automatically:
    - Logs method entry/exit
    - Tracks execution time
    - Handles exceptions consistently
    - Updates plugin state
    
    Args:
        method: The plugin method to wrap
        
    Returns:
        The wrapped method with additional functionality
    """
    async def wrapper(self: 'BasePlugin', *args, **kwargs):
        method_name = method.__name__
        self.log.debug(f"Starting {method_name}")
        start_time = time.time()
        
        try:
            # Update plugin state
            self._last_execution = datetime.utcnow()
            self._status = f"running_{method_name}"
            
            # Execute the method
            result = await method(self, *args, **kwargs)
            
            # Update state on success
            self._status = "completed"
            self._last_success = datetime.utcnow()
            
            return result
            
        except Exception as e:
            # Log the error and update state
            self.log.error(f"Error in {method_name}: {str(e)}", exc_info=True)
            self._status = f"error_{method_name}"
            self._errors.append({
                'method': method_name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            raise  # Re-raise the exception
            
        finally:
            # Update execution time
            execution_time = time.time() - start_time
            self._execution_times[method_name] = execution_time
            self.log.debug(f"Completed {method_name} in {execution_time:.2f}s")
    
    # Preserve the original method's name and docstring
    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class BasePlugin(metaclass=abc.ABCMeta):
    """
    Base class for all plugins in the Bug Bounty Framework.
    
    All plugins must inherit from this class and implement the required methods.
    Plugins are the core building blocks of the framework and provide specific
    functionality for different stages of security testing.
    
    Attributes:
        name: Unique identifier for the plugin (required)
        description: Human-readable description of the plugin's purpose
        version: Plugin version string (semver recommended)
        enabled: Whether the plugin is enabled (can be overridden in config)
        required_ports: List of ports this plugin needs
        required_protocols: List of protocols this plugin uses (http, https, dns, etc.)
        depends_on: List of plugin names that must run before this one
        timeout: Maximum execution time in seconds (0 for no timeout)
    """
    
    # Plugin metadata (must be overridden by subclasses)
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
            config: Dictionary containing plugin configuration. This will be
                   merged with any default configuration defined in the class.
                   The following special keys are recognized:
                   - enabled: Override the plugin's enabled state
                   - timeout: Override the default timeout
        """
        # Initialize state
        self._initialized = False
        self._status = "created"
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._errors: List[Dict[str, str]] = []
        self._warnings: List[str] = []
        self._results: Dict[str, Any] = {}
        self._execution_times: Dict[str, float] = {}
        self._dependencies_met = False
        
        # Set up logger for this plugin instance
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Process configuration
        self.config = self._process_config(config or {})
        
        # Apply configuration overrides
        if 'enabled' in self.config:
            self.enabled = bool(self.config['enabled'])
        if 'timeout' in self.config:
            self.timeout = int(self.config['timeout'] or 0)
        
        # Initialize metrics
        self._metrics = {
            'start_time': None,
            'end_time': None,
            'execution_count': 0,
            'success_count': 0,
            'error_count': 0,
            'average_time': 0.0,
            'last_error': None
        }
    
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

    def _process_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and validate plugin configuration.
        
        This method can be overridden by subclasses to implement custom
        configuration processing and validation.
        
        Args:
            config: Raw configuration dictionary
            
        Returns:
            Processed configuration dictionary
            
        Raises:
            PluginValidationError: If the configuration is invalid
        """
        # Default implementation just returns a copy of the config
        return config.copy()
    
    async def initialize(self) -> None:
        """
        Initialize the plugin.
        
        This method is called once when the plugin is first loaded.
        It should be used to set up any required resources.
        
        Raises:
            PluginError: If initialization fails
        """
        if self._initialized:
            return
            
        self._status = "initializing"
        self._start_time = datetime.utcnow()
        
        try:
            # Verify required attributes
            if not self.name or self.name == "base_plugin":
                raise PluginValidationError("Plugin must define a unique 'name' attribute")
                
            # Initialize metrics
            self._metrics['start_time'] = self._start_time.isoformat()
            self._metrics['execution_count'] = 0
            
            self._initialized = True
            self._status = "initialized"
            self.log.info(f"Initialized plugin: {self.name} v{self.version}")
            
        except Exception as e:
            self._status = "initialization_failed"
            self._errors.append({
                'method': 'initialize',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            self.log.error(f"Failed to initialize plugin: {e}", exc_info=True)
            raise PluginError(f"Plugin initialization failed: {e}") from e
    
    async def check_dependencies(self, available_plugins: Set[str]) -> bool:
        """
        Check if all plugin dependencies are met.
        
        Args:
            available_plugins: Set of available plugin names
            
        Returns:
            bool: True if all dependencies are met, False otherwise
            
        Raises:
            PluginDependencyError: If required dependencies are missing
        """
        if not self.depends_on:
            self._dependencies_met = True
            return True
            
        missing = [dep for dep in self.depends_on if dep not in available_plugins]
        
        if missing:
            error_msg = f"Missing dependencies: {', '.join(missing)}"
            self._status = "missing_dependencies"
            self._errors.append({
                'method': 'check_dependencies',
                'error': error_msg,
                'timestamp': datetime.utcnow().isoformat()
            })
            raise PluginDependencyError(error_msg)
        
        self._dependencies_met = True
        return True
    
    @abc.abstractmethod
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the plugin's main functionality.
        
        This method must be implemented by all plugins. It should contain
        the core logic of the plugin.
        
        Args:
            target: The target to test (e.g., domain, IP, URL)
            **kwargs: Additional arguments specific to the plugin
            
        Returns:
            Dictionary containing the results of the plugin's execution
            
        Raises:
            PluginError: If execution fails
        """
        raise NotImplementedError("Plugin must implement execute() method")
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the plugin.
        
        This method is called when the plugin is being unloaded or when
        the framework is shutting down. It should be used to release any
        resources (e.g., file handles, network connections) that the plugin
        has acquired.
        """
        self._end_time = datetime.utcnow()
        self._status = "cleaned_up"
        
        if self._start_time and self._end_time:
            execution_time = (self._end_time - self._start_time).total_seconds()
            self._metrics['end_time'] = self._end_time.isoformat()
            self._metrics['average_time'] = (
                (self._metrics['average_time'] * (self._metrics['execution_count'] - 1) + execution_time) /
                self._metrics['execution_count']
                if self._metrics['execution_count'] > 0 else execution_time
            )
    
    @property
    def status(self) -> str:
        """Get the current status of the plugin."""
        return self._status
    
    @property
    def metrics(self) -> Dict[str, Any]:
        """Get performance metrics for the plugin."""
        return self._metrics.copy()
    
    @property
    def errors(self) -> List[Dict[str, str]]:
        """Get a list of errors that occurred during plugin execution."""
        return self._errors.copy()
    
    @property
    def results(self) -> Dict[str, Any]:
        """Get the results of the plugin's execution."""
        return self._results.copy()
    
    def add_result(self, key: str, value: Any) -> None:
        """
        Add a result to the plugin's results.
        
        Args:
            key: The result key
            value: The result value
        """
        self._results[key] = value
    
    def add_error(self, error: Union[str, Exception]) -> None:
        """
        Add an error to the plugin's error list.
        
        Args:
            error: The error message or exception
        """
        error_msg = str(error)
        self._errors.append({
            'method': inspect.currentframe().f_back.f_code.co_name,
            'error': error_msg,
            'timestamp': datetime.utcnow().isoformat()
        })
        self._metrics['error_count'] += 1
        self._metrics['last_error'] = error_msg
        self.log.error(f"Error in {self.name}: {error_msg}", exc_info=isinstance(error, Exception))


class PluginRegistry:
    """
    Registry for managing plugin classes.
    
    This class implements the singleton pattern to maintain a global registry
    of all available plugins. Plugins are registered using the @plugin decorator.
    """
    
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
            PluginValidationError: If the plugin is invalid or a plugin with
                                the same name is already registered
        """
        if not inspect.isclass(plugin_class):
            raise PluginValidationError(f"Plugin must be a class, got {type(plugin_class)}")
            
        if not issubclass(plugin_class, BasePlugin):
            raise PluginValidationError(
                f"Plugin {plugin_class.__name__} must inherit from BasePlugin"
            )
            
        if plugin_class is BasePlugin:
            raise PluginValidationError("Cannot register BasePlugin class itself")
            
        if not hasattr(plugin_class, 'name') or not plugin_class.name:
            raise PluginValidationError(
                f"Plugin class {plugin_class.__name__} must define a 'name' attribute"
            )
            
        plugin_name = plugin_class.name
        
        # Validate plugin name format
        if not isinstance(plugin_name, str) or not plugin_name.replace('_', '').isalnum():
            raise PluginValidationError(
                f"Plugin name '{plugin_name}' must contain only alphanumeric "
                "characters and underscores"
            )
        
        # Check for duplicate plugin names
        if plugin_name in cls._plugins:
            existing_plugin = cls._plugins[plugin_name]
            if existing_plugin is not plugin_class:
                raise PluginValidationError(
                    f"Plugin name '{plugin_name}' is already registered by "
                    f"{existing_plugin.__module__}.{existing_plugin.__name__}"
                )
        
        # Register the plugin
        cls._plugins[plugin_name] = plugin_class
        logger.debug(
            f"Registered plugin: {plugin_name} "
            f"({plugin_class.__module__}.{plugin_class.__name__})"
        )
            
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
            raise KeyError(f"No plugin found with name: {name}")
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
    def clear_registry(cls):
        """Clear all registered plugins (for testing purposes)."""
        cls._plugins = {}
        logger.debug("Plugin registry cleared")


def plugin(plugin_class: Type[BasePlugin]) -> Type[BasePlugin]:
    """
    Decorator to register a plugin class.
    
    This is a convenience wrapper around PluginRegistry.register() that should
    be used as a class decorator to register plugin classes.
    
    Example:
        @plugin
        class MyPlugin(BasePlugin):
            name = "my_plugin"
            description = "My custom plugin"
            version = "1.0.0"
            
            async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
                # Plugin logic here
                return {"result": "success"}
    
    Args:
        plugin_class: The plugin class to register
        
    Returns:
        The registered plugin class
        
    Raises:
        PluginValidationError: If the plugin is invalid or a plugin with
                            the same name is already registered
    """
    return PluginRegistry.register(plugin_class)


def get_plugin(name: str) -> Type[BasePlugin]:
    """
    Get a plugin class by name.
    
    Args:
        name: The name of the plugin to retrieve
        
    Returns:
        The plugin class
        
    Raises:
        KeyError: If no plugin with the given name is found
    """
    return PluginRegistry.get_plugin_class(name)


def get_available_plugins() -> Dict[str, Type[BasePlugin]]:
    """
    Get all registered plugins.
    
    Returns:
        Dictionary mapping plugin names to plugin classes
    """
    return PluginRegistry.get_available_plugins()


def clear_plugin_registry() -> None:
    """
    Clear all registered plugins.
    
    This is primarily useful for testing purposes.
    """
    PluginRegistry.clear_registry()
