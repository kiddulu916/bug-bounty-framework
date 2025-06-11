"""
Base plugin class for the Bug Bounty Framework.

This module defines the BasePlugin class that all plugins must inherit from.
"""

import abc
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Type, Set, Callable, Awaitable

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
    async def wrapper(self, *args, **kwargs):
        method_name = method.__name__
        start_time = datetime.utcnow()
        
        try:
            self.log.debug(f"Entering {method_name}")
            result = await method(self, *args, **kwargs)
            self.log.debug(f"Exiting {method_name}")
            
            # Update execution time
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            self._execution_times[method_name] = execution_time
            
            return result
            
        except Exception as e:
            self.log.error(f"Error in {method_name}: {str(e)}", exc_info=True)
            self.add_error(e)
            raise
    
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
    timeout: int = 300
    
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