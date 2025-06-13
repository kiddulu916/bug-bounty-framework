"""
Base classes for the bug bounty framework.

This module contains the base classes that define the core interfaces
and functionality for plugins, stages, and services.
"""

import abc
import logging
import inspect
from datetime import datetime, UTC
from typing import Dict, List, Optional, Any, Type, Set, Callable, Awaitable, Union

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
        start_time = datetime.now(UTC)
        
        try:
            self.log.debug(f"Entering {method_name}")
            result = await method(self, *args, **kwargs)
            self.log.debug(f"Exiting {method_name}")
            
            # Update execution time
            end_time = datetime.now(UTC)
            execution_time = (end_time - start_time).total_seconds()
            self._execution_times[method_name] = execution_time
            
            return result
            
        except Exception as e:
            self.log.error(f"Error in {method_name}: {str(e)}", exc_info=True)
            self.add_error(e)
            raise
    
    return wrapper


class BaseService(abc.ABC):
    """Base class for all services in the framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._initialized = False
    
    @abc.abstractmethod
    async def initialize(self) -> None:
        """Initialize the service."""
        pass
    
    @abc.abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources used by the service."""
        pass
    
    @property
    def is_initialized(self) -> bool:
        """Check if the service is initialized."""
        return self._initialized


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
            'timestamp': datetime.now(UTC).isoformat()
        })
        self._metrics['error_count'] += 1
        self._metrics['last_error'] = error_msg
        self.log.error(f"Error in {self.name}: {error_msg}", exc_info=isinstance(error, Exception))
    
    @property
    def results(self) -> Dict[str, Any]:
        """Get the plugin's results."""
        return self._results.copy()
    
    @property
    def errors(self) -> List[Dict[str, str]]:
        """Get the plugin's errors."""
        return self._errors.copy()
    
    @property
    def state(self) -> Dict[str, Any]:
        """Get the plugin's state."""
        return {
            'status': self._status,
            'initialized': self._initialized,
            'dependencies_met': self._dependencies_met,
            'start_time': self._start_time.isoformat() if self._start_time else None,
            'end_time': self._end_time.isoformat() if self._end_time else None,
            'metrics': self._metrics.copy()
        }
    
    @state.setter
    def state(self, value: Dict[str, Any]) -> None:
        """Set the plugin's state."""
        self._status = value.get('status', self._status)
        self._initialized = value.get('initialized', self._initialized)
        self._dependencies_met = value.get('dependencies_met', self._dependencies_met)
        if 'start_time' in value and value['start_time']:
            self._start_time = datetime.fromisoformat(value['start_time'])
        if 'end_time' in value and value['end_time']:
            self._end_time = datetime.fromisoformat(value['end_time'])
        if 'metrics' in value:
            self._metrics.update(value['metrics'])
    
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
        self._start_time = datetime.now(UTC)
        
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
                'timestamp': datetime.now(UTC).isoformat()
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
                'timestamp': datetime.now(UTC).isoformat()
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
        self._end_time = datetime.now(UTC)
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


class BaseStage(abc.ABC):
    """Base class for all stages in the framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._plugins: List[BasePlugin] = []
        self._initialized = False
        self._execution_count = 0
        self._last_execution: Optional[datetime] = None
        self._execution_times: List[float] = []
    
    @abc.abstractmethod
    async def initialize(self) -> None:
        """Initialize the stage."""
        pass
    
    @abc.abstractmethod
    async def execute(self, target: Any, **kwargs) -> Any:
        """Execute the stage."""
        pass
    
    @abc.abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources used by the stage."""
        pass
    
    async def add_plugin(self, plugin: BasePlugin) -> None:
        """Add a plugin to the stage."""
        self._plugins.append(plugin)
    
    async def remove_plugin(self, plugin: BasePlugin) -> None:
        """Remove a plugin from the stage."""
        self._plugins.remove(plugin)
    
    @property
    def plugins(self) -> List[BasePlugin]:
        """Get the list of plugins in this stage."""
        return self._plugins.copy()
    
    @property
    def is_initialized(self) -> bool:
        """Check if the stage is initialized."""
        return self._initialized
    
    @property
    def execution_count(self) -> int:
        """Get the number of times this stage has been executed."""
        return self._execution_count
    
    @property
    def last_execution(self) -> Optional[datetime]:
        """Get the timestamp of the last execution."""
        return self._last_execution
    
    @property
    def average_execution_time(self) -> float:
        """Get the average execution time of this stage."""
        if not self._execution_times:
            return 0.0
        return sum(self._execution_times) / len(self._execution_times) 