"""
Base plugin class for the Bug Bounty Framework.

This module defines the BasePlugin class that all plugins must inherit from.
"""

import abc
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set, Union, Callable, Coroutine

from ..core.plugin import BasePlugin as CoreBasePlugin

logger = logging.getLogger(__name__)

class BasePlugin(CoreBasePlugin):
    """
    Base class for all Bug Bounty Framework plugins.
    
    This class extends the core BasePlugin with additional functionality
    specific to the Bug Bounty Framework.
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
        super().__init__(config or {})
        
        # Set up logger for this plugin instance
        self.log = logging.getLogger(f"bbf.plugins.{self.name}")
        
        # Plugin state
        self._state: Dict[str, Any] = {}
        self._results: Dict[str, Any] = {}
        self._errors: List[Exception] = []
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for the plugin's functionality.
        
        This method must be implemented by all plugins. It should contain
        the core logic of the plugin.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Dictionary containing the results of the plugin's execution
            
        Raises:
            PluginExecutionError: If the plugin fails to execute
        """
        try:
            # Initialize the plugin
            await self.setup()
            
            # Execute the plugin's main logic
            results = await self.execute(*args, **kwargs)
            
            # Store the results
            if results is not None:
                self._results.update(results)
            
            return self._results
            
        except Exception as e:
            self.log.error(f"Plugin {self.name} failed: {e}", exc_info=True)
            self.add_error(e)
            raise PluginExecutionError(f"Plugin {self.name} failed: {e}") from e
            
        finally:
            # Clean up resources
            await self.cleanup()
    
    @abc.abstractmethod
    async def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute the main logic of the plugin.
        
        This method must be implemented by all plugins. It should contain
        the core functionality of the plugin.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Dictionary containing the results of the plugin's execution
        """
        raise NotImplementedError("Plugin must implement the execute() method")
    
    async def setup(self) -> None:
        """
        Perform any setup required before the plugin runs.
        
        This method can be overridden by plugins that need to perform
        initialization steps before the main execution.
        """
        self.log.debug(f"Initializing plugin: {self.name}")
    
    async def cleanup(self) -> None:
        """
        Perform any cleanup after the plugin has finished running.
        
        This method can be overridden by plugins that need to perform
        cleanup operations after execution.
        """
        self.log.debug(f"Cleaning up plugin: {self.name}")
    
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
