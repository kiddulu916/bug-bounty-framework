"""
Base plugin class for the Bug Bounty Framework.

This module defines the base class that all plugins must inherit from.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Type, TypeVar

from ..core.exceptions import (
    PluginError,
    PluginTimeoutError,
    PluginResourceError,
    PluginExecutionError
)
from ..core.execution import ExecutionManager

logger = logging.getLogger(__name__)

T = TypeVar('T')

class BasePlugin(ABC):
    """
    Base class for all plugins.
    
    This class defines the interface that all plugins must implement.
    It provides common functionality for:
    - Plugin lifecycle management
    - Resource management
    - Error handling
    - Result caching
    """
    
    # Plugin metadata
    name: str
    version: str
    description: str
    enabled: bool = True
    required_ports: Set[int] = set()
    required_protocols: Set[str] = set()
    depends_on: Set[str] = set()
    timeout: Optional[float] = None
    
    def __init__(self):
        """Initialize plugin."""
        if not hasattr(self, 'name'):
            raise PluginError("Plugin must have a name")
        if not hasattr(self, 'version'):
            raise PluginError("Plugin must have a version")
        if not hasattr(self, 'description'):
            raise PluginError("Plugin must have a description")
    
    @abstractmethod
    async def setup(self) -> None:
        """
        Set up plugin resources.
        
        This method is called before plugin execution to set up any
        required resources. It should be implemented by subclasses.
        
        Raises:
            PluginError: If setup fails
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """
        Clean up plugin resources.
        
        This method is called after plugin execution to clean up any
        resources. It should be implemented by subclasses.
        
        Raises:
            PluginError: If cleanup fails
        """
        pass
    
    @abstractmethod
    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        """
        Execute plugin functionality.
        
        This method implements the main plugin functionality. It should
        be implemented by subclasses.
        
        Args:
            *args: Positional arguments for plugin execution
            **kwargs: Keyword arguments for plugin execution
            
        Returns:
            Plugin execution result
            
        Raises:
            PluginError: If execution fails
        """
        pass
    
    async def run(
        self,
        *args: Any,
        timeout: Optional[float] = None,
        max_memory: Optional[int] = None,
        max_cpu: Optional[float] = None,
        max_threads: Optional[int] = None,
        cache_ttl: Optional[int] = None,
        use_cache: bool = True,
        **kwargs: Any
    ) -> Any:
        """
        Run plugin with resource management.
        
        This method:
        1. Sets up plugin resources
        2. Executes plugin functionality
        3. Cleans up plugin resources
        4. Manages resources and timeouts
        5. Handles caching
        
        Args:
            *args: Positional arguments for plugin execution
            timeout: Maximum execution time in seconds
            max_memory: Maximum memory usage in bytes
            max_cpu: Maximum CPU usage (0.0 to 1.0)
            max_threads: Maximum number of threads
            cache_ttl: Cache TTL in seconds
            use_cache: Whether to use result caching
            **kwargs: Keyword arguments for plugin execution
            
        Returns:
            Plugin execution result
            
        Raises:
            PluginTimeoutError: If execution times out
            PluginResourceError: If resource limits are exceeded
            PluginExecutionError: If execution fails
        """
        try:
            # Set up plugin
            await self.setup()
            
            # Execute plugin with resource management
            return await ExecutionManager.execute_plugin(
                self,
                *args,
                timeout=timeout,
                max_memory=max_memory,
                max_cpu=max_cpu,
                max_threads=max_threads,
                cache_ttl=cache_ttl,
                use_cache=use_cache,
                **kwargs
            )
            
        except Exception as e:
            if isinstance(e, (PluginTimeoutError, PluginResourceError, PluginExecutionError)):
                raise
            raise PluginExecutionError(f"Plugin execution failed: {str(e)}") from e
            
        finally:
            # Clean up plugin
            try:
                await self.cleanup()
            except Exception as e:
                logger.error(f"Plugin cleanup failed: {e}")
    
    def cancel(self) -> None:
        """
        Cancel plugin execution.
        
        This method cancels the current plugin execution if it is running.
        
        Raises:
            PluginError: If plugin is not being executed
        """
        ExecutionManager.cancel_execution(self.name)
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear plugin result cache."""
        ExecutionManager.clear_cache() 