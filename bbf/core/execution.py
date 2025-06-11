"""
Plugin execution management system for the Bug Bounty Framework.

This module provides functionality for managing plugin execution, including:
- Result caching
- Timeout handling
- Resource limits
- Error recovery
"""

import asyncio
import functools
import logging
import os
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union

import psutil
from cachetools import TTLCache, cached
from .exceptions import (
    PluginError,
    PluginTimeoutError,
    PluginResourceError,
    PluginExecutionError
)
from .plugin import BasePlugin, PluginRegistry
from .metadata import PluginMetadataManager

logger = logging.getLogger(__name__)

# Type variables for generic functions
T = TypeVar('T')
R = TypeVar('R')

class ExecutionContext:
    """
    Context for plugin execution.
    
    This class manages the execution environment for plugins, including:
    - Resource limits
    - Timeout settings
    - Error handling
    - Result caching
    """
    
    def __init__(
        self,
        plugin: BasePlugin,
        timeout: Optional[float] = None,
        max_memory: Optional[int] = None,
        max_cpu: Optional[float] = None,
        max_threads: Optional[int] = None,
        cache_ttl: Optional[int] = None
    ):
        """
        Initialize execution context.
        
        Args:
            plugin: The plugin to execute
            timeout: Maximum execution time in seconds
            max_memory: Maximum memory usage in bytes
            max_cpu: Maximum CPU usage (0.0 to 1.0)
            max_threads: Maximum number of threads
            cache_ttl: Cache TTL in seconds
        """
        self.plugin = plugin
        self.timeout = timeout or plugin.timeout
        self.max_memory = max_memory or (1024 * 1024 * 1024)  # 1GB default
        self.max_cpu = max_cpu or 0.8  # 80% default
        self.max_threads = max_threads or os.cpu_count() or 4
        self.cache_ttl = cache_ttl or 300  # 5 minutes default
        
        # Initialize resource tracking
        self._start_time: Optional[float] = None
        self._start_memory: Optional[int] = None
        self._process: Optional[psutil.Process] = None
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        
        # Initialize result cache
        self._cache = TTLCache(
            maxsize=1000,  # Maximum number of cached results
            ttl=self.cache_ttl
        )
    
    async def __aenter__(self):
        """Set up execution context."""
        # Start resource tracking
        self._start_time = time.monotonic()
        self._process = psutil.Process()
        self._start_memory = self._process.memory_info().rss
        self._thread_pool = ThreadPoolExecutor(max_workers=self.max_threads)
        
        # Set up timeout
        if self.timeout:
            self._timeout_task = asyncio.create_task(self._watch_timeout())
        
        # Set up resource monitoring
        self._monitor_task = asyncio.create_task(self._monitor_resources())
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up execution context."""
        # Cancel monitoring tasks
        if hasattr(self, '_timeout_task'):
            self._timeout_task.cancel()
        if hasattr(self, '_monitor_task'):
            self._monitor_task.cancel()
        
        # Clean up thread pool
        if self._thread_pool:
            self._thread_pool.shutdown(wait=False)
        
        # Update execution stats
        if self._start_time:
            execution_time = time.monotonic() - self._start_time
            success = exc_type is None
            error = str(exc_val) if exc_val else None
            
            PluginRegistry.update_execution_stats(
                self.plugin.name,
                execution_time,
                success,
                error
            )
    
    async def _watch_timeout(self):
        """Watch for execution timeout."""
        try:
            await asyncio.sleep(self.timeout)
            raise PluginTimeoutError(
                f"Plugin '{self.plugin.name}' execution timed out after {self.timeout}s"
            )
        except asyncio.CancelledError:
            pass
    
    async def _monitor_resources(self):
        """Monitor resource usage."""
        try:
            while True:
                # Check memory usage
                current_memory = self._process.memory_info().rss
                if current_memory - self._start_memory > self.max_memory:
                    raise PluginResourceError(
                        f"Plugin '{self.plugin.name}' exceeded memory limit of "
                        f"{self.max_memory / (1024 * 1024):.1f}MB"
                    )
                
                # Check CPU usage
                cpu_percent = self._process.cpu_percent() / 100.0
                if cpu_percent > self.max_cpu:
                    raise PluginResourceError(
                        f"Plugin '{self.plugin.name}' exceeded CPU limit of "
                        f"{self.max_cpu * 100:.0f}%"
                    )
                
                # Check thread count
                thread_count = self._process.num_threads()
                if thread_count > self.max_threads:
                    raise PluginResourceError(
                        f"Plugin '{self.plugin.name}' exceeded thread limit of "
                        f"{self.max_threads}"
                    )
                
                await asyncio.sleep(0.1)  # Check every 100ms
                
        except asyncio.CancelledError:
            pass
    
    def _get_cache_key(self, *args, **kwargs) -> str:
        """
        Generate cache key for function arguments.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Cache key string
        """
        # Convert args and kwargs to a stable string representation
        key_parts = [
            str(arg) for arg in args
        ] + [
            f"{k}={v}" for k, v in sorted(kwargs.items())
        ]
        return f"{self.plugin.name}:{':'.join(key_parts)}"
    
    @cached(cache=TTLCache(maxsize=1000, ttl=300))
    def _cached_execute(self, func: Callable[..., R], *args, **kwargs) -> R:
        """
        Execute function with caching.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            PluginExecutionError: If execution fails
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise PluginExecutionError(f"Plugin execution failed: {str(e)}") from e
    
    async def execute(
        self,
        func: Callable[..., R],
        *args,
        use_cache: bool = True,
        **kwargs
    ) -> R:
        """
        Execute function with resource management.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            use_cache: Whether to use result caching
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            PluginTimeoutError: If execution times out
            PluginResourceError: If resource limits are exceeded
            PluginExecutionError: If execution fails
        """
        if use_cache:
            # Try to get result from cache
            cache_key = self._get_cache_key(*args, **kwargs)
            try:
                return self._cache[cache_key]
            except KeyError:
                pass
        
        # Execute function in thread pool
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                self._thread_pool,
                functools.partial(self._cached_execute, func, *args, **kwargs)
            )
            
            # Cache result if caching is enabled
            if use_cache:
                self._cache[cache_key] = result
            
            return result
            
        except asyncio.CancelledError:
            raise PluginTimeoutError(
                f"Plugin '{self.plugin.name}' execution was cancelled"
            )
        except Exception as e:
            if isinstance(e, (PluginTimeoutError, PluginResourceError)):
                raise
            raise PluginExecutionError(f"Plugin execution failed: {str(e)}") from e

class ExecutionManager:
    """
    Manages plugin execution.
    
    This class provides a central interface for executing plugins with:
    - Resource management
    - Timeout handling
    - Result caching
    - Error recovery
    """
    
    _instance = None
    _contexts: Dict[str, ExecutionContext] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    async def execute_plugin(
        cls,
        plugin: BasePlugin,
        *args,
        timeout: Optional[float] = None,
        max_memory: Optional[int] = None,
        max_cpu: Optional[float] = None,
        max_threads: Optional[int] = None,
        cache_ttl: Optional[int] = None,
        use_cache: bool = True,
        **kwargs
    ) -> Any:
        """
        Execute a plugin with resource management.
        
        Args:
            plugin: Plugin to execute
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
        # Create execution context
        context = ExecutionContext(
            plugin,
            timeout=timeout,
            max_memory=max_memory,
            max_cpu=max_cpu,
            max_threads=max_threads,
            cache_ttl=cache_ttl
        )
        
        # Store context
        cls._contexts[plugin.name] = context
        
        try:
            async with context:
                # Execute plugin
                return await context.execute(
                    plugin.execute,
                    *args,
                    use_cache=use_cache,
                    **kwargs
                )
        finally:
            # Remove context
            cls._contexts.pop(plugin.name, None)
    
    @classmethod
    def get_context(cls, plugin_name: str) -> Optional[ExecutionContext]:
        """
        Get execution context for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Execution context if found, None otherwise
        """
        return cls._contexts.get(plugin_name)
    
    @classmethod
    def cancel_execution(cls, plugin_name: str) -> None:
        """
        Cancel plugin execution.
        
        Args:
            plugin_name: Name of the plugin to cancel
            
        Raises:
            PluginError: If plugin is not being executed
        """
        context = cls.get_context(plugin_name)
        if not context:
            raise PluginError(f"Plugin '{plugin_name}' is not being executed")
        
        # Cancel timeout and monitoring tasks
        if hasattr(context, '_timeout_task'):
            context._timeout_task.cancel()
        if hasattr(context, '_monitor_task'):
            context._monitor_task.cancel()
        
        # Shutdown thread pool
        if context._thread_pool:
            context._thread_pool.shutdown(wait=False)
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear all execution caches."""
        for context in cls._contexts.values():
            context._cache.clear() 