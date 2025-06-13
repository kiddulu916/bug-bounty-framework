"""
Base plugin system for the Bug Bounty Framework.

This module provides the plugin registration mechanism and utility functions.
The BasePlugin class is defined in base.py to avoid circular imports.
"""

import abc
import inspect
import logging
import time
import sys
import importlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, Set, Callable, Awaitable, Union
from datetime import datetime, UTC

from bbf.core.exceptions import (
    PluginError,
    PluginValidationError,
    PluginDependencyError
)
from bbf.core.validation import validate_plugin
from bbf.core.metadata_manager import PluginMetadataManager
from bbf.core.base import BasePlugin

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
            self._last_execution = datetime.now(UTC)
            self._status = f"running_{method_name}"
            
            # Execute the method
            result = await method(self, *args, **kwargs)
            
            # Update state on success
            self._status = "completed"
            self._last_success = datetime.now(UTC)
            
            return result
            
        except Exception as e:
            # Log the error and update state
            self.log.error(f"Error in {method_name}: {str(e)}", exc_info=True)
            self._status = f"error_{method_name}"
            self._errors.append({
                'method': method_name,
                'error': str(e),
                'timestamp': datetime.now(UTC).isoformat()
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

class PluginRegistry:
    """
    Registry for managing plugin registration and discovery.
    
    This class provides functionality for:
    - Registering and unregistering plugins
    - Discovering and loading plugins
    - Managing plugin dependencies
    - Managing plugin metadata
    """
    
    _instance = None
    _plugins: Dict[str, Type[BasePlugin]] = {}
    _enabled_plugins: Set[str] = set()
    _plugin_metadata: PluginMetadataManager = PluginMetadataManager()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def register(cls, plugin_class: Type[BasePlugin]) -> None:
        """
        Register a plugin class with the registry.
        
        Args:
            plugin_class: The plugin class to register
            
        Raises:
            PluginError: If the plugin is already registered or validation fails
        """
        if not issubclass(plugin_class, BasePlugin):
            raise PluginError(f"{plugin_class.__name__} must inherit from BasePlugin")
            
        plugin_name = plugin_class.name
        if plugin_name in cls._plugins:
            raise PluginError(f"Plugin {plugin_name} is already registered")
            
        # Validate the plugin
        if not validate_plugin(plugin_class):
            raise PluginValidationError(f"Plugin {plugin_name} failed validation")
            
        # Register the plugin
        cls._plugins[plugin_name] = plugin_class
        if plugin_class.enabled:
            cls._enabled_plugins.add(plugin_name)
            
        # Update metadata
        cls._plugin_metadata.update_plugin(plugin_name, {
            'version': plugin_class.version,
            'description': plugin_class.description,
            'dependencies': plugin_class.depends_on,
            'required_ports': plugin_class.required_ports,
            'required_protocols': plugin_class.required_protocols
        })
        
        logger.info(f"Registered plugin: {plugin_name} v{plugin_class.version}")
    
    @classmethod
    def unregister(cls, plugin_name: str) -> None:
        """
        Unregister a plugin from the registry.
        
        Args:
            plugin_name: Name of the plugin to unregister
            
        Raises:
            PluginError: If the plugin is not registered
        """
        if plugin_name not in cls._plugins:
            raise PluginError(f"Plugin {plugin_name} is not registered")
            
        # Remove from registry
        del cls._plugins[plugin_name]
        cls._enabled_plugins.discard(plugin_name)
        
        # Remove metadata
        cls._plugin_metadata.remove_plugin(plugin_name)
        
        logger.info(f"Unregistered plugin: {plugin_name}")
    
    @classmethod
    def get_plugin(cls, plugin_name: str) -> Optional[Type[BasePlugin]]:
        """
        Get a registered plugin class by name.
        
        Args:
            plugin_name: Name of the plugin to get
            
        Returns:
            The plugin class if found, None otherwise
        """
        return cls._plugins.get(plugin_name)
    
    @classmethod
    def get_enabled_plugins(cls) -> List[Type[BasePlugin]]:
        """
        Get all enabled plugins.
        
        Returns:
            List of enabled plugin classes
        """
        return [cls._plugins[name] for name in cls._enabled_plugins]
    
    @classmethod
    def get_plugin_metadata(cls, plugin_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin metadata dictionary if found, None otherwise
        """
        return cls._plugin_metadata.get_plugin(plugin_name)
    
    @classmethod
    def update_plugin_metadata(cls, plugin_name: str, **kwargs) -> None:
        """
        Update metadata for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            **kwargs: Metadata fields to update
            
        Raises:
            PluginError: If the plugin is not registered
        """
        if plugin_name not in cls._plugins:
            raise PluginError(f"Plugin {plugin_name} is not registered")
            
        cls._plugin_metadata.update_plugin(plugin_name, kwargs)
    
    @classmethod
    def update_execution_stats(
        cls,
        plugin_name: str,
        execution_time: float,
        success: bool,
        error: Optional[str] = None
    ) -> None:
        """
        Update execution statistics for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            execution_time: Time taken to execute in seconds
            success: Whether execution was successful
            error: Error message if execution failed
            
        Raises:
            PluginError: If the plugin is not registered
        """
        if plugin_name not in cls._plugins:
            raise PluginError(f"Plugin {plugin_name} is not registered")
            
        metadata = cls._plugin_metadata.get_plugin(plugin_name) or {}
        stats = metadata.get('execution_stats', {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'total_time': 0.0,
            'average_time': 0.0,
            'last_error': None
        })
        
        # Update stats
        stats['total_runs'] += 1
        if success:
            stats['successful_runs'] += 1
        else:
            stats['failed_runs'] += 1
            stats['last_error'] = error
            
        stats['total_time'] += execution_time
        stats['average_time'] = stats['total_time'] / stats['total_runs']
        
        # Save updated stats
        cls._plugin_metadata.update_plugin(plugin_name, {'execution_stats': stats})
    
    @classmethod
    def validate_all_metadata(cls) -> bool:
        """
        Validate metadata for all registered plugins.
        
        Returns:
            True if all metadata is valid, False otherwise
        """
        return cls._plugin_metadata.validate_all()
    
    @classmethod
    def migrate_all_metadata(cls, target_version: str) -> None:
        """
        Migrate metadata for all plugins to a new version.
        
        Args:
            target_version: Version to migrate to
            
        Raises:
            PluginError: If migration fails
        """
        try:
            cls._plugin_metadata.migrate_all(target_version)
        except Exception as e:
            raise PluginError(f"Failed to migrate metadata: {str(e)}")
    
    @classmethod
    def clear_metadata_cache(cls) -> None:
        """Clear the metadata cache."""
        cls._plugin_metadata.clear_cache()

def plugin(plugin_class: Type[BasePlugin]) -> Type[BasePlugin]:
    """
    Decorator for registering a plugin class.
    
    This decorator should be applied to all plugin classes to automatically
    register them with the plugin registry.
    
    Example:
        @plugin
        class MyPlugin(BasePlugin):
            name = "my_plugin"
            ...
    
    Args:
        plugin_class: The plugin class to register
        
    Returns:
        The plugin class unchanged
    """
    PluginRegistry.register(plugin_class)
    return plugin_class

def get_plugin(name: str) -> Type[BasePlugin]:
    """
    Get a registered plugin class by name.
    
    Args:
        name: Name of the plugin to get
        
    Returns:
        The plugin class
        
    Raises:
        PluginError: If the plugin is not found
    """
    plugin_class = PluginRegistry.get_plugin(name)
    if plugin_class is None:
        raise PluginError(f"Plugin {name} not found")
    return plugin_class

def get_available_plugins() -> Dict[str, Type[BasePlugin]]:
    """
    Get all registered plugins.
    
    Returns:
        Dictionary mapping plugin names to plugin classes
    """
    return PluginRegistry._plugins.copy()

def clear_plugin_registry() -> None:
    """Clear all registered plugins."""
    PluginRegistry._plugins.clear()
    PluginRegistry._enabled_plugins.clear()
    PluginRegistry._plugin_metadata.clear_cache()
