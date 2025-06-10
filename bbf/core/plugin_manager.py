"""
Plugin Manager for the Bug Bounty Framework.

This module provides functionality to discover, load, and manage plugins.
"""

import importlib
import importlib.util
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Type, TypeVar, Any

from bbf.core.plugin import BasePlugin
from bbf.core.exceptions import (
    PluginError,
    PluginLoadError,
    PluginValidationError
)

logger = logging.getLogger(__name__)

# Type variable for plugin classes
T = TypeVar('T', bound=BasePlugin)


class PluginManager:
    """
    Manages the loading and instantiation of plugins.
    """
    
    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initialize the PluginManager.
        
        Args:
            plugin_dirs: List of directories to search for plugins.
        """
        self.plugin_dirs = plugin_dirs or []
        self._discovered_plugins: Dict[str, Type[BasePlugin]] = {}
        self._loaded_plugins: Dict[str, BasePlugin] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """
        Initialize the plugin manager and discover plugins.
        """
        if self._initialized:
            return
            
        logger.info("Initializing plugin manager")
        
        # Discover plugins from all plugin directories
        for plugin_dir in self.plugin_dirs:
            await self.discover_plugins(plugin_dir)
        
        # Also discover plugins from the built-in plugins package
        try:
            import bbf.plugins
            await self.discover_package(bbf.plugins)
        except ImportError:
            logger.warning("Built-in plugins package not found")
        
        self._initialized = True
        logger.info(f"Discovered {len(self._discovered_plugins)} plugins")
    
    async def discover_plugins(self, plugin_dir: str) -> None:
        """
        Discover plugins in the specified directory.
        
        Args:
            plugin_dir: Directory path to search for plugins.
        """
        plugin_path = Path(plugin_dir)
        
        if not plugin_path.exists():
            logger.warning(f"Plugin directory not found: {plugin_dir}")
            return
        
        if not plugin_path.is_dir():
            logger.warning(f"Plugin path is not a directory: {plugin_dir}")
            return
        
        logger.debug(f"Discovering plugins in {plugin_dir}")
        
        # Import all Python files in the directory
        for file_path in plugin_path.glob("*.py"):
            if file_path.name.startswith('_'):
                continue
                
            module_name = file_path.stem
            
            try:
                spec = importlib.util.spec_from_file_location(
                    f"bbf.plugins.{module_name}",
                    file_path
                )
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load spec for {file_path}")
                
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Discover plugins in the imported module
                await self._discover_plugins_in_module(module)
                
            except Exception as e:
                logger.error(f"Error loading plugin from {file_path}: {e}", exc_info=True)
    
    async def discover_package(self, package) -> None:
        """
        Discover plugins in a Python package.
        
        Args:
            package: The package to search for plugins.
        """
        logger.debug(f"Discovering plugins in package: {package.__name__}")
        
        # Handle both namespace packages and regular packages
        if hasattr(package, '__path__'):
            for _, name, _ in pkgutil.iter_modules(package.__path__, package.__name__ + '.'):
                try:
                    module = importlib.import_module(name)
                    await self._discover_plugins_in_module(module)
                except Exception as e:
                    logger.error(f"Error importing module {name}: {e}", exc_info=True)
    
    async def _discover_plugins_in_module(self, module) -> None:
        """
        Discover plugins in a module.
        
        Args:
            module: The module to search for plugins.
        """
        for name, obj in inspect.getmembers(module):
            if (
                inspect.isclass(obj)
                and issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and not inspect.isabstract(obj)
            ):
                await self.register_plugin(obj)
    
    async def register_plugin(self, plugin_class: Type[BasePlugin]) -> None:
        """
        Register a plugin class.
        
        Args:
            plugin_class: The plugin class to register.
            
        Raises:
            PluginValidationError: If the plugin is invalid.
        """
        if not hasattr(plugin_class, 'name') or not plugin_class.name:
            raise PluginValidationError(
                f"Plugin class {plugin_class.__name__} is missing a 'name' attribute"
            )
        
        plugin_name = plugin_class.name
        
        if plugin_name in self._discovered_plugins:
            existing_plugin = self._discovered_plugins[plugin_name]
            if existing_plugin is not plugin_class:
                logger.warning(
                    f"Plugin name '{plugin_name}' is already registered by "
                    f"{existing_plugin.__module__}.{existing_plugin.__name__}. "
                    f"Skipping {plugin_class.__module__}.{plugin_class.__name__}."
                )
            return
        
        logger.debug(f"Discovered plugin: {plugin_name} ({plugin_class.__name__})")
        self._discovered_plugins[plugin_name] = plugin_class
    
    async def get_plugin(self, plugin_name: str, config: Optional[Dict[str, Any]] = None) -> BasePlugin:
        """
        Get an instance of a plugin by name.
        
        Args:
            plugin_name: The name of the plugin to get.
            config: Optional configuration for the plugin.
            
        Returns:
            An instance of the requested plugin.
            
        Raises:
            PluginError: If the plugin is not found or cannot be instantiated.
        """
        if not self._initialized:
            await self.initialize()
        
        # Return cached instance if available
        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]
        
        # Get the plugin class
        plugin_class = self._discovered_plugins.get(plugin_name)
        if not plugin_class:
            raise PluginError(f"Plugin not found: {plugin_name}")
        
        try:
            # Create a new instance of the plugin
            plugin = plugin_class(config or {})
            await plugin.initialize()
            self._loaded_plugins[plugin_name] = plugin
            return plugin
        except Exception as e:
            raise PluginLoadError(
                f"Failed to load plugin {plugin_name}: {str(e)}"
            ) from e
    
    async def get_plugins_by_type(self, base_class: Type[T]) -> Dict[str, T]:
        """
        Get all plugins that are subclasses of the specified base class.
        
        Args:
            base_class: The base class to filter plugins by.
            
        Returns:
            A dictionary of plugin names to plugin instances.
        """
        if not self._initialized:
            await self.initialize()
        
        plugins: Dict[str, T] = {}
        
        for name, plugin_class in self._discovered_plugins.items():
            if (
                issubclass(plugin_class, base_class)
                and plugin_class is not base_class
            ):
                try:
                    plugin = await self.get_plugin(name)
                    plugins[name] = plugin
                except PluginError as e:
                    logger.error(f"Failed to load plugin {name}: {e}")
        
        return plugins
    
    async def get_available_plugins(self) -> Set[str]:
        """
        Get a set of all available plugin names.
        
        Returns:
            A set of plugin names.
        """
        if not self._initialized:
            await self.initialize()
            
        return set(self._discovered_plugins.keys())
    
    async def close(self) -> None:
        """
        Clean up resources used by plugins.
        """
        for plugin in self._loaded_plugins.values():
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin {plugin.name}: {e}", exc_info=True)
        
        self._loaded_plugins.clear()
        self._discovered_plugins.clear()
        self._initialized = False
