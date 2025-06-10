"""
Core components of the Bug Bounty Framework.

This package contains the fundamental building blocks of the framework,
including the plugin system, stage management, and core utilities.
"""

from .exceptions import (
    BBFError,
    PluginError,
    PluginDependencyError,
    PluginExecutionError,
    PluginLoadError,
    PluginValidationError,
    PluginNotFoundError,
    StageError,
    StageExecutionError,
    StageNotEnabledError,
    StateError,
    StateLoadError,
    StateSaveError,
    ConfigurationError,
    ConfigurationValidationError,
    FrameworkError,
    InitializationError,
    ShutdownError,
)

from .plugin import BasePlugin, plugin, get_plugin, get_available_plugins, clear_plugin_registry
from .plugin_manager import PluginManager
from .framework import BFFramework
from .state import StateManager

# Export all exceptions and core components
__all__ = [
    # Core classes
    'BasePlugin',
    'BFFramework',
    'PluginManager',
    'StateManager',
    
    # Plugin utilities
    'plugin',
    'get_plugin',
    'get_available_plugins',
    'clear_plugin_registry',
    
    # Base exceptions
    'BBFError',
    
    # Plugin-related exceptions
    'PluginError',
    'PluginDependencyError',
    'PluginExecutionError',
    'PluginLoadError',
    'PluginValidationError',
    'PluginNotFoundError',
    
    # Stage-related exceptions
    'StageError',
    'StageExecutionError',
    'StageNotEnabledError',
    
    # State management exceptions
    'StateError',
    'StateLoadError',
    'StateSaveError',
    
    # Configuration exceptions
    'ConfigurationError',
    'ConfigurationValidationError',
    
    # Framework exceptions
    'FrameworkError',
    'InitializationError',
    'ShutdownError',
]
