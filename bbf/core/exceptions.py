"""
Custom exceptions for the Bug Bounty Framework.

This module defines all custom exceptions used throughout the framework.
"""

__all__ = [
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

class BBFError(Exception):
    """Base exception for all BBF errors."""
    pass

# Plugin-related exceptions
class PluginError(BBFError):
    """Base exception for plugin-related errors."""
    pass

class PluginDependencyError(PluginError):
    """Raised when a plugin has unmet dependencies."""
    pass

class PluginExecutionError(PluginError):
    """Raised when a plugin fails during execution."""
    pass

class PluginLoadError(PluginError):
    """Raised when a plugin fails to load."""
    pass

class PluginValidationError(PluginError):
    """Raised when a plugin fails validation."""
    pass

class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not found."""
    pass

# Stage-related exceptions
class StageError(BBFError):
    """Base exception for stage-related errors."""
    pass

class StageExecutionError(StageError):
    """Raised when a stage fails during execution."""
    pass

class StageNotEnabledError(StageError):
    """Raised when trying to execute a disabled stage."""
    pass

# State management exceptions
class StateError(BBFError):
    """Raised for state management related errors."""
    pass

class StateLoadError(StateError):
    """Raised when there's an error loading state."""
    pass

class StateSaveError(StateError):
    """Raised when there's an error saving state."""
    pass

# Configuration exceptions
class ConfigurationError(BBFError):
    """Raised for configuration related errors."""
    pass

class ConfigurationValidationError(ConfigurationError):
    """Raised when configuration validation fails."""
    pass

# Framework exceptions
class FrameworkError(BBFError):
    """Base exception for framework-level errors."""
    pass

class InitializationError(FrameworkError):
    """Raised when the framework fails to initialize."""
    pass

class ShutdownError(FrameworkError):
    """Raised when there's an error during framework shutdown."""
    pass
