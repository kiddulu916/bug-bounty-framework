"""
Custom exceptions for the Bug Bounty Framework.
"""

class BBFError(Exception):
    """Base exception for all BBF errors."""
    pass

class PluginError(BBFError):
    """Base exception for plugin-related errors."""
    pass

class PluginDependencyError(PluginError):
    """Raised when a plugin has unmet dependencies."""
    pass

class PluginExecutionError(PluginError):
    """Raised when a plugin fails during execution."""
    pass

class StageError(BBFError):
    """Base exception for stage-related errors."""
    pass

class StageExecutionError(StageError):
    """Raised when a stage fails during execution."""
    pass

class StateError(BBFError):
    """Raised for state management related errors."""
    pass

class ConfigurationError(BBFError):
    """Raised for configuration related errors."""
    pass
