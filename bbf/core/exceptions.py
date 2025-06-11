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
    'PluginTimeoutError',
    'PluginResourceError',
    'PluginVersionError',
    'PluginSecurityError',
    'PluginMetadataError',
    'PluginCacheError',
    'PluginStateError',
    'PluginConfigError',
    'PluginDiscoveryError',
    'PluginLoadingError',
    'PluginUnloadingError',
    'PluginRegistrationError',
    'PluginUnregistrationError',
    
    # Stage-related exceptions
    'StageError',
    'StageExecutionError',
    'StageNotEnabledError',
    'StageValidationError',
    
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

    # Service-related exceptions
    'ServiceError',
    'ServiceRegistrationError',
    'ServiceDiscoveryError',
    'ServiceHealthError',
    'ServiceConfigError',

    # Security-related exceptions
    'SecurityError',
    'AuthenticationError',
    'AuthorizationError',
    'RateLimitError',
    'ValidationError',
    'AuditError',

    # Integration-related exceptions
    'IntegrationError',
    'ServiceConnectionError',
    'ServiceTimeoutError',
    'ServiceResponseError',
    'CacheError',
    'DatabaseError',
    'MessageQueueError',
    'EventBusError',

    # Marketplace-related exceptions
    'MarketplaceError',
    'PluginInstallationError',
    'PluginUpdateError',
    'PluginVerificationError',
    'PluginReviewError',
    'PluginPackageError',

    # Development tools-related exceptions
    'DevToolsError',
    'PluginTestError',
    'PluginDocError',
    'PluginProjectError',
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

class StageValidationError(StageError):
    """Raised when stage validation fails."""
    pass

class StageExecutionError(StageError):
    """Raised when stage execution fails."""
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

# Service-related exceptions
class ServiceError(Exception):
    """Base exception for service-related errors."""
    pass

class ServiceRegistrationError(ServiceError):
    """Raised when service registration fails."""
    pass

class ServiceDiscoveryError(ServiceError):
    """Raised when service discovery fails."""
    pass

class ServiceHealthError(ServiceError):
    """Raised when service health check fails."""
    pass

class ServiceConfigError(ServiceError):
    """Raised when service configuration is invalid."""
    pass

# Security-related exceptions
class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass

class AuthenticationError(SecurityError):
    """Raised when authentication fails."""
    pass

class AuthorizationError(SecurityError):
    """Raised when authorization fails."""
    pass

class RateLimitError(SecurityError):
    """Raised when rate limit is exceeded."""
    pass

class ValidationError(SecurityError):
    """Raised when input validation fails."""
    pass

class AuditError(SecurityError):
    """Raised when audit logging fails."""
    pass

# Integration-related exceptions
class IntegrationError(Exception):
    """Base exception for integration-related errors."""
    pass

class ServiceConnectionError(IntegrationError):
    """Raised when service connection fails."""
    pass

class ServiceTimeoutError(IntegrationError):
    """Raised when service request times out."""
    pass

class ServiceResponseError(IntegrationError):
    """Raised when service returns an error."""
    pass

class CacheError(IntegrationError):
    """Raised when cache operation fails."""
    pass

class DatabaseError(IntegrationError):
    """Raised when database operation fails."""
    pass

class MessageQueueError(IntegrationError):
    """Raised when message queue operation fails."""
    pass

class EventBusError(IntegrationError):
    """Raised when event bus operation fails."""
    pass

# Marketplace-related exceptions
class MarketplaceError(Exception):
    """Base exception for marketplace-related errors."""
    pass

class PluginInstallationError(MarketplaceError):
    """Raised when plugin installation fails."""
    pass

class PluginUpdateError(MarketplaceError):
    """Raised when plugin update fails."""
    pass

class PluginVerificationError(MarketplaceError):
    """Raised when plugin verification fails."""
    pass

class PluginReviewError(MarketplaceError):
    """Raised when plugin review operation fails."""
    pass

class PluginPackageError(MarketplaceError):
    """Raised when plugin package operation fails."""
    pass

# Development tools-related exceptions
class DevToolsError(Exception):
    """Base exception for development tools-related errors."""
    pass

class PluginTestError(DevToolsError):
    """Raised when plugin testing fails."""
    pass

class PluginDocError(DevToolsError):
    """Raised when plugin documentation generation fails."""
    pass

class PluginProjectError(DevToolsError):
    """Raised when plugin project operation fails."""
    pass
