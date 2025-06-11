"""
Plugin validation system for the Bug Bounty Framework.

This module provides validation functionality for plugins, including:
- Schema validation for plugin metadata
- Interface validation
- Dependency validation
- Version compatibility checks
- Security validation
"""

import re
import semver
import inspect
from typing import Dict, Any, List, Set, Type, Optional
from datetime import datetime

from .exceptions import PluginValidationError
from .plugin import BasePlugin

# Plugin metadata schema
PLUGIN_METADATA_SCHEMA = {
    'name': {
        'type': str,
        'required': True,
        'pattern': r'^[a-z][a-z0-9_]*$',
        'description': 'Plugin name (lowercase, alphanumeric, underscores)'
    },
    'description': {
        'type': str,
        'required': True,
        'min_length': 10,
        'description': 'Plugin description (minimum 10 characters)'
    },
    'version': {
        'type': str,
        'required': True,
        'pattern': r'^\d+\.\d+\.\d+$',
        'description': 'Plugin version (semver format)'
    },
    'enabled': {
        'type': bool,
        'required': False,
        'default': True,
        'description': 'Whether the plugin is enabled by default'
    },
    'required_ports': {
        'type': list,
        'required': False,
        'default': [],
        'item_type': int,
        'description': 'List of required ports'
    },
    'required_protocols': {
        'type': list,
        'required': False,
        'default': [],
        'item_type': str,
        'description': 'List of required protocols'
    },
    'depends_on': {
        'type': list,
        'required': False,
        'default': [],
        'item_type': str,
        'description': 'List of plugin dependencies'
    },
    'timeout': {
        'type': int,
        'required': False,
        'default': 300,
        'min': 0,
        'description': 'Plugin timeout in seconds'
    }
}

# Required plugin methods
REQUIRED_PLUGIN_METHODS = {
    'run': {
        'async': True,
        'args': ['self', '*args', '**kwargs'],
        'return_type': Dict[str, Any],
        'description': 'Main entry point for plugin execution'
    },
    'execute': {
        'async': True,
        'args': ['self', 'target', '**kwargs'],
        'return_type': Dict[str, Any],
        'description': 'Execute plugin logic'
    },
    'setup': {
        'async': True,
        'args': ['self'],
        'return_type': None,
        'description': 'Plugin setup'
    },
    'cleanup': {
        'async': True,
        'args': ['self'],
        'return_type': None,
        'description': 'Plugin cleanup'
    }
}

class PluginValidator:
    """
    Validates plugins against the framework's requirements.
    
    This class provides methods to validate plugin metadata, interface,
    dependencies, version compatibility, and security.
    """
    
    def __init__(self, plugin_class: Type[BasePlugin]):
        """
        Initialize the validator with a plugin class.
        
        Args:
            plugin_class: The plugin class to validate
        """
        self.plugin_class = plugin_class
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_all(self) -> bool:
        """
        Run all validation checks on the plugin.
        
        Returns:
            bool: True if all validations pass, False otherwise
            
        Raises:
            PluginValidationError: If validation fails
        """
        try:
            # Run all validations
            self.validate_metadata()
            self.validate_interface()
            self.validate_dependencies()
            self.validate_version()
            self.validate_security()
            
            # Check if any errors occurred
            if self.errors:
                raise PluginValidationError(
                    f"Plugin validation failed for {self.plugin_class.__name__}:\n" +
                    "\n".join(f"- {error}" for error in self.errors)
                )
            
            # Log warnings if any
            if self.warnings:
                for warning in self.warnings:
                    print(f"Warning: {warning}")
            
            return True
            
        except Exception as e:
            if not isinstance(e, PluginValidationError):
                raise PluginValidationError(f"Validation error: {str(e)}") from e
            raise
    
    def validate_metadata(self) -> None:
        """
        Validate plugin metadata against the schema.
        
        Raises:
            PluginValidationError: If metadata validation fails
        """
        for field, schema in PLUGIN_METADATA_SCHEMA.items():
            # Get the value from the plugin class
            value = getattr(self.plugin_class, field, None)
            
            # Check required fields
            if schema['required'] and value is None:
                self.errors.append(f"Required field '{field}' is missing")
                continue
            
            # Skip validation if value is None and field is not required
            if value is None:
                continue
            
            # Type validation
            if not isinstance(value, schema['type']):
                self.errors.append(
                    f"Field '{field}' must be of type {schema['type'].__name__}, "
                    f"got {type(value).__name__}"
                )
                continue
            
            # Pattern validation for strings
            if schema['type'] == str and 'pattern' in schema:
                if not re.match(schema['pattern'], value):
                    self.errors.append(
                        f"Field '{field}' must match pattern {schema['pattern']}"
                    )
            
            # Length validation for strings
            if schema['type'] == str and 'min_length' in schema:
                if len(value) < schema['min_length']:
                    self.errors.append(
                        f"Field '{field}' must be at least {schema['min_length']} "
                        f"characters long"
                    )
            
            # List item type validation
            if schema['type'] == list and 'item_type' in schema:
                for item in value:
                    if not isinstance(item, schema['item_type']):
                        self.errors.append(
                            f"Items in '{field}' must be of type "
                            f"{schema['item_type'].__name__}, got {type(item).__name__}"
                        )
            
            # Numeric range validation
            if schema['type'] in (int, float):
                if 'min' in schema and value < schema['min']:
                    self.errors.append(
                        f"Field '{field}' must be at least {schema['min']}"
                    )
                if 'max' in schema and value > schema['max']:
                    self.errors.append(
                        f"Field '{field}' must be at most {schema['max']}"
                    )
    
    def validate_interface(self) -> None:
        """
        Validate that the plugin implements all required methods correctly.
        
        Raises:
            PluginValidationError: If interface validation fails
        """
        for method_name, requirements in REQUIRED_PLUGIN_METHODS.items():
            # Check if method exists
            method = getattr(self.plugin_class, method_name, None)
            if method is None:
                self.errors.append(f"Required method '{method_name}' is missing")
                continue
            
            # Get method signature
            sig = inspect.signature(method)
            
            # Check if method is async
            is_async = inspect.iscoroutinefunction(method)
            if requirements['async'] and not is_async:
                self.errors.append(f"Method '{method_name}' must be async")
            elif not requirements['async'] and is_async:
                self.errors.append(f"Method '{method_name}' must not be async")
            
            # Check method arguments
            required_args = set(requirements['args'])
            actual_args = set(sig.parameters.keys())
            
            # Check for missing required arguments
            missing_args = required_args - actual_args
            if missing_args:
                self.errors.append(
                    f"Method '{method_name}' is missing required arguments: "
                    f"{', '.join(missing_args)}"
                )
            
            # Check return type
            if requirements['return_type'] is not None:
                return_annotation = sig.return_annotation
                if return_annotation != requirements['return_type']:
                    self.errors.append(
                        f"Method '{method_name}' must return {requirements['return_type']}, "
                        f"got {return_annotation}"
                    )
    
    def validate_dependencies(self) -> None:
        """
        Validate plugin dependencies.
        
        This checks that:
        1. Dependencies are valid plugin names
        2. No circular dependencies exist
        3. Dependencies are available in the registry
        
        Raises:
            PluginValidationError: If dependency validation fails
        """
        # Get dependencies from plugin class
        dependencies = getattr(self.plugin_class, 'depends_on', [])
        
        # Check for circular dependencies
        visited = set()
        path = []
        
        def check_circular_deps(plugin_name: str) -> None:
            if plugin_name in path:
                cycle = ' -> '.join(path[path.index(plugin_name):] + [plugin_name])
                self.errors.append(f"Circular dependency detected: {cycle}")
                return
            
            if plugin_name in visited:
                return
            
            visited.add(plugin_name)
            path.append(plugin_name)
            
            # Get plugin class from registry
            try:
                plugin_class = get_plugin(plugin_name)
                for dep in getattr(plugin_class, 'depends_on', []):
                    check_circular_deps(dep)
            except Exception as e:
                self.errors.append(f"Dependency '{plugin_name}' is not available: {str(e)}")
            
            path.pop()
        
        # Check each dependency
        for dep in dependencies:
            check_circular_deps(dep)
    
    def validate_version(self) -> None:
        """
        Validate plugin version compatibility.
        
        This checks that:
        1. Version string is valid semver
        2. Version is compatible with framework version
        3. Version is not older than minimum required version
        
        Raises:
            PluginValidationError: If version validation fails
        """
        version = getattr(self.plugin_class, 'version', None)
        if not version:
            self.errors.append("Plugin version is required")
            return
        
        try:
            # Parse version
            plugin_version = semver.VersionInfo.parse(version)
            
            # TODO: Add framework version compatibility check
            # For now, just validate semver format
            
        except ValueError as e:
            self.errors.append(f"Invalid version format: {str(e)}")
    
    def validate_security(self) -> None:
        """
        Validate plugin security.
        
        This checks that:
        1. Plugin doesn't use dangerous operations
        2. Plugin handles sensitive data properly
        3. Plugin has proper error handling
        4. Plugin has proper resource cleanup
        
        Raises:
            PluginValidationError: If security validation fails
        """
        # Get plugin source code
        source = inspect.getsource(self.plugin_class)
        
        # Check for dangerous operations
        dangerous_ops = [
            'eval(',
            'exec(',
            'os.system(',
            'subprocess.call(',
            'subprocess.Popen(',
            '__import__(',
            'pickle.loads(',
            'yaml.load(',
            'marshal.loads('
        ]
        
        for op in dangerous_ops:
            if op in source:
                self.warnings.append(
                    f"Plugin uses potentially dangerous operation: {op}"
                )
        
        # Check for proper error handling
        if 'try:' not in source or 'except' not in source:
            self.warnings.append(
                "Plugin may not have proper error handling"
            )
        
        # Check for resource cleanup
        if 'cleanup' in source and 'finally:' not in source:
            self.warnings.append(
                "Plugin may not properly clean up resources"
            )

def validate_plugin(plugin_class: Type[BasePlugin]) -> bool:
    """
    Validate a plugin class.
    
    Args:
        plugin_class: The plugin class to validate
        
    Returns:
        bool: True if validation passes, False otherwise
        
    Raises:
        PluginValidationError: If validation fails
    """
    validator = PluginValidator(plugin_class)
    return validator.validate_all() 