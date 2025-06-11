"""
Plugin metadata management system for the Bug Bounty Framework.

This module provides functionality for managing plugin metadata, including:
- Metadata storage and persistence
- Metadata versioning
- Metadata validation
- Metadata migration
"""

import json
import os
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Type
from pathlib import Path

import semver
from .exceptions import PluginError, PluginValidationError
from .plugin import BasePlugin
from .validation import PLUGIN_METADATA_SCHEMA

logger = logging.getLogger(__name__)

class PluginMetadata:
    """
    Represents metadata for a plugin.
    
    This class handles the storage, validation, and versioning of plugin metadata.
    """
    
    def __init__(self, plugin_class: Type[BasePlugin]):
        """
        Initialize metadata for a plugin.
        
        Args:
            plugin_class: The plugin class to manage metadata for
        """
        self.plugin_class = plugin_class
        self.name = plugin_class.name
        self.version = plugin_class.version
        self.metadata: Dict[str, Any] = {}
        self._load_metadata()
    
    def _load_metadata(self) -> None:
        """Load metadata from storage or create new metadata."""
        try:
            # Try to load existing metadata
            metadata_path = self._get_metadata_path()
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
            else:
                # Create new metadata
                self.metadata = self._create_metadata()
                self._save_metadata()
        except Exception as e:
            logger.error(f"Failed to load metadata for {self.name}: {e}")
            # Create new metadata on error
            self.metadata = self._create_metadata()
    
    def _create_metadata(self) -> Dict[str, Any]:
        """
        Create new metadata for the plugin.
        
        Returns:
            Dictionary containing plugin metadata
        """
        return {
            'name': self.name,
            'version': self.version,
            'description': self.plugin_class.description,
            'enabled': self.plugin_class.enabled,
            'required_ports': self.plugin_class.required_ports,
            'required_protocols': self.plugin_class.required_protocols,
            'depends_on': self.plugin_class.depends_on,
            'timeout': self.plugin_class.timeout,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'last_execution': None,
            'execution_count': 0,
            'success_count': 0,
            'error_count': 0,
            'average_execution_time': 0.0,
            'last_error': None,
            'dependencies_met': False,
            'status': 'created'
        }
    
    def _get_metadata_path(self) -> Path:
        """
        Get the path to the metadata file.
        
        Returns:
            Path to the metadata file
        """
        # Create metadata directory if it doesn't exist
        metadata_dir = Path('data/plugins/metadata')
        metadata_dir.mkdir(parents=True, exist_ok=True)
        
        return metadata_dir / f"{self.name}.json"
    
    def _save_metadata(self) -> None:
        """Save metadata to storage."""
        try:
            metadata_path = self._get_metadata_path()
            with open(metadata_path, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata for {self.name}: {e}")
            raise PluginError(f"Failed to save metadata: {e}")
    
    def update(self, **kwargs) -> None:
        """
        Update plugin metadata.
        
        Args:
            **kwargs: Metadata fields to update
        """
        # Update metadata fields
        for key, value in kwargs.items():
            if key in self.metadata:
                self.metadata[key] = value
        
        # Update timestamp
        self.metadata['updated_at'] = datetime.utcnow().isoformat()
        
        # Save changes
        self._save_metadata()
    
    def update_execution_stats(self, execution_time: float, success: bool, error: Optional[str] = None) -> None:
        """
        Update execution statistics.
        
        Args:
            execution_time: Time taken to execute the plugin
            success: Whether execution was successful
            error: Error message if execution failed
        """
        # Update execution count
        self.metadata['execution_count'] += 1
        
        # Update success/error count
        if success:
            self.metadata['success_count'] += 1
        else:
            self.metadata['error_count'] += 1
            self.metadata['last_error'] = error
        
        # Update average execution time
        current_avg = self.metadata['average_execution_time']
        current_count = self.metadata['execution_count']
        self.metadata['average_execution_time'] = (
            (current_avg * (current_count - 1) + execution_time) / current_count
        )
        
        # Update last execution time
        self.metadata['last_execution'] = datetime.utcnow().isoformat()
        
        # Save changes
        self._save_metadata()
    
    def validate(self) -> bool:
        """
        Validate plugin metadata.
        
        Returns:
            bool: True if metadata is valid, False otherwise
            
        Raises:
            PluginValidationError: If validation fails
        """
        try:
            # Validate against schema
            for field, schema in PLUGIN_METADATA_SCHEMA.items():
                if field not in self.metadata:
                    if schema['required']:
                        raise PluginValidationError(f"Required field '{field}' is missing")
                    continue
                
                value = self.metadata[field]
                
                # Type validation
                if not isinstance(value, schema['type']):
                    raise PluginValidationError(
                        f"Field '{field}' must be of type {schema['type'].__name__}, "
                        f"got {type(value).__name__}"
                    )
                
                # Pattern validation for strings
                if schema['type'] == str and 'pattern' in schema:
                    if not re.match(schema['pattern'], value):
                        raise PluginValidationError(
                            f"Field '{field}' must match pattern {schema['pattern']}"
                        )
                
                # Length validation for strings
                if schema['type'] == str and 'min_length' in schema:
                    if len(value) < schema['min_length']:
                        raise PluginValidationError(
                            f"Field '{field}' must be at least {schema['min_length']} "
                            f"characters long"
                        )
                
                # List item type validation
                if schema['type'] == list and 'item_type' in schema:
                    for item in value:
                        if not isinstance(item, schema['item_type']):
                            raise PluginValidationError(
                                f"Items in '{field}' must be of type "
                                f"{schema['item_type'].__name__}, got {type(item).__name__}"
                            )
            
            return True
            
        except Exception as e:
            if isinstance(e, PluginValidationError):
                raise
            raise PluginValidationError(f"Metadata validation failed: {str(e)}")
    
    def migrate(self, target_version: str) -> None:
        """
        Migrate metadata to a new version.
        
        Args:
            target_version: Target version to migrate to
            
        Raises:
            PluginError: If migration fails
        """
        try:
            current_version = semver.VersionInfo.parse(self.version)
            target_version = semver.VersionInfo.parse(target_version)
            
            # No migration needed if versions are the same
            if current_version == target_version:
                return
            
            # Perform migration steps based on version changes
            if target_version.major > current_version.major:
                # Major version upgrade
                self._migrate_major_version(current_version, target_version)
            elif target_version.minor > current_version.minor:
                # Minor version upgrade
                self._migrate_minor_version(current_version, target_version)
            elif target_version.patch > current_version.patch:
                # Patch version upgrade
                self._migrate_patch_version(current_version, target_version)
            
            # Update version
            self.metadata['version'] = str(target_version)
            self._save_metadata()
            
        except Exception as e:
            raise PluginError(f"Failed to migrate metadata: {str(e)}")
    
    def _migrate_major_version(self, current: semver.VersionInfo, target: semver.VersionInfo) -> None:
        """
        Migrate metadata for a major version upgrade.
        
        Args:
            current: Current version
            target: Target version
        """
        # Backup current metadata
        backup_path = self._get_metadata_path().with_suffix('.json.bak')
        shutil.copy2(self._get_metadata_path(), backup_path)
        
        try:
            # Major version migrations
            if current.major == 1 and target.major == 2:
                # Example: Migrate from v1.x to v2.x
                self._migrate_v1_to_v2()
            
            # Add more major version migrations as needed
            
        except Exception as e:
            # Restore backup on failure
            shutil.copy2(backup_path, self._get_metadata_path())
            raise PluginError(f"Major version migration failed: {str(e)}")
        finally:
            # Clean up backup
            if backup_path.exists():
                backup_path.unlink()
    
    def _migrate_minor_version(self, current: semver.VersionInfo, target: semver.VersionInfo) -> None:
        """
        Migrate metadata for a minor version upgrade.
        
        Args:
            current: Current version
            target: Target version
        """
        # Minor version migrations
        if current.minor == 0 and target.minor == 1:
            # Example: Migrate from v1.0.x to v1.1.x
            self._migrate_v1_0_to_v1_1()
        
        # Add more minor version migrations as needed
    
    def _migrate_patch_version(self, current: semver.VersionInfo, target: semver.VersionInfo) -> None:
        """
        Migrate metadata for a patch version upgrade.
        
        Args:
            current: Current version
            target: Target version
        """
        # Patch version migrations
        if current.patch == 0 and target.patch == 1:
            # Example: Migrate from v1.1.0 to v1.1.1
            self._migrate_v1_1_0_to_v1_1_1()
        
        # Add more patch version migrations as needed
    
    def _migrate_v1_to_v2(self) -> None:
        """Migrate metadata from v1.x to v2.x."""
        # Example migration steps
        if 'old_field' in self.metadata:
            # Migrate old field to new format
            old_value = self.metadata.pop('old_field')
            self.metadata['new_field'] = self._convert_old_to_new(old_value)
    
    def _migrate_v1_0_to_v1_1(self) -> None:
        """Migrate metadata from v1.0.x to v1.1.x."""
        # Example migration steps
        if 'deprecated_field' in self.metadata:
            # Update deprecated field
            self.metadata['updated_field'] = self.metadata.pop('deprecated_field')
    
    def _migrate_v1_1_0_to_v1_1_1(self) -> None:
        """Migrate metadata from v1.1.0 to v1.1.1."""
        # Example migration steps
        if 'field_with_bug' in self.metadata:
            # Fix bug in field
            self.metadata['field_with_bug'] = self._fix_field_bug(
                self.metadata['field_with_bug']
            )

class PluginMetadataManager:
    """
    Manages metadata for all plugins.
    
    This class provides a central interface for managing plugin metadata,
    including loading, saving, and migrating metadata.
    """
    
    _instance = None
    _metadata: Dict[str, PluginMetadata] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_metadata(cls, plugin_class: Type[BasePlugin]) -> PluginMetadata:
        """
        Get metadata for a plugin.
        
        Args:
            plugin_class: The plugin class to get metadata for
            
        Returns:
            PluginMetadata object for the plugin
        """
        name = plugin_class.name
        if name not in cls._metadata:
            cls._metadata[name] = PluginMetadata(plugin_class)
        return cls._metadata[name]
    
    @classmethod
    def update_metadata(cls, plugin_class: Type[BasePlugin], **kwargs) -> None:
        """
        Update metadata for a plugin.
        
        Args:
            plugin_class: The plugin class to update metadata for
            **kwargs: Metadata fields to update
        """
        metadata = cls.get_metadata(plugin_class)
        metadata.update(**kwargs)
    
    @classmethod
    def update_execution_stats(
        cls,
        plugin_class: Type[BasePlugin],
        execution_time: float,
        success: bool,
        error: Optional[str] = None
    ) -> None:
        """
        Update execution statistics for a plugin.
        
        Args:
            plugin_class: The plugin class to update stats for
            execution_time: Time taken to execute the plugin
            success: Whether execution was successful
            error: Error message if execution failed
        """
        metadata = cls.get_metadata(plugin_class)
        metadata.update_execution_stats(execution_time, success, error)
    
    @classmethod
    def validate_all(cls) -> bool:
        """
        Validate metadata for all plugins.
        
        Returns:
            bool: True if all metadata is valid, False otherwise
            
        Raises:
            PluginValidationError: If validation fails
        """
        for metadata in cls._metadata.values():
            if not metadata.validate():
                return False
        return True
    
    @classmethod
    def migrate_all(cls, target_version: str) -> None:
        """
        Migrate metadata for all plugins to a new version.
        
        Args:
            target_version: Target version to migrate to
            
        Raises:
            PluginError: If migration fails
        """
        for metadata in cls._metadata.values():
            metadata.migrate(target_version)
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear the metadata cache."""
        cls._metadata.clear() 