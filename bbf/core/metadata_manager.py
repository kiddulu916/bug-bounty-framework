"""
Plugin metadata manager for the Bug Bounty Framework.

This module provides the PluginMetadataManager class for managing plugin metadata.
"""

import logging
from typing import Dict, Type, Optional

from bbf.core.base import BasePlugin
from bbf.core.metadata import PluginMetadata
from bbf.core.exceptions import PluginError

logger = logging.getLogger(__name__)

class PluginMetadataManager:
    """
    Manages metadata for all plugins.
    
    This class provides a central interface for managing plugin metadata,
    including loading, saving, and migrating metadata.
    """
    
    _instance = None
    _metadata: Dict[str, PluginMetadata] = {}
    
    def __new__(cls):
        """Ensure singleton instance."""
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
            
        Raises:
            PluginError: If metadata cannot be loaded
        """
        if plugin_class.name not in cls._metadata:
            try:
                cls._metadata[plugin_class.name] = PluginMetadata(plugin_class)
            except Exception as e:
                raise PluginError(f"Failed to load metadata for {plugin_class.name}: {e}")
        return cls._metadata[plugin_class.name]
    
    @classmethod
    def update_metadata(cls, plugin_class: Type[BasePlugin], **kwargs) -> None:
        """
        Update metadata for a plugin.
        
        Args:
            plugin_class: The plugin class to update metadata for
            **kwargs: Metadata fields to update
            
        Raises:
            PluginError: If metadata cannot be updated
        """
        try:
            metadata = cls.get_metadata(plugin_class)
            metadata.update(**kwargs)
        except Exception as e:
            raise PluginError(f"Failed to update metadata for {plugin_class.name}: {e}")
    
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
            
        Raises:
            PluginError: If stats cannot be updated
        """
        try:
            metadata = cls.get_metadata(plugin_class)
            metadata.update_execution_stats(execution_time, success, error)
        except Exception as e:
            raise PluginError(f"Failed to update execution stats for {plugin_class.name}: {e}")
    
    @classmethod
    def validate_all(cls) -> bool:
        """
        Validate metadata for all plugins.
        
        Returns:
            bool: True if all metadata is valid, False otherwise
            
        Raises:
            PluginError: If validation fails
        """
        try:
            for metadata in cls._metadata.values():
                if not metadata.validate():
                    return False
            return True
        except Exception as e:
            raise PluginError(f"Failed to validate metadata: {e}")
    
    @classmethod
    def migrate_all(cls, target_version: str) -> None:
        """
        Migrate metadata for all plugins to a new version.
        
        Args:
            target_version: Version to migrate to
            
        Raises:
            PluginError: If migration fails
        """
        try:
            for metadata in cls._metadata.values():
                metadata.migrate(target_version)
        except Exception as e:
            raise PluginError(f"Failed to migrate metadata: {e}")
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear the metadata cache."""
        cls._metadata.clear() 