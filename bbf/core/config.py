"""
Configuration management for the Bug Bounty Framework.

This module provides functionality for loading, validating, and managing
configuration settings from various sources (YAML files, environment variables, etc.).
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

import yaml
from pydantic import BaseModel, validator, Field, HttpUrl, DirectoryPath, FilePath

logger = logging.getLogger("bbf.config")

# Default configuration
DEFAULT_CONFIG = {
    'target': None,
    'output_dir': 'reports',
    'log_level': 'INFO',
    'state_file': '.bbf_state.json',
    'max_workers': 10,
    'stages': {
        'recon': {'enabled': True, 'plugins': []},
        'scan': {'enabled': True, 'plugins': []},
        'test': {'enabled': True, 'plugins': []},
        'report': {'enabled': True, 'plugins': []},
    },
    'plugins': {}
}

class PluginConfig(BaseModel):
    """Configuration for a plugin."""
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)

class StageConfig(BaseModel):
    """Configuration for a stage."""
    enabled: bool = True
    plugins: List[str] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = None
    continue_on_error: bool = False

class GlobalConfig(BaseModel):
    """Global configuration for the framework."""
    target: Optional[str]
    output_dir: str = 'reports'
    log_level: str = 'INFO'
    state_file: str = '.bbf_state.json'
    max_workers: int = 10
    stages: Dict[str, StageConfig] = Field(default_factory=dict)
    plugins: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Invalid log level: {v}. Must be one of {valid_levels}')
        return v.upper()
    
    @validator('output_dir')
    def create_output_dir(cls, v):
        """Create output directory if it doesn't exist."""
        os.makedirs(v, exist_ok=True)
        return v

class ConfigManager:
    """
    Manages configuration for the Bug Bounty Framework.
    
    This class handles loading, validating, and accessing configuration
    settings from various sources.
    """
    
    def __init__(self, config: Optional[Union[Dict[str, Any], str, Path]] = None):
        """
        Initialize the ConfigManager.
        
        Args:
            config: Configuration as a dictionary, file path, or None to use defaults
        """
        self._config = self._load_config(config) if config is not None else GlobalConfig(**DEFAULT_CONFIG)
    
    def _load_config(self, config: Union[Dict[str, Any], str, Path]) -> GlobalConfig:
        """
        Load configuration from a dictionary, file path, or directory.
        
        Args:
            config: Configuration source (dict, file path, or directory path)
            
        Returns:
            Loaded and validated configuration
            
        Raises:
            ValueError: If the configuration is invalid
            FileNotFoundError: If a configuration file is specified but not found
        """
        if isinstance(config, (str, Path)):
            config_path = Path(config)
            
            if config_path.is_file():
                # Load from a single file
                with open(config_path, 'r') as f:
                    if config_path.suffix.lower() in ('.yaml', '.yml'):
                        config_data = yaml.safe_load(f) or {}
                    else:
                        raise ValueError(f'Unsupported config file format: {config_path.suffix}')
            else:
                raise FileNotFoundError(f'Config file not found: {config_path}')
        else:
            # Already a dictionary
            config_data = config
        
        # Merge with defaults
        merged_config = self._merge_configs(DEFAULT_CONFIG, config_data)
        
        # Validate and convert to Pydantic model
        return GlobalConfig(**merged_config)
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge two configuration dictionaries.
        
        Args:
            base: Base configuration
            override: Configuration to merge on top of base
            
        Returns:
            Merged configuration
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge dictionaries
                result[key] = self._merge_configs(result[key], value)
            else:
                # Override with new value
                result[key] = value
        
        return result
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin configuration dictionary
        """
        return self._config.plugins.get(plugin_name, {})
    
    def get_stage_config(self, stage_name: str) -> StageConfig:
        """
        Get configuration for a specific stage.
        
        Args:
            stage_name: Name of the stage
            
        Returns:
            Stage configuration
        """
        return self._config.stages.get(stage_name, StageConfig())
    
    @property
    def target(self) -> Optional[str]:
        """Get the target."""
        return self._config.target
    
    @property
    def output_dir(self) -> str:
        """Get the output directory."""
        return self._config.output_dir
    
    @property
    def log_level(self) -> str:
        """Get the log level."""
        return self._config.log_level
    
    @property
    def state_file(self) -> str:
        """Get the state file path."""
        return self._config.state_file
    
    @property
    def max_workers(self) -> int:
        """Get the maximum number of workers."""
        return self._config.max_workers
    
    @property
    def stages(self) -> Dict[str, StageConfig]:
        """Get all stage configurations."""
        return self._config.stages
    
    @property
    def plugins(self) -> Dict[str, Dict[str, Any]]:
        """Get all plugin configurations."""
        return self._config.plugins
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the configuration to a dictionary."""
        return self._config.dict()


def load_config(config: Optional[Union[Dict[str, Any], str, Path]] = None) -> ConfigManager:
    """
    Load configuration from a file or dictionary.
    
    Args:
        config: Configuration source (dict, file path, or directory path)
        
    Returns:
        ConfigManager instance
    """
    return ConfigManager(config)
