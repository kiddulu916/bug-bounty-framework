"""
State management for the Bug Bounty Framework.

This module provides the StateManager class which is responsible for managing
the state of the framework, including plugin states, stage states, and global state.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from datetime import datetime
import hashlib
import os

from .exceptions import StateError

logger = logging.getLogger(__name__)

class StateManager:
    """
    Manages the state of the Bug Bounty Framework.
    
    The StateManager is responsible for:
    - Maintaining global state across the framework
    - Managing plugin states
    - Managing stage states
    - Persisting state to disk
    - Loading state from disk
    - Handling state versioning and migrations
    """
    
    # Current state version (increment when making breaking changes)
    STATE_VERSION = "1.0"
    
    def __init__(self, state_dir: Optional[str] = None, load_existing: bool = True):
        """
        Initialize the StateManager.
        
        Args:
            state_dir: Directory to store state files. If None, a default location is used.
            load_existing: If True, attempt to load existing state from disk.
        """
        # Set up state directory
        self.state_dir = Path(state_dir) if state_dir else Path.cwd() / ".bbf_state"
        self.state_file = self.state_dir / "state.json"
        
        # Initialize state containers
        self._global_state: Dict[str, Any] = {
            "version": self.STATE_VERSION,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        self._plugin_states: Dict[str, Dict[str, Any]] = {}
        self._stage_states: Dict[str, Dict[str, Any]] = {}
        self._dependencies: Dict[str, Set[str]] = {}
        
        # Create state directory if it doesn't exist
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing state if requested
        if load_existing and self.state_file.exists():
            self._load_state()
    
    def _load_state(self) -> None:
        """Load state from disk."""
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                
            # Verify state version
            if state.get("version") != self.STATE_VERSION:
                logger.warning(
                    f"State version mismatch: expected {self.STATE_VERSION}, "
                    f"got {state.get('version')}. Some state may be lost."
                )
            
            # Load state data
            self._global_state = state.get("global", {})
            self._plugin_states = state.get("plugins", {})
            self._stage_states = state.get("stages", {})
            self._dependencies = {
                k: set(v) for k, v in state.get("dependencies", {}).items()
            }
            
            logger.info(f"Loaded state from {self.state_file}")
            
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            # Reset to empty state on error
            self._global_state = {"version": self.STATE_VERSION}
            self._plugin_states = {}
            self._stage_states = {}
            self._dependencies = {}
    
    def save_state(self) -> None:
        """Save current state to disk."""
        try:
            # Update timestamp
            self._global_state["updated_at"] = datetime.utcnow().isoformat()
            
            # Prepare state dictionary
            state = {
                "version": self.STATE_VERSION,
                "global": self._global_state,
                "plugins": self._plugin_states,
                "stages": self._stage_states,
                "dependencies": {k: list(v) for k, v in self._dependencies.items()},
            }
            
            # Write to disk atomically using a temporary file
            temp_file = self.state_file.with_suffix(".tmp")
            with open(temp_file, 'w') as f:
                json.dump(state, f, indent=2, sort_keys=True)
            
            # On Windows, we need to remove the destination file first
            if os.name == 'nt' and self.state_file.exists():
                os.remove(self.state_file)
            
            # Rename temp file to final name
            temp_file.rename(self.state_file)
            
            logger.debug(f"Saved state to {self.state_file}")
            
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            raise StateError(f"Failed to save state: {e}") from e
    
    # Global state methods
    def set_global(self, key: str, value: Any) -> None:
        """
        Set a global state value.
        
        Args:
            key: The key to set
            value: The value to store
        """
        self._global_state[key] = value
    
    def get_global(self, key: str, default: Any = None) -> Any:
        """
        Get a global state value.
        
        Args:
            key: The key to retrieve
            default: Default value to return if key is not found
            
        Returns:
            The stored value or the default if not found
        """
        return self._global_state.get(key, default)
    
    # Plugin state methods
    def set_plugin_state(self, plugin_name: str, state: Dict[str, Any]) -> None:
        """
        Set the state for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            state: Dictionary containing the plugin's state
        """
        self._plugin_states[plugin_name] = state
    
    def get_plugin_state(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get the state for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            The plugin's state dictionary
        """
        return self._plugin_states.get(plugin_name, {})
    
    # Stage state methods
    def set_stage_state(self, stage_name: str, state: Dict[str, Any]) -> None:
        """
        Set the state for a stage.
        
        Args:
            stage_name: Name of the stage
            state: Dictionary containing the stage's state
        """
        self._stage_states[stage_name] = state
    
    def get_stage_state(self, stage_name: str) -> Dict[str, Any]:
        """
        Get the state for a stage.
        
        Args:
            stage_name: Name of the stage
            
        Returns:
            The stage's state dictionary
        """
        return self._stage_states.get(stage_name, {})
    
    # Dependency management
    def add_dependency(self, dependent: str, dependency: str) -> None:
        """
        Add a dependency between two items.
        
        Args:
            dependent: The item that depends on another
            dependency: The item that is depended upon
        """
        if dependent not in self._dependencies:
            self._dependencies[dependent] = set()
        self._dependencies[dependent].add(dependency)
    
    def get_dependencies(self, item: str) -> Set[str]:
        """
        Get all dependencies for an item.
        
        Args:
            item: The item to get dependencies for
            
        Returns:
            Set of dependency names
        """
        return self._dependencies.get(item, set())
    
    # Utility methods
    def checksum(self, data: Any) -> str:
        """
        Generate a checksum for the given data.
        
        Args:
            data: The data to checksum (must be JSON-serializable)
            
        Returns:
            Hex digest of the checksum
        """
        json_data = json.dumps(data, sort_keys=True).encode('utf-8')
        return hashlib.md5(json_data).hexdigest()
    
    def clear(self) -> None:
        """Clear all state."""
        self._global_state = {"version": self.STATE_VERSION}
        self._plugin_states = {}
        self._stage_states = {}
        self._dependencies = {}
        
        # Save the cleared state
        self.save_state()
    
    def __str__(self) -> str:
        """String representation of the state."""
        return (
            f"StateManager(state_file='{self.state_file}', "
            f"plugins={len(self._plugin_states)}, "
            f"stages={len(self._stage_states)})"
        )
