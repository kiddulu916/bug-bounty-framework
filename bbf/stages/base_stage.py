"""
Base stage implementation for the Bug Bounty Framework.

This module defines the base Stage class that all framework stages should inherit from.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Type, Union, Callable, Coroutine

from ..core.framework import BFFramework
from ..core.plugin import BasePlugin
from ..core.exceptions import StageError

logger = logging.getLogger(__name__)


class Stage:
    """
    Base class for all stages in the Bug Bounty Framework.
    
    Stages are the main building blocks of the framework's execution flow.
    Each stage is responsible for a specific phase of the testing process.
    
    Attributes:
        name: The name of the stage (auto-generated from class name if not set)
        description: A brief description of what the stage does
        enabled: Whether the stage is enabled
        required_previous_stages: List of stage names that must complete successfully
                                 before this stage can run
        required_plugins: List of plugin names that must be available for this stage
    """
    
    # Stage metadata
    name: str = None
    description: str = "Base stage class. Should be overridden by subclasses."
    
    # Stage configuration
    enabled: bool = True
    required_previous_stages: List[str] = []
    required_plugins: List[str] = []
    
    def __init__(self, framework: BFFramework):
        """
        Initialize the stage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        self.framework = framework
        
        # Set default name from class name if not specified
        if self.name is None:
            self.name = self.__class__.__name__.replace('Stage', '').lower()
        
        # Set up logger for this stage
        self.log = logging.getLogger(f"bbf.stage.{self.name}")
        
        # Stage state
        self._results: Dict[str, Any] = {}
        self._errors: List[Exception] = []
        self._warnings: List[str] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._plugins_initialized: bool = False
    
    async def initialize(self) -> None:
        """
        Initialize the stage.
        
        This method is called before the stage runs and can be overridden
        by subclasses to perform any necessary setup.
        """
        if self._start_time is not None:
            self.log.warning("Stage already initialized")
            return
        
        self.log.info(f"Initializing stage: {self.name}")
        self._start_time = asyncio.get_event_loop().time()
        
        # Check required plugins
        await self._check_required_plugins()
        
        self._plugins_initialized = True
    
    async def _check_required_plugins(self) -> None:
        """
        Check if all required plugins are available.
        
        Raises:
            StageError: If any required plugins are missing
        """
        if not self.required_plugins:
            return
            
        missing_plugins = []
        
        for plugin_name in self.required_plugins:
            try:
                self.framework.get_plugin(plugin_name)
            except Exception as e:
                self.log.error(f"Required plugin not found: {plugin_name}")
                missing_plugins.append(plugin_name)
        
        if missing_plugins:
            raise StageError(
                f"Missing required plugins for stage {self.name}: "
                f"{', '.join(missing_plugins)}"
            )
    
    async def run(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the stage.
        
        This is the main entry point for the stage. It initializes the stage,
        runs the stage logic, and handles cleanup.
        
        Args:
            **kwargs: Additional arguments specific to the stage
            
        Returns:
            Dictionary containing the results of the stage
            
        Raises:
            StageError: If the stage fails to execute
        """
        try:
            # Initialize the stage
            await self.initialize()
            
            # Run the stage logic
            self.log.info(f"Starting stage: {self.name}")
            results = await self.execute(**kwargs)
            
            # Store results
            if results is not None:
                self._results.update(results)
            
            self.log.info(f"Completed stage: {self.name}")
            return self._results
            
        except Exception as e:
            self.log.error(f"Stage {self.name} failed: {e}", exc_info=True)
            self.add_error(e)
            raise StageError(f"Stage {self.name} failed: {e}") from e
            
        finally:
            # Clean up resources
            await self.cleanup()
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the main logic of the stage.
        
        This method should be overridden by subclasses to implement
        the specific functionality of the stage.
        
        Args:
            **kwargs: Additional arguments specific to the stage
            
        Returns:
            Dictionary containing the results of the stage
        """
        # Default implementation just runs all plugins for the stage
        return await self.run_plugins(**kwargs)
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the stage.
        
        This method is called after the stage completes, regardless of success or failure.
        It can be overridden by subclasses to perform any necessary cleanup.
        """
        if self._end_time is None:
            self._end_time = asyncio.get_event_loop().time()
            
        if self._start_time is not None:
            duration = self._end_time - self._start_time
            self.log.info(f"Stage {self.name} completed in {duration:.2f} seconds")
    
    async def get_plugins(self) -> List[str]:
        """
        Get the list of plugins to run in this stage.
        
        This method should be overridden by subclasses to return the list
        of plugin names that should be executed in this stage.
        
        Returns:
            List of plugin names to run
        """
        return []
    
    async def run_plugins(self, **kwargs) -> Dict[str, Any]:
        """
        Run all plugins configured for this stage.
        
        Args:
            **kwargs: Additional arguments to pass to the plugins
            
        Returns:
            Dictionary mapping plugin names to their results
        """
        plugin_names = await self.get_plugins()
        if not plugin_names:
            self.log.warning(f"No plugins configured for stage {self.name}")
            return {}
            
        self.log.info(f"Running {len(plugin_names)} plugins in stage {self.name}")
        return await self.framework.run_plugins_parallel(plugin_names, **kwargs)
    
    def add_result(self, key: str, value: Any) -> None:
        """
        Add a result to the stage's results.
        
        Args:
            key: The key under which to store the result
            value: The result value to store
        """
        self._results[key] = value
    
    def add_error(self, error: Exception) -> None:
        """
        Add an error to the stage's error list.
        
        Args:
            error: The exception that occurred
        """
        self._errors.append(error)
        self.log.error(f"Error in stage {self.name}: {str(error)}", exc_info=True)
    
    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the stage's warning list.
        
        Args:
            warning: The warning message to add
        """
        self._warnings.append(warning)
        self.log.warning(f"Warning in stage {self.name}: {warning}")
    
    @property
    def results(self) -> Dict[str, Any]:
        """Get the stage's results."""
        return self._results
    
    @property
    def errors(self) -> List[Exception]:
        """Get the stage's errors."""
        return self._errors
    
    @property
    def warnings(self) -> List[str]:
        """Get the stage's warnings."""
        return self._warnings
    
    @property
    def duration(self) -> Optional[float]:
        """Get the duration of the stage in seconds, or None if not started or completed."""
        if self._start_time is None or self._end_time is None:
            return None
        return self._end_time - self._start_time
    
    def __str__(self) -> str:
        """String representation of the stage."""
        status = "enabled" if self.enabled else "disabled"
        return f"{self.__class__.__name__}(name='{self.name}', status='{status}')"
