"""
Base stage implementation for the Bug Bounty Framework.

This module provides the base Stage class that all stages must inherit from.
Stages represent distinct phases of security testing (e.g., reconnaissance,
vulnerability scanning, exploitation testing).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import asyncio
import logging
from datetime import datetime

from bbf.core.exceptions import StageError, StageExecutionError, StageValidationError
from bbf.core.plugin import PluginRegistry

logger = logging.getLogger(__name__)

class Stage(ABC):
    """Base class for all stages in the Bug Bounty Framework.
    
    A stage represents a distinct phase of security testing (e.g., reconnaissance,
    vulnerability scanning, exploitation testing). Each stage can execute multiple
    plugins in parallel and aggregate their results.
    
    Attributes:
        name (str): The name of the stage.
        description (str): A description of what the stage does.
        enabled (bool): Whether the stage is enabled.
        required_previous_stages (List[str]): List of stages that must be completed before this stage.
        required_plugins (List[str]): List of plugins that must be available for this stage.
        timeout (int): Maximum time in seconds for the stage to complete.
    """
    
    name: str
    description: str
    enabled: bool = True
    required_previous_stages: List[str] = []
    required_plugins: List[str] = []
    timeout: int = 3600  # 1 hour default timeout
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the stage.
        
        Args:
            config: Optional configuration dictionary for the stage.
        """
        self.config = config or {}
        self._validate_config()
        self._state: Dict[str, Any] = {}
        self._results: Dict[str, Any] = {}
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._plugins: List[str] = []
        self._plugin_registry = PluginRegistry()
        
    def _validate_config(self) -> None:
        """Validate the stage configuration.
        
        Raises:
            StageValidationError: If the configuration is invalid.
        """
        if not self.name:
            raise StageValidationError("Stage name is required")
        if not self.description:
            raise StageValidationError("Stage description is required")
            
        # Validate timeout
        if 'timeout' in self.config:
            try:
                timeout = int(self.config['timeout'])
                if timeout <= 0:
                    raise StageValidationError("Timeout must be positive")
                self.timeout = timeout
            except (TypeError, ValueError):
                raise StageValidationError("Timeout must be an integer")
                
        # Validate enabled state
        if 'enabled' in self.config:
            if not isinstance(self.config['enabled'], bool):
                raise StageValidationError("Enabled must be a boolean")
            self.enabled = self.config['enabled']
            
        # Validate required stages
        if 'required_previous_stages' in self.config:
            if not isinstance(self.config['required_previous_stages'], list):
                raise StageValidationError("Required previous stages must be a list")
            self.required_previous_stages = self.config['required_previous_stages']
            
        # Validate required plugins
        if 'required_plugins' in self.config:
            if not isinstance(self.config['required_plugins'], list):
                raise StageValidationError("Required plugins must be a list")
            self.required_plugins = self.config['required_plugins']
            
    async def initialize(self) -> None:
        """Initialize the stage.
        
        This method is called before the stage is executed. It should:
        1. Validate that all required plugins are available
        2. Initialize any resources needed by the stage
        3. Set up the stage state
        
        Raises:
            StageError: If initialization fails.
        """
        try:
            # Check required plugins
            for plugin_name in self.required_plugins:
                if not self._plugin_registry.get_plugin(plugin_name):
                    raise StageError(f"Required plugin {plugin_name} not found")
                    
            # Initialize stage state
            self._state = {
                'status': 'initialized',
                'start_time': None,
                'end_time': None,
                'error': None,
                'results': {}
            }
            
            # Call stage-specific initialization
            await self._initialize()
            
        except Exception as e:
            logger.error(f"Failed to initialize stage {self.name}: {str(e)}")
            raise StageError(f"Stage initialization failed: {str(e)}")
            
    @abstractmethod
    async def _initialize(self) -> None:
        """Stage-specific initialization.
        
        This method should be implemented by subclasses to perform any
        stage-specific initialization.
        """
        pass
        
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the stage.
        
        This method:
        1. Initializes the stage
        2. Executes all enabled plugins in parallel
        3. Aggregates the results
        4. Cleans up resources
        
        Args:
            target: The target to test (e.g., domain name, IP address).
            **kwargs: Additional arguments for the stage.
            
        Returns:
            Dict containing the stage results.
            
        Raises:
            StageExecutionError: If execution fails.
        """
        if not self.enabled:
            logger.info(f"Stage {self.name} is disabled, skipping execution")
            return {}
            
        try:
            # Initialize stage
            await self.initialize()
            
            # Record start time
            self._start_time = datetime.now()
            self._state['start_time'] = self._start_time
            
            # Execute stage
            logger.info(f"Executing stage {self.name} on target {target}")
            self._state['status'] = 'running'
            
            # Execute plugins in parallel
            tasks = []
            for plugin_name in self._plugins:
                plugin = self._plugin_registry.get_plugin(plugin_name)
                if plugin and plugin.enabled:
                    tasks.append(self._execute_plugin(plugin, target, **kwargs))
                    
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for plugin_name, result in zip(self._plugins, results):
                    if isinstance(result, Exception):
                        logger.error(f"Plugin {plugin_name} failed: {str(result)}")
                        self._state['error'] = str(result)
                    else:
                        self._results[plugin_name] = result
                        
            # Call stage-specific execution
            await self._execute(target, **kwargs)
            
            # Record end time
            self._end_time = datetime.now()
            self._state['end_time'] = self._end_time
            self._state['status'] = 'completed'
            
            # Clean up
            await self.cleanup()
            
            return {
                'stage': self.name,
                'status': self._state['status'],
                'start_time': self._start_time,
                'end_time': self._end_time,
                'error': self._state['error'],
                'results': self._results
            }
            
        except Exception as e:
            logger.error(f"Stage {self.name} execution failed: {str(e)}")
            self._state['status'] = 'failed'
            self._state['error'] = str(e)
            self._end_time = datetime.now()
            self._state['end_time'] = self._end_time
            await self.cleanup()
            raise StageExecutionError(f"Stage execution failed: {str(e)}")
            
    @abstractmethod
    async def _execute(self, target: str, **kwargs) -> None:
        """Stage-specific execution.
        
        This method should be implemented by subclasses to perform any
        stage-specific execution logic.
        
        Args:
            target: The target to test.
            **kwargs: Additional arguments for the stage.
        """
        pass
        
    async def _execute_plugin(self, plugin: Any, target: str, **kwargs) -> Dict[str, Any]:
        """Execute a plugin with timeout.
        
        Args:
            plugin: The plugin to execute.
            target: The target to test.
            **kwargs: Additional arguments for the plugin.
            
        Returns:
            Dict containing the plugin results.
            
        Raises:
            StageExecutionError: If plugin execution fails or times out.
        """
        try:
            return await asyncio.wait_for(
                plugin.execute(target, **kwargs),
                timeout=plugin.timeout
            )
        except asyncio.TimeoutError:
            raise StageExecutionError(f"Plugin {plugin.name} timed out after {plugin.timeout} seconds")
        except Exception as e:
            raise StageExecutionError(f"Plugin {plugin.name} failed: {str(e)}")
            
    async def cleanup(self) -> None:
        """Clean up stage resources.
        
        This method is called after the stage is executed, regardless of whether
        execution succeeded or failed. It should clean up any resources used by
        the stage.
        
        Raises:
            StageError: If cleanup fails.
        """
        try:
            # Call stage-specific cleanup
            await self._cleanup()
            
            # Clean up plugin resources
            for plugin_name in self._plugins:
                plugin = self._plugin_registry.get_plugin(plugin_name)
                if plugin:
                    try:
                        await plugin.cleanup()
                    except Exception as e:
                        logger.error(f"Plugin {plugin_name} cleanup failed: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Stage {self.name} cleanup failed: {str(e)}")
            raise StageError(f"Stage cleanup failed: {str(e)}")
            
    @abstractmethod
    async def _cleanup(self) -> None:
        """Stage-specific cleanup.
        
        This method should be implemented by subclasses to perform any
        stage-specific cleanup.
        """
        pass
        
    def get_state(self) -> Dict[str, Any]:
        """Get the current stage state.
        
        Returns:
            Dict containing the current stage state.
        """
        return self._state.copy()
        
    def get_results(self) -> Dict[str, Any]:
        """Get the stage results.
        
        Returns:
            Dict containing the stage results.
        """
        return self._results.copy() 